//
//  SealedSenderModelTests.swift
//  post-quantum-solace
//
//  TDD for additive sealed-sender models. Strict SemVer: 4.2.0 fixtures
//  must still decode; no new public enum cases.
//

import BinaryCodable
import Crypto
import Foundation
import SessionModels
import Testing

@Suite("Sealed sender models (PQS 4.3 additive)")
struct SealedSenderModelTests {

    private static let deviceId = UUID(uuidString: "00000000-0000-4000-8000-0000000000aa")!

    @Test("4.2.0 device key bundle without capabilities still decodes as incapable")
    func legacyDeviceKeyBundleDecodesIncapable() throws {
        // BinaryCodable embeds the type identity, so a 4.2 payload is a
        // DeviceKeyBundle encoded without key "e" — not a differently named struct.
        let bundle = UserConfiguration.DeviceKeyBundle(
            deviceId: Self.deviceId,
            longTermPublicKey: Data(repeating: 0x11, count: 32),
            finalMLKEMPublicKey: try MLKEMPublicKey(id: Self.deviceId, Data(repeating: 0x22, count: 1568)),
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        #expect(!bundle.supportsSealedSender)
        let data = try BinaryEncoder().encode(bundle)
        let decoded = try BinaryDecoder().decode(UserConfiguration.DeviceKeyBundle.self, from: data)
        #expect(decoded.deviceId == Self.deviceId)
        #expect(decoded.capabilities.isEmpty)
        #expect(!decoded.supportsSealedSender)
    }

    @Test("bundle with sealed-sender bit round-trips and JSON extra keys are ignored")
    func sealedCapabilityRoundTripsAndLegacyDecoderIgnoresNewKey() throws {
        let bundle = UserConfiguration.DeviceKeyBundle(
            deviceId: Self.deviceId,
            longTermPublicKey: Data(repeating: 0x11, count: 32),
            finalMLKEMPublicKey: try MLKEMPublicKey(id: Self.deviceId, Data(repeating: 0x22, count: 1568)),
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            capabilities: .sealedSender
        )
        #expect(bundle.supportsSealedSender)
        let data = try BinaryEncoder().encode(bundle)
        let modern = try BinaryDecoder().decode(UserConfiguration.DeviceKeyBundle.self, from: data)
        #expect(modern.supportsSealedSender)

        let json = try JSONEncoder().encode(bundle)
        let legacy = try JSONDecoder().decode(LegacyDeviceKeyBundle.self, from: json)
        #expect(legacy.deviceId == Self.deviceId)
    }

    @Test("default DeviceKeyBundle init still compiles without capabilities")
    func defaultInitOmitsCapabilities() throws {
        let bundle = UserConfiguration.DeviceKeyBundle(
            deviceId: Self.deviceId,
            longTermPublicKey: Data(repeating: 0x33, count: 32),
            finalMLKEMPublicKey: try MLKEMPublicKey(id: Self.deviceId, Data(repeating: 0x44, count: 1568))
        )
        #expect(!bundle.supportsSealedSender)
    }

    @Test("legacy friendship metadata without a delivery token still decodes")
    func legacyFriendshipMetadataDecodesWithoutToken() throws {
        let friendship = FriendshipMetadata(
            myState: .accepted,
            theirState: .accepted,
            ourState: .accepted
        )
        #expect(friendship.sealedDeliveryToken == nil)
        let data = try BinaryEncoder().encode(friendship)
        let decoded = try BinaryDecoder().decode(FriendshipMetadata.self, from: data)
        #expect(decoded.ourState == .accepted)
        #expect(decoded.sealedDeliveryToken == nil)
    }

    @Test("friendship delivery token round-trips without changing settled state")
    func friendshipDeliveryTokenRoundTrips() throws {
        var friendship = FriendshipMetadata(myState: .accepted, theirState: .accepted, ourState: .accepted)
        friendship.sealedDeliveryToken = Data(repeating: 0xAB, count: 32)
        let decoded = try BinaryDecoder().decode(
            FriendshipMetadata.self,
            from: try BinaryEncoder().encode(friendship)
        )
        #expect(decoded.sealedDeliveryToken == Data(repeating: 0xAB, count: 32))
        #expect(decoded.ourState == .accepted)
    }

    @Test("sender certificate verifies inside skew and rejects expiry, mismatch, and bad signatures")
    func senderCertificateLifecycle() throws {
        let privateKey = try MLDSA65.PrivateKey()
        let publicKey = privateKey.publicKey.rawRepresentation
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let cert = try SenderCertificate.issue(
            secretName: "alice",
            deviceId: Self.deviceId,
            issuedAt: now,
            lifetime: 24 * 3600,
            authorityKeyId: "ca-2026-08",
            signingKey: privateKey
        )
        #expect(cert.authorityKeyId == "ca-2026-08")
        try cert.verify(againstPublicKey: publicKey, now: now)
        try cert.verify(
            againstPublicKey: publicKey,
            expectedSecretName: "alice",
            expectedDeviceId: Self.deviceId,
            now: now
        )
        try cert.verify(
            againstPublicKey: publicKey,
            expectedSecretName: "alice",
            expectedDeviceId: Self.deviceId,
            now: now.addingTimeInterval(4 * 60)
        )

        #expect(throws: SenderCertificateError.self) {
            try cert.verify(
                againstPublicKey: publicKey,
                expectedSecretName: "alice",
                expectedDeviceId: Self.deviceId,
                now: now.addingTimeInterval(24 * 3600 + 6 * 60)
            )
        }
        #expect(throws: SenderCertificateError.self) {
            try cert.verify(
                againstPublicKey: publicKey,
                expectedSecretName: "bob",
                expectedDeviceId: Self.deviceId,
                now: now
            )
        }

        let otherKey = try MLDSA65.PrivateKey()
        #expect(throws: SenderCertificateError.self) {
            try cert.verify(
                againstPublicKey: otherKey.publicKey.rawRepresentation,
                expectedSecretName: "alice",
                expectedDeviceId: Self.deviceId,
                now: now
            )
        }
    }

    @Test("every local device-key-bundle publish path advertises sealed sender")
    func allBundlePublishPathsAdvertiseSealedSender() throws {
        // Existing accounts migrate to sealed sender through whichever bundle
        // publish runs next (routine rotation, unlock rebuild, schema backfill),
        // and no republish may strip the bit once advertised.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let publishPaths = [
            "Sources/PQSSession/Session/PQSSession+AccountCreation.swift",
            "Sources/PQSSession/Session/PQSSession+KeyRotation.swift",
            "Sources/PQSSession/Session/PQSSession+Unlock.swift",
            "Sources/PQSSession/Session/PQSSession+SchemaMigration.swift",
        ]
        for path in publishPaths {
            let source = try String(
                contentsOf: root.appendingPathComponent(path),
                encoding: .utf8
            )
            let bundleConstructions = source.components(separatedBy: "bundle: .init(").count - 1
            let advertised = source.components(separatedBy: "capabilities: .sealedSender").count - 1
            if bundleConstructions > 0 {
                #expect(
                    advertised >= bundleConstructions,
                    "\(path) publishes a DeviceKeyBundle without .sealedSender"
                )
            } else {
                #expect(
                    source.contains("capabilities: .sealedSender"),
                    "\(path) publishes a DeviceKeyBundle without .sealedSender"
                )
            }
        }
    }

    @Test("sealed-sender plaintext wraps a certificate inside AEAD payload bytes")
    func sealedSenderPlaintextRoundTripsAndVerifies() throws {
        let privateKey = try MLDSA65.PrivateKey()
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let cert = try SenderCertificate.issue(
            secretName: "alice",
            deviceId: Self.deviceId,
            issuedAt: now,
            lifetime: 24 * 3600,
            signingKey: privateKey
        )
        let inner = Data("hello sealed".utf8)
        let plaintext = SealedSenderPlaintext(certificate: cert, innerMessage: inner)
        let decoded = try BinaryDecoder().decode(
            SealedSenderPlaintext.self,
            from: try BinaryEncoder().encode(plaintext)
        )
        #expect(decoded.innerMessage == inner)
        try decoded.certificate.verify(
            againstPublicKey: privateKey.publicKey.rawRepresentation,
            expectedSecretName: "alice",
            expectedDeviceId: Self.deviceId,
            now: now
        )
    }
}

private struct LegacyDeviceKeyBundle: Codable {
    let deviceId: UUID
    let longTermPublicKey: Data
    let finalMLKEMPublicKey: MLKEMPublicKey
    let updatedAt: Date?

    enum CodingKeys: String, CodingKey {
        case deviceId = "a"
        case longTermPublicKey = "b"
        case finalMLKEMPublicKey = "c"
        case updatedAt = "d"
    }
}

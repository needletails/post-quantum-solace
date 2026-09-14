//
//  SealedOuterBoxTests.swift
//  post-quantum-solace
//

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
import SessionModels
import Testing

@Suite("PQS sealed outer box")
struct SealedOuterBoxTests {
    @Test("ciphertext uses compact Codable keys")
    func compactCiphertextCoding() throws {
        let value = SealedOuterCiphertext(
            version: 1,
            kemCiphertext: Data([1, 2]),
            aeadCiphertext: Data([3, 4])
        )
        let encoded = try JSONEncoder().encode(value)
        let object = try #require(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )

        #expect(Set(object.keys) == Set(["a", "b", "c"]))
        #expect(try JSONDecoder().decode(SealedOuterCiphertext.self, from: encoded) == value)
    }

    @Test("fresh ML-KEM seal round-trips certificate and signed ratchet message")
    func roundTrip() throws {
        let fixture = try Fixture()
        let sealed = try fixture.seal()
        let plaintext = try fixture.open(sealed)
        let decodedMessage = try BinaryDecoder().decode(
            SignedRatchetMessage.self,
            from: plaintext.innerMessage
        )

        #expect(plaintext.certificate == fixture.certificate)
        #expect(
            try BinaryEncoder().encode(decodedMessage)
                == BinaryEncoder().encode(fixture.signedMessage)
        )
        #expect(sealed.version == SealedOuterBox.currentVersion)
        #expect(sealed.kemCiphertext.count == 1_568)
        #expect(sealed.aeadCiphertext.count >= 28)
        #expect(sealed.recipientKeyId == fixture.recipientPublicKey.id)
    }

    @Test("nil recipientKeyId is omitted from JSON and BinaryCodable keyed payloads")
    func recipientKeyIdNilIsSkippedOnTheWire() throws {
        struct Legacy: Codable, Equatable {
            enum CodingKeys: String, CodingKey {
                case version = "a"
                case kemCiphertext = "b"
                case aeadCiphertext = "c"
            }
            var version: UInt8
            var kemCiphertext: Data
            var aeadCiphertext: Data
        }
        let current = SealedOuterCiphertext(
            version: 1,
            kemCiphertext: Data([1, 2, 3]),
            aeadCiphertext: Data([4, 5, 6]),
            recipientKeyId: nil
        )
        let legacy = Legacy(
            version: 1,
            kemCiphertext: Data([1, 2, 3]),
            aeadCiphertext: Data([4, 5, 6])
        )
        let object = try #require(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(current)) as? [String: Any]
        )
        #expect(Set(object.keys) == Set(["a", "b", "c"]))
        // Compare decoded values, not raw JSONEncoder bytes. Linux Foundation
        // emits keyed fields in dictionary order, so byte-identity fails even
        // when the wire keys and values match.
        #expect(try JSONDecoder().decode(Legacy.self, from: JSONEncoder().encode(current)) == legacy)
        let decoded = try BinaryDecoder().decode(
            SealedOuterCiphertext.self,
            from: BinaryEncoder().encode(current)
        )
        #expect(decoded.recipientKeyId == nil)
        #expect(try BinaryEncoder().encode(decoded) == BinaryEncoder().encode(current))
    }

    @Test("legacy bytes without d still open after a hinted seal/open pair")
    func legacyCiphertextWithoutHintStillOpens() throws {
        let fixture = try Fixture()
        let sealed = try fixture.seal()
        let legacy = SealedOuterCiphertext(
            version: sealed.version,
            kemCiphertext: sealed.kemCiphertext,
            aeadCiphertext: sealed.aeadCiphertext,
            recipientKeyId: nil
        )
        _ = try fixture.open(legacy)
        #expect(SealedOpenFailureReason.classify(
            hintedKeyId: UUID(),
            heldKeyIds: [fixture.recipientPrivateKey.id],
            boxError: nil
        ) == .recipientKeyUnknown)
        #expect(SealedOpenFailureReason.classify(
            hintedKeyId: fixture.recipientPrivateKey.id,
            heldKeyIds: [fixture.recipientPrivateKey.id],
            boxError: .authenticationFailed
        ) == .authenticationFailed)
        #expect(SealedOpenFailureReason.classify(
            hintedKeyId: fixture.recipientPrivateKey.id,
            heldKeyIds: [fixture.recipientPrivateKey.id],
            boxError: .unsupportedVersion
        ) == .malformed)
    }

    @Test("seal to key A then open with A's retained prior key")
    func openSucceedsWithPreviousGenerationKey() throws {
        let fixture = try Fixture()
        let sealed = try fixture.seal()
        var keys = DeviceKeys(
            deviceId: UUID(),
            signingPrivateKey: Data(repeating: 1, count: 32),
            longTermPrivateKey: Data(repeating: 2, count: 32),
            oneTimePrivateKeys: [],
            mlKEMOneTimePrivateKeys: [],
            finalMLKEMPrivateKey: fixture.recipientPrivateKey
        )
        let next = try MLKEMPrivateKey(id: UUID(), MLKEM1024.PrivateKey().encode())
        keys.replaceFinalMLKEMPrivateKey(next, retainingPrevious: true)
        #expect(keys.finalMLKEMPrivateKey(matching: fixture.recipientPrivateKey.id) == fixture.recipientPrivateKey)
        _ = try fixture.open(sealed, recipientFinalMLKEMPrivateKey: keys.previousFinalMLKEMPrivateKey)
        _ = try SealedInboundOpen.open(
            sealed,
            deviceKeys: keys,
            recipientSecretName: fixture.context.recipientSecretName,
            recipientDeviceId: fixture.context.recipientDeviceId,
            envelopeId: fixture.context.envelopeId,
            packetId: fixture.context.packetId
        )
    }

    @Test("hinted inbound open resolves by id and unknown ids stay terminal")
    func hintedInboundOpenResolvesByKeyId() throws {
        let fixture = try Fixture()
        let sealed = try fixture.seal()
        var keys = DeviceKeys(
            deviceId: fixture.context.recipientDeviceId,
            signingPrivateKey: Data(repeating: 1, count: 32),
            longTermPrivateKey: Data(repeating: 2, count: 32),
            oneTimePrivateKeys: [],
            mlKEMOneTimePrivateKeys: [],
            finalMLKEMPrivateKey: fixture.recipientPrivateKey
        )
        #expect(sealed.recipientKeyId == fixture.recipientPublicKey.id)
        _ = try SealedInboundOpen.open(
            sealed,
            deviceKeys: keys,
            recipientSecretName: fixture.context.recipientSecretName,
            recipientDeviceId: fixture.context.recipientDeviceId,
            envelopeId: fixture.context.envelopeId,
            packetId: fixture.context.packetId
        )

        let unknownId = UUID()
        let hintedUnknown = SealedOuterCiphertext(
            version: sealed.version,
            kemCiphertext: sealed.kemCiphertext,
            aeadCiphertext: sealed.aeadCiphertext,
            recipientKeyId: unknownId
        )
        do {
            _ = try SealedInboundOpen.open(
                hintedUnknown,
                deviceKeys: keys,
                recipientSecretName: fixture.context.recipientSecretName,
                recipientDeviceId: fixture.context.recipientDeviceId,
                envelopeId: fixture.context.envelopeId,
                packetId: fixture.context.packetId
            )
            Issue.record("Unknown recipientKeyId must not open")
        } catch SealedInboundOpenError.recipientKeyUnknown(let keyId) {
            #expect(keyId == unknownId)
        }

        let nextFinal = try MLKEMPrivateKey(id: UUID(), MLKEM1024.PrivateKey().encode())
        keys.replaceFinalMLKEMPrivateKey(nextFinal, retainingPrevious: true)
        let legacy = SealedOuterCiphertext(
            version: sealed.version,
            kemCiphertext: sealed.kemCiphertext,
            aeadCiphertext: sealed.aeadCiphertext,
            recipientKeyId: nil
        )
        _ = try SealedInboundOpen.open(
            legacy,
            deviceKeys: keys,
            recipientSecretName: fixture.context.recipientSecretName,
            recipientDeviceId: fixture.context.recipientDeviceId,
            envelopeId: fixture.context.envelopeId,
            packetId: fixture.context.packetId
        )
    }

    @Test("dedicated sealed-sender rotation keeps one generation openable")
    func dedicatedKeyRotationOpensPreviousGeneration() throws {
        let fixture = try Fixture()
        var keys = DeviceKeys(
            deviceId: fixture.context.recipientDeviceId,
            signingPrivateKey: Data(repeating: 1, count: 32),
            longTermPrivateKey: Data(repeating: 2, count: 32),
            oneTimePrivateKeys: [],
            mlKEMOneTimePrivateKeys: [],
            finalMLKEMPrivateKey: try MLKEMPrivateKey(id: UUID(), MLKEM1024.PrivateKey().encode())
        )
        keys.replaceSealedSenderMLKEMPrivateKey(fixture.recipientPrivateKey, retainingPrevious: false)
        let sealed = try fixture.seal()
        #expect(sealed.recipientKeyId == fixture.recipientPrivateKey.id)

        let nextDedicated = try MLKEMPrivateKey(id: UUID(), MLKEM1024.PrivateKey().encode())
        keys.replaceSealedSenderMLKEMPrivateKey(nextDedicated, retainingPrevious: true)
        #expect(keys.sealedRecipientPrivateKey(matching: fixture.recipientPrivateKey.id) == fixture.recipientPrivateKey)
        _ = try SealedInboundOpen.open(
            sealed,
            deviceKeys: keys,
            recipientSecretName: fixture.context.recipientSecretName,
            recipientDeviceId: fixture.context.recipientDeviceId,
            envelopeId: fixture.context.envelopeId,
            packetId: fixture.context.packetId
        )
    }

    @Test("wrong final key fails closed")
    func wrongKeyFails() throws {
        let fixture = try Fixture()
        let sealed = try fixture.seal()
        let wrongKEM = try MLKEM1024.PrivateKey()
        let wrongPrivateKey = try MLKEMPrivateKey(
            id: UUID(),
            try wrongKEM.encode()
        )

        expectFailure(.authenticationFailed) {
            try fixture.open(
                sealed,
                recipientFinalMLKEMPrivateKey: wrongPrivateKey
            )
        }
    }

    @Test("every routing AAD field is authenticated")
    func wrongAADFails() throws {
        let fixture = try Fixture()
        let sealed = try fixture.seal()
        let original = fixture.context
        let variants = [
            Context(
                recipientSecretName: original.recipientSecretName + "-wrong",
                recipientDeviceId: original.recipientDeviceId,
                envelopeId: original.envelopeId,
                packetId: original.packetId
            ),
            Context(
                recipientSecretName: original.recipientSecretName,
                recipientDeviceId: UUID(),
                envelopeId: original.envelopeId,
                packetId: original.packetId
            ),
            Context(
                recipientSecretName: original.recipientSecretName,
                recipientDeviceId: original.recipientDeviceId,
                envelopeId: UUID().uuidString,
                packetId: original.packetId
            ),
            Context(
                recipientSecretName: original.recipientSecretName,
                recipientDeviceId: original.recipientDeviceId,
                envelopeId: original.envelopeId,
                packetId: UUID().uuidString
            ),
        ]

        for context in variants {
            expectFailure(.authenticationFailed) {
                try fixture.open(sealed, context: context)
            }
        }
    }

    @Test("KEM and AEAD tampering fail closed")
    func tamperingFails() throws {
        let fixture = try Fixture()
        let sealed = try fixture.seal()

        var kemCiphertext = sealed.kemCiphertext
        kemCiphertext[0] ^= 0x01
        let kemTampered = SealedOuterCiphertext(
            version: sealed.version,
            kemCiphertext: kemCiphertext,
            aeadCiphertext: sealed.aeadCiphertext
        )
        expectFailure(.authenticationFailed) {
            try fixture.open(kemTampered)
        }

        var aeadCiphertext = sealed.aeadCiphertext
        aeadCiphertext[aeadCiphertext.index(before: aeadCiphertext.endIndex)] ^= 0x01
        let aeadTampered = SealedOuterCiphertext(
            version: sealed.version,
            kemCiphertext: sealed.kemCiphertext,
            aeadCiphertext: aeadCiphertext
        )
        expectFailure(.authenticationFailed) {
            try fixture.open(aeadTampered)
        }
    }

    @Test("unsupported versions and malformed lengths are rejected")
    func versionAndLengthValidation() throws {
        let fixture = try Fixture()
        let sealed = try fixture.seal()

        expectFailure(.unsupportedVersion) {
            try fixture.open(
                SealedOuterCiphertext(
                    version: sealed.version &+ 1,
                    kemCiphertext: sealed.kemCiphertext,
                    aeadCiphertext: sealed.aeadCiphertext
                )
            )
        }
        expectFailure(.invalidKEMCiphertextLength) {
            try fixture.open(
                SealedOuterCiphertext(
                    version: sealed.version,
                    kemCiphertext: sealed.kemCiphertext.dropLast(),
                    aeadCiphertext: sealed.aeadCiphertext
                )
            )
        }
        expectFailure(.invalidAEADCiphertextLength) {
            try fixture.open(
                SealedOuterCiphertext(
                    version: sealed.version,
                    kemCiphertext: sealed.kemCiphertext,
                    aeadCiphertext: Data(repeating: 0, count: 27)
                )
            )
        }
    }

    @Test("repeated seals use fresh KEM encapsulations and nonces")
    func repeatedSealsAreUnique() throws {
        let fixture = try Fixture()
        let first = try fixture.seal()
        let second = try fixture.seal()

        #expect(first.kemCiphertext != second.kemCiphertext)
        #expect(first.aeadCiphertext != second.aeadCiphertext)
        #expect(first != second)
    }

    @Test("outer wire bytes expose neither certificate nor known inner key bytes")
    func sensitiveInnerBytesAreOpaque() throws {
        let fixture = try Fixture()
        let sealed = try fixture.seal()
        let wireBytes = try BinaryEncoder().encode(sealed)
        let encodedCertificate = try BinaryEncoder().encode(fixture.certificate)

        #expect(wireBytes.range(of: encodedCertificate) == nil)
        #expect(wireBytes.range(of: fixture.knownInnerKeyBytes) == nil)
        #expect(sealed.aeadCiphertext.range(of: encodedCertificate) == nil)
        #expect(sealed.aeadCiphertext.range(of: fixture.knownInnerKeyBytes) == nil)
    }
}

private extension SealedOuterBoxTests {
    struct Context {
        let recipientSecretName: String
        let recipientDeviceId: UUID
        let envelopeId: String
        let packetId: String
    }

    struct Fixture {
        let recipientPrivateKey: MLKEMPrivateKey
        let recipientPublicKey: MLKEMPublicKey
        let certificate: SenderCertificate
        let signedMessage: SignedRatchetMessage
        let knownInnerKeyBytes: Data
        let context: Context

        init() throws {
            let recipientKEM = try MLKEM1024.PrivateKey()
            recipientPrivateKey = try MLKEMPrivateKey(
                id: UUID(),
                try recipientKEM.encode()
            )
            recipientPublicKey = try MLKEMPublicKey(
                id: recipientPrivateKey.id,
                recipientKEM.publicKey.rawRepresentation
            )

            let certificateKey = try MLDSA65.PrivateKey()
            certificate = try SenderCertificate.issue(
                secretName: "alice",
                deviceId: UUID(uuidString: "00000000-0000-4000-8000-0000000000a1")!,
                issuedAt: Date(timeIntervalSince1970: 1_800_000_000),
                signingKey: certificateKey
            )

            knownInnerKeyBytes = Data(repeating: 0xA7, count: 32)
            let innerKEM = try MLKEM1024.PrivateKey()
            let header = EncryptedHeader(
                remoteLongTermPublicKey: knownInnerKeyBytes,
                remoteOneTimePublicKey: nil,
                remoteMLKEMPublicKey: try MLKEMPublicKey(
                    innerKEM.publicKey.rawRepresentation
                ),
                headerCiphertext: Data(repeating: 0xB8, count: 48),
                messageCiphertext: Data(repeating: 0xC9, count: 48),
                oneTimeKeyId: nil,
                mlKEMOneTimeKeyId: UUID(),
                encrypted: Data(repeating: 0xDA, count: 48)
            )
            signedMessage = try SignedRatchetMessage(
                message: RatchetMessage(
                    header: header,
                    ciphertext: Data("sealed inner message".utf8)
                ),
                signingPrivateKey: Curve25519.Signing.PrivateKey().rawRepresentation
            )

            context = Context(
                recipientSecretName: "bob",
                recipientDeviceId: UUID(uuidString: "00000000-0000-4000-8000-0000000000b1")!,
                envelopeId: "00000000-0000-4000-8000-0000000000e1",
                packetId: "00000000-0000-4000-8000-0000000000f1"
            )
        }

        func seal() throws -> SealedOuterCiphertext {
            try SealedOuterBox.seal(
                certificate: certificate,
                signedMessage: signedMessage,
                recipientFinalMLKEMPublicKey: recipientPublicKey,
                recipientSecretName: context.recipientSecretName,
                recipientDeviceId: context.recipientDeviceId,
                envelopeId: context.envelopeId,
                packetId: context.packetId
            )
        }

        func open(
            _ ciphertext: SealedOuterCiphertext,
            recipientFinalMLKEMPrivateKey: MLKEMPrivateKey? = nil,
            context: Context? = nil
        ) throws -> SealedSenderPlaintext {
            let context = context ?? self.context
            return try SealedOuterBox.open(
                ciphertext,
                recipientFinalMLKEMPrivateKey: recipientFinalMLKEMPrivateKey
                    ?? recipientPrivateKey,
                recipientSecretName: context.recipientSecretName,
                recipientDeviceId: context.recipientDeviceId,
                envelopeId: context.envelopeId,
                packetId: context.packetId
            )
        }
    }

    func expectFailure(
        _ expected: SealedOuterBoxError,
        performing operation: () throws -> SealedSenderPlaintext
    ) {
        do {
            _ = try operation()
            Issue.record("Expected \(expected), but operation succeeded")
        } catch let error as SealedOuterBoxError {
            #expect(error == expected)
        } catch {
            Issue.record("Expected \(expected), got \(error)")
        }
    }
}

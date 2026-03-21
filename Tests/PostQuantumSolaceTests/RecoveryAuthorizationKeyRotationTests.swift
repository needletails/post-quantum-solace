//
//  RecoveryAuthorizationKeyRotationTests.swift
//  post-quantum-solace
//
//  Guards binary layout and signing material for corrupt multi-device recovery (server verifies the
//  same bytes the client signs). Catches drift between app and API without a full Mongo deploy.
//

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
import SessionModels
import Testing

@Suite("Recovery authorization (key rotation wire contract)")
struct RecoveryAuthorizationKeyRotationTests {

    @Test("RotatedKeysRecoveryAuthorization binary round-trip preserves fields")
    func recoveryAuthorizationBinaryRoundTrip() throws {
        let secret = "nudge"
        let recovering = UUID()
        let newPSK = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let signedDeviceData = Data((0..<64).map { UInt8($0 % 256) })
        let a = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
        let b = UUID(uuidString: "BBBBBBBB-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!

        let original = RotatedKeysRecoveryAuthorization(
            secretName: secret,
            recoveringDeviceId: recovering,
            newSigningPublicKey: newPSK,
            newSignedDeviceData: signedDeviceData,
            prunedDeviceIds: [b, a]
        )
        #expect(original.prunedDeviceIds == [a, b])

        let encoded = try BinaryEncoder().encode(original)
        let decoded = try BinaryDecoder().decode(RotatedKeysRecoveryAuthorization.self, from: encoded)
        #expect(decoded.secretName == secret)
        #expect(decoded.recoveringDeviceId == recovering)
        #expect(decoded.newSigningPublicKey == newPSK)
        #expect(decoded.newSignedDeviceData == signedDeviceData)
        #expect(decoded.prunedDeviceIds == [a, b])
    }

    @Test("Pruned device id order does not change encoded authorization bytes (sorted in init)")
    func prunedOrderDoesNotChangeEncodedBytes() throws {
        let u1 = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let u2 = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let newPSK = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let data = Data(repeating: 7, count: 32)

        let enc1 = try BinaryEncoder().encode(
            RotatedKeysRecoveryAuthorization(
                secretName: "s",
                recoveringDeviceId: u1,
                newSigningPublicKey: newPSK,
                newSignedDeviceData: data,
                prunedDeviceIds: [u1, u2]
            )
        )
        let enc2 = try BinaryEncoder().encode(
            RotatedKeysRecoveryAuthorization(
                secretName: "s",
                recoveringDeviceId: u1,
                newSigningPublicKey: newPSK,
                newSignedDeviceData: data,
                prunedDeviceIds: [u2, u1]
            )
        )
        #expect(enc1 == enc2)
    }

    @Test("Recovery proof verifies with account signing key or device signing key (server OR semantics)")
    func recoverySignatureVerifiesWithAccountOrDeviceKey() throws {
        let accountKey = Curve25519.Signing.PrivateKey()
        let deviceKey = Curve25519.Signing.PrivateKey()
        let recovering = UUID()
        let pruned = UUID()
        let newAccount = Curve25519.Signing.PrivateKey()
        let signedBlob = Data(repeating: 3, count: 48)

        let authorization = RotatedKeysRecoveryAuthorization(
            secretName: "user-secret",
            recoveringDeviceId: recovering,
            newSigningPublicKey: newAccount.publicKey.rawRepresentation,
            newSignedDeviceData: signedBlob,
            prunedDeviceIds: [pruned]
        )
        let authorizationData = try BinaryEncoder().encode(authorization)

        let sigAccount = try accountKey.signature(for: authorizationData)
        let sigDevice = try deviceKey.signature(for: authorizationData)

        let accountPub = accountKey.publicKey
        let devicePub = deviceKey.publicKey

        #expect(accountPub.isValidSignature(sigAccount, for: authorizationData))
        #expect(devicePub.isValidSignature(sigDevice, for: authorizationData))
        #expect(!accountPub.isValidSignature(sigDevice, for: authorizationData))
        #expect(!devicePub.isValidSignature(sigAccount, for: authorizationData))
    }

    @Test("RotatedPublicKeys with recovery encodes and decodes for transport")
    func rotatedPublicKeysWithRecoveryRoundTrip() throws {
        let newAccount = Curve25519.Signing.PrivateKey()
        let deviceKey = Curve25519.Signing.PrivateKey()
        let mlkem = try MLKEMPublicKey(Data(repeating: 9, count: 1568))
        let device = UserDeviceConfiguration(
            deviceId: UUID(),
            signingPublicKey: deviceKey.publicKey.rawRepresentation,
            longTermPublicKey: Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation,
            finalMLKEMPublicKey: mlkem,
            deviceName: "d",
            hmacData: Data(repeating: 1, count: 32),
            isMasterDevice: true
        )
        let signedDevice = try UserConfiguration.SignedDeviceConfiguration(device: device, signingKey: newAccount)
        let recovery = RotatedKeysRecovery(
            recoveringDeviceId: device.deviceId,
            prunedDeviceIds: [UUID()],
            oldAccountSignature: Data(repeating: 0xAB, count: 64)
        )
        let rotated = RotatedPublicKeys(
            pskData: newAccount.publicKey.rawRepresentation,
            signedDevice: signedDevice,
            recovery: recovery
        )
        let data = try BinaryEncoder().encode(rotated)
        let back = try BinaryDecoder().decode(RotatedPublicKeys.self, from: data)
        #expect(back.pskData == rotated.pskData)
        #expect(back.signedDevice.id == rotated.signedDevice.id)
        #expect(back.recovery?.recoveringDeviceId == recovery.recoveringDeviceId)
        #expect(back.recovery?.prunedDeviceIds == recovery.prunedDeviceIds)
        #expect(back.recovery?.oldAccountSignature == recovery.oldAccountSignature)
        #expect(back.allSignedDevices == nil)
    }
}

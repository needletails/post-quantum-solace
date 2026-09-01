//
//  SealedOuterBox.swift
//  post-quantum-solace
//
//  ML-KEM-1024 + HKDF-SHA256 + AES-GCM sealed-sender protection.
//

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation

public enum SealedOuterBoxError: Error, Equatable, Sendable {
    case unsupportedVersion
    case invalidKEMCiphertextLength
    case invalidAEADCiphertextLength
    case invalidRecipientSecretName
    case invalidRecipientKey
    case plaintextTooLarge
    case encryptionFailed
    case authenticationFailed
}

/// Post-quantum outer protection for a sealed-sender ratchet message.
///
/// Every call to ``seal(certificate:signedMessage:recipientFinalMLKEMPublicKey:recipientSecretName:recipientDeviceId:envelopeId:packetId:)``
/// performs a fresh ML-KEM-1024 encapsulation. It never reads or consumes
/// recipient one-time keys.
public enum SealedOuterBox {
    public static let currentVersion: UInt8 = 1

    private static let mlKEM1024CiphertextLength = 1_568
    private static let aesGCMOverhead = 12 + 16
    private static let maximumAEADCiphertextLength = 16 * 1_024 * 1_024
    private static let maximumSecretNameLength = 1_024
    private static let hkdfDomain = Data("NeedleTails/PQS/SealedOuterBox/HKDF-SHA256/v1".utf8)
    private static let hkdfSaltDomain = Data("NeedleTails/PQS/SealedOuterBox/HKDF-SALT/v1".utf8)
    private static let aadDomain = Data("NeedleTails/PQS/SealedOuterBox/AAD/v1".utf8)

    /// Encrypts a sender certificate and encoded signed ratchet message for one
    /// recipient device's final ML-KEM-1024 public key.
    public static func seal(
        certificate: SenderCertificate,
        signedMessage: SignedRatchetMessage,
        recipientFinalMLKEMPublicKey: MLKEMPublicKey,
        recipientSecretName: String,
        recipientDeviceId: UUID,
        envelopeId: String,
        packetId: String
    ) throws -> SealedOuterCiphertext {
        try validateRecipientSecretName(recipientSecretName)

        let encodedMessage: Data
        let plaintext: Data
        do {
            encodedMessage = try BinaryEncoder().encode(signedMessage)
            plaintext = try BinaryEncoder().encode(
                SealedSenderPlaintext(
                    certificate: certificate,
                    innerMessage: encodedMessage
                )
            )
        } catch {
            throw SealedOuterBoxError.encryptionFailed
        }

        guard plaintext.count <= maximumAEADCiphertextLength - aesGCMOverhead else {
            throw SealedOuterBoxError.plaintextTooLarge
        }

        let recipientPublicKey: MLKEM1024.PublicKey
        do {
            recipientPublicKey = try MLKEM1024.PublicKey(
                rawRepresentation: recipientFinalMLKEMPublicKey.rawRepresentation
            )
        } catch {
            throw SealedOuterBoxError.invalidRecipientKey
        }

        do {
            let encapsulation = try recipientPublicKey.encapsulate()
            let kemCiphertext = encapsulation.encapsulated
            guard kemCiphertext.count == mlKEM1024CiphertextLength else {
                throw SealedOuterBoxError.invalidKEMCiphertextLength
            }

            let aad = try canonicalAAD(
                version: currentVersion,
                kemCiphertext: kemCiphertext,
                recipientSecretName: recipientSecretName,
                recipientDeviceId: recipientDeviceId,
                envelopeId: envelopeId,
                packetId: packetId
            )
            let key = deriveAEADKey(
                from: encapsulation.sharedSecret,
                kemCiphertext: kemCiphertext
            )
            let sealed = try AES.GCM.seal(
                plaintext,
                using: key,
                nonce: AES.GCM.Nonce(),
                authenticating: aad
            )
            guard let combined = sealed.combined,
                  combined.count >= aesGCMOverhead,
                  combined.count <= maximumAEADCiphertextLength
            else {
                throw SealedOuterBoxError.encryptionFailed
            }

            return SealedOuterCiphertext(
                version: currentVersion,
                kemCiphertext: kemCiphertext,
                aeadCiphertext: combined
            )
        } catch let error as SealedOuterBoxError {
            throw error
        } catch {
            throw SealedOuterBoxError.encryptionFailed
        }
    }

    /// Authenticates and decrypts a sealed-sender payload with the recipient
    /// device's final ML-KEM-1024 private key.
    ///
    /// Authentication, key, AAD, and inner-decoding failures intentionally
    /// collapse to ``SealedOuterBoxError/authenticationFailed``.
    public static func open(
        _ ciphertext: SealedOuterCiphertext,
        recipientFinalMLKEMPrivateKey: MLKEMPrivateKey,
        recipientSecretName: String,
        recipientDeviceId: UUID,
        envelopeId: String,
        packetId: String
    ) throws -> SealedSenderPlaintext {
        try validate(ciphertext)
        try validateRecipientSecretName(recipientSecretName)

        let aad = try canonicalAAD(
            version: ciphertext.version,
            kemCiphertext: ciphertext.kemCiphertext,
            recipientSecretName: recipientSecretName,
            recipientDeviceId: recipientDeviceId,
            envelopeId: envelopeId,
            packetId: packetId
        )

        do {
            let recipientPrivateKey = try recipientFinalMLKEMPrivateKey
                .rawRepresentation
                .decodeMLKem1024()
            let sharedSecret = try recipientPrivateKey.decapsulate(ciphertext.kemCiphertext)
            let key = deriveAEADKey(
                from: sharedSecret,
                kemCiphertext: ciphertext.kemCiphertext
            )
            let sealed = try AES.GCM.SealedBox(combined: ciphertext.aeadCiphertext)
            let encodedPlaintext = try AES.GCM.open(
                sealed,
                using: key,
                authenticating: aad
            )
            let plaintext = try BinaryDecoder().decode(
                SealedSenderPlaintext.self,
                from: encodedPlaintext
            )

            // The outer box only accepts the Stage 2 payload shape. A valid
            // AEAD plaintext containing arbitrary bytes is still rejected.
            _ = try BinaryDecoder().decode(
                SignedRatchetMessage.self,
                from: plaintext.innerMessage
            )
            return plaintext
        } catch {
            throw SealedOuterBoxError.authenticationFailed
        }
    }

    private static func validate(_ ciphertext: SealedOuterCiphertext) throws {
        guard ciphertext.version == currentVersion else {
            throw SealedOuterBoxError.unsupportedVersion
        }
        guard ciphertext.kemCiphertext.count == mlKEM1024CiphertextLength else {
            throw SealedOuterBoxError.invalidKEMCiphertextLength
        }
        guard ciphertext.aeadCiphertext.count >= aesGCMOverhead,
              ciphertext.aeadCiphertext.count <= maximumAEADCiphertextLength
        else {
            throw SealedOuterBoxError.invalidAEADCiphertextLength
        }
    }

    private static func validateRecipientSecretName(_ secretName: String) throws {
        let count = secretName.utf8.count
        guard count > 0, count <= maximumSecretNameLength else {
            throw SealedOuterBoxError.invalidRecipientSecretName
        }
    }

    private static func deriveAEADKey(
        from sharedSecret: SymmetricKey,
        kemCiphertext: Data
    ) -> SymmetricKey {
        var saltInput = hkdfSaltDomain
        saltInput.append(kemCiphertext)
        let salt = Data(SHA256.hash(data: saltInput))
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecret,
            salt: salt,
            info: hkdfDomain,
            outputByteCount: 32
        )
    }

    /// Canonical AAD: fixed domain followed by a UInt32 big-endian length and
    /// raw bytes for every field, in the order listed below.
    private static func canonicalAAD(
        version: UInt8,
        kemCiphertext: Data,
        recipientSecretName: String,
        recipientDeviceId: UUID,
        envelopeId: String,
        packetId: String
    ) throws -> Data {
        var aad = Data()
        try appendLengthPrefixed(aadDomain, to: &aad)
        try appendLengthPrefixed(Data([version]), to: &aad)
        try appendLengthPrefixed(kemCiphertext, to: &aad)
        try appendLengthPrefixed(Data(recipientSecretName.utf8), to: &aad)
        try appendLengthPrefixed(bytes(of: recipientDeviceId), to: &aad)
        try appendLengthPrefixed(Data(envelopeId.utf8), to: &aad)
        try appendLengthPrefixed(Data(packetId.utf8), to: &aad)
        return aad
    }

    private static func appendLengthPrefixed(_ field: Data, to output: inout Data) throws {
        guard let count = UInt32(exactly: field.count) else {
            throw SealedOuterBoxError.invalidAEADCiphertextLength
        }
        var bigEndianCount = count.bigEndian
        withUnsafeBytes(of: &bigEndianCount) {
            output.append(contentsOf: $0)
        }
        output.append(field)
    }

    private static func bytes(of uuid: UUID) -> Data {
        var value = uuid.uuid
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}

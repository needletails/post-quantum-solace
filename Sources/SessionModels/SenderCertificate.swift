//
//  SenderCertificate.swift
//  post-quantum-solace
//
//  Short-lived ML-DSA-65 sender identity, carried inside AEAD ciphertext.
//

import Crypto
import Foundation

public enum SenderCertificateError: Error, Equatable, Sendable {
    case expired
    case identityMismatch
    case invalidSignature
    case unsupportedAlgorithm
    case invalidPublicKey
}

/// Recipient-verified proof of who sent a sealed DM. Never placed on the
/// routing envelope.
public struct SenderCertificate: Codable, Sendable, Equatable {
    public static let mlDSA65Algorithm = "ML-DSA-65"
    public static let defaultLifetime: TimeInterval = 24 * 3600
    public static let clockSkew: TimeInterval = 5 * 60

    public let secretName: String
    public let deviceId: UUID
    public let expiresAt: Date
    public let algorithm: String
    public let authorityKeyId: String?
    public let signature: Data

    public init(
        secretName: String,
        deviceId: UUID,
        expiresAt: Date,
        algorithm: String = mlDSA65Algorithm,
        authorityKeyId: String? = nil,
        signature: Data
    ) {
        self.secretName = secretName
        self.deviceId = deviceId
        self.expiresAt = expiresAt
        self.algorithm = algorithm
        self.authorityKeyId = authorityKeyId
        self.signature = signature
    }

    public static func toBeSigned(
        secretName: String,
        deviceId: UUID,
        expiresAt: Date,
        algorithm: String = mlDSA65Algorithm,
        authorityKeyId: String? = nil
    ) -> Data {
        var data = Data()
        data.append(contentsOf: secretName.utf8)
        data.append(0)
        var uuid = deviceId.uuid
        withUnsafeBytes(of: &uuid) { data.append(contentsOf: $0) }
        var expiry = Int64(expiresAt.timeIntervalSince1970).bigEndian
        withUnsafeBytes(of: &expiry) { data.append(contentsOf: $0) }
        data.append(contentsOf: algorithm.utf8)
        if let authorityKeyId {
            data.append(0)
            data.append(contentsOf: authorityKeyId.utf8)
        }
        return data
    }

    public static func issue(
        secretName: String,
        deviceId: UUID,
        issuedAt: Date = Date(),
        lifetime: TimeInterval = defaultLifetime,
        authorityKeyId: String? = nil,
        signingKey: MLDSA65.PrivateKey
    ) throws -> SenderCertificate {
        let expiresAt = issuedAt.addingTimeInterval(lifetime)
        let tbs = toBeSigned(
            secretName: secretName,
            deviceId: deviceId,
            expiresAt: expiresAt,
            authorityKeyId: authorityKeyId
        )
        let signature = try signingKey.signature(for: tbs)
        return SenderCertificate(
            secretName: secretName,
            deviceId: deviceId,
            expiresAt: expiresAt,
            authorityKeyId: authorityKeyId,
            signature: Data(signature)
        )
    }

    /// Verifies cryptographic validity before the caller trusts the embedded
    /// sender identity. Sealed receive cannot know that identity in advance.
    public func verify(
        againstPublicKey publicKeyBytes: Data,
        now: Date = Date()
    ) throws {
        guard algorithm == Self.mlDSA65Algorithm else {
            throw SenderCertificateError.unsupportedAlgorithm
        }
        if now > expiresAt.addingTimeInterval(Self.clockSkew) {
            throw SenderCertificateError.expired
        }
        let publicKey: MLDSA65.PublicKey
        do {
            publicKey = try MLDSA65.PublicKey(rawRepresentation: publicKeyBytes)
        } catch {
            throw SenderCertificateError.invalidPublicKey
        }
        let tbs = Self.toBeSigned(
            secretName: secretName,
            deviceId: deviceId,
            expiresAt: expiresAt,
            algorithm: algorithm,
            authorityKeyId: authorityKeyId
        )
        guard publicKey.isValidSignature(signature, for: tbs) else {
            throw SenderCertificateError.invalidSignature
        }
    }

    public func verify(
        againstPublicKey publicKeyBytes: Data,
        expectedSecretName: String,
        expectedDeviceId: UUID,
        now: Date = Date()
    ) throws {
        try verify(againstPublicKey: publicKeyBytes, now: now)
        guard secretName == expectedSecretName, deviceId == expectedDeviceId else {
            throw SenderCertificateError.identityMismatch
        }
    }
}

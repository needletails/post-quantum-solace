//
//  OutOfBandResendControl.swift
//  post-quantum-solace
//

import Crypto
import Foundation

/// Authenticated §4.1 retry control carried outside Double Ratchet.
public struct OutOfBandResendControl: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        case request
        case unavailable
    }

    public enum ValidationError: Error {
        case emptyMessageIds
        case tooManyMessageIds
        case invalidMessageId
        case invalidSignature
    }

    public static let maxMessageIds = 64

    public let version: UInt8
    public let kind: Kind
    public let requestId: UUID
    public let senderSecretName: String
    public let senderDeviceId: UUID
    public let targetSecretName: String
    public let targetDeviceId: UUID
    public let envelopeMessageIds: [String]
    public let signature: Data

    public init(
        kind: Kind,
        requestId: UUID = UUID(),
        senderSecretName: String,
        senderDeviceId: UUID,
        targetSecretName: String,
        targetDeviceId: UUID,
        envelopeMessageIds: [String],
        signingPrivateKey: Data
    ) throws {
        try Self.validateMessageIds(envelopeMessageIds)
        self.version = 1
        self.kind = kind
        self.requestId = requestId
        self.senderSecretName = senderSecretName
        self.senderDeviceId = senderDeviceId
        self.targetSecretName = targetSecretName
        self.targetDeviceId = targetDeviceId
        self.envelopeMessageIds = envelopeMessageIds
        let privateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: signingPrivateKey)
        self.signature = try privateKey.signature(
            for: Self.canonicalSigningData(
                version: 1,
                kind: kind,
                requestId: requestId,
                senderSecretName: senderSecretName,
                senderDeviceId: senderDeviceId,
                targetSecretName: targetSecretName,
                targetDeviceId: targetDeviceId,
                envelopeMessageIds: envelopeMessageIds))
    }

    public func verify(signingPublicKey: Data) throws {
        try Self.validateMessageIds(envelopeMessageIds)
        let publicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: signingPublicKey)
        guard publicKey.isValidSignature(signature, for: canonicalSigningData()) else {
            throw ValidationError.invalidSignature
        }
    }

    public func canonicalSigningData() -> Data {
        Self.canonicalSigningData(
            version: version,
            kind: kind,
            requestId: requestId,
            senderSecretName: senderSecretName,
            senderDeviceId: senderDeviceId,
            targetSecretName: targetSecretName,
            targetDeviceId: targetDeviceId,
            envelopeMessageIds: envelopeMessageIds)
    }

    private static func canonicalSigningData(
        version: UInt8,
        kind: Kind,
        requestId: UUID,
        senderSecretName: String,
        senderDeviceId: UUID,
        targetSecretName: String,
        targetDeviceId: UUID,
        envelopeMessageIds: [String]
    ) -> Data {
        var data = Data([version])
        append(kind.rawValue, to: &data)
        append(requestId.uuidString.lowercased(), to: &data)
        append(senderSecretName, to: &data)
        append(senderDeviceId.uuidString.lowercased(), to: &data)
        append(targetSecretName, to: &data)
        append(targetDeviceId.uuidString.lowercased(), to: &data)
        var count = UInt32(envelopeMessageIds.count).bigEndian
        withUnsafeBytes(of: &count) { data.append(contentsOf: $0) }
        for messageId in envelopeMessageIds {
            append(messageId, to: &data)
        }
        return data
    }

    private static func append(_ value: String, to data: inout Data) {
        let bytes = Data(value.utf8)
        var length = UInt32(bytes.count).bigEndian
        withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
        data.append(bytes)
    }

    private static func validateMessageIds(_ messageIds: [String]) throws {
        guard !messageIds.isEmpty else { throw ValidationError.emptyMessageIds }
        guard messageIds.count <= maxMessageIds else {
            throw ValidationError.tooManyMessageIds
        }
        guard messageIds.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 256 }) else {
            throw ValidationError.invalidMessageId
        }
    }
}

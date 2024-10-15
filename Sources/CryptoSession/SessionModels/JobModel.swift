//
//  JobModel.swift
//  needletail-crypto
//
//  Created by Cole M on 9/15/24.
//
import Foundation
import BSON
import NeedleTailCrypto
import DoubleRatchetKit
@preconcurrency import Crypto

public struct Job: Sendable, Codable, Equatable {
    public let id: UUID
    public let sequenceId: Int
    public let isBackgroundTask: Bool
    var task: EncrytableTask
    public var delayedUntil: Date?
    public var scheduledAt: Date
    public var attempts: Int
    
    public static func == (lhs: Job, rhs: Job) -> Bool {
        return lhs.id == rhs.id
    }
}

public final class JobModel: SecureModelProtocol, Codable, @unchecked Sendable {
    public let id = UUID()
    public var data: Data
    
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id = "a"
        case data = "b"
    }
    
    /// SymmetricKey can be updated.
    private var symmetricKey: SymmetricKey?
    
    /// Asynchronously retrieves the decrypted properties, if available.
    var props: UnwrappedProps? {
        get async {
            do {
                guard let symmetricKey = symmetricKey else { return nil }
                return try await decryptProps(symmetricKey: symmetricKey)
            } catch {
                return nil
            }
        }
    }
    
    public struct UnwrappedProps: Codable & Sendable {
        private enum CodingKeys: String, CodingKey, Sendable {
            case sequenceId = "a"
            case task = "b"
            case isBackgroundTask = "c"
            case delayedUntil = "d"
            case scheduledAt = "e"
            case attempts = "f"
        }
        let sequenceId: Int
        var task: EncrytableTask
        let isBackgroundTask: Bool
        var delayedUntil: Date?
        var scheduledAt: Date
        var attempts: Int
    }
    
    init(
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.symmetricKey = symmetricKey
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    public init(data: Data) {
        self.data = data
    }
    
    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    /// - Throws: An error if decryption fails.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        let crypto = NeedleTailCrypto()
        guard let decrypted = try crypto.decrypt(data: self.data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionError
        }
        return try BSONDecoder().decodeData(UnwrappedProps.self, from: decrypted)
    }
    
    /// Asynchronously updates the properties of the model.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - props: The new unwrapped properties to be set.
    /// - Returns: The updated decrypted properties.
    ///
    /// - Throws: An error if encryption fails.
    public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps? {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return await self.props
    }
    
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type) async throws -> T {
        guard let props = await props else { throw CryptoSession.SessionErrors.propsError }
        return Job(
            id: id,
            sequenceId: props.sequenceId,
            isBackgroundTask: props.isBackgroundTask,
            task: props.task,
            scheduledAt: props.scheduledAt,
            attempts: props.attempts) as! T
    }
}

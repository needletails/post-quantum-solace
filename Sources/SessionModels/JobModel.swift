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
import NeedleTailAsyncSequence
import Crypto

public struct OutboundTaskMessage: Codable & Sendable {
    public var message: CryptoMessage
    public let recipientIdentity: SessionIdentity
    public let localId: UUID
    public let sharedId: String
    
    public init(
        message: CryptoMessage,
        recipientIdentity: SessionIdentity,
        localId: UUID,
        sharedId: String
    ) {
        self.message = message
        self.recipientIdentity = recipientIdentity
        self.localId = localId
        self.sharedId = sharedId
    }
}


public struct InboundTaskMessage: Codable & Sendable {
    public let message: SignedRatchetMessage
    public let senderSecretName: String
    public let senderDeviceId: UUID
    public let sharedMessageId: String
    
    public init(
        message: SignedRatchetMessage,
        senderSecretName: String,
        senderDeviceId: UUID,
        sharedMessageId: String
    ) {
        self.message = message
        self.senderSecretName = senderSecretName
        self.senderDeviceId = senderDeviceId
        self.sharedMessageId = sharedMessageId
    }
}


public enum TaskType: Codable & Sendable {
    case streamMessage(InboundTaskMessage), writeMessage(OutboundTaskMessage)
}

public struct EncrytableTask: Codable & Sendable {
    public let task: TaskType
    public let priority: Priority
    public let scheduledAt: Date
    
    public init(
        task: TaskType,
        priority: Priority = .standard,
        scheduledAt: Date = Date()
    ) {
        self.task = task
        self.priority = priority
        self.scheduledAt = scheduledAt
    }
}

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
    public let id: UUID
    public var data: Data
    
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id = "a"
        case data = "b"
    }
    
    /// Asynchronously retrieves the decrypted properties, if available.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
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
        public let sequenceId: Int
        public var task: EncrytableTask
        public let isBackgroundTask: Bool
        public var delayedUntil: Date?
        public var scheduledAt: Date
        public var attempts: Int
        
        public init(
            sequenceId: Int,
            task: EncrytableTask,
            isBackgroundTask: Bool,
            delayedUntil: Date? = nil,
            scheduledAt: Date,
            attempts: Int
        ) {
            self.sequenceId = sequenceId
            self.task = task
            self.isBackgroundTask = isBackgroundTask
            self.delayedUntil = delayedUntil
            self.scheduledAt = scheduledAt
            self.attempts = attempts
        }
        
    }
    
    public init(
        id: UUID,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.id = id
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    public init(id: UUID, data: Data) {
        self.id = id
        self.data = data
    }
    
    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    /// - Throws: An error if decryption fails.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        let crypto = NeedleTailCrypto()
        guard let decrypted = try crypto.decrypt(data: self.data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionFailed
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
        return try await self.decryptProps(symmetricKey: symmetricKey)
    }
    
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw Errors.propsError
        }
        return Job(
            id: id,
            sequenceId: props.sequenceId,
            isBackgroundTask: props.isBackgroundTask,
            task: props.task,
            scheduledAt: props.scheduledAt,
            attempts: props.attempts) as! T
    }
    
    private enum Errors: Error {
        case propsError
    }
}

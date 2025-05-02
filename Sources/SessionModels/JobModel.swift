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

/// A struct representing an outbound task message to be sent to a recipient.
public struct OutboundTaskMessage: Codable & Sendable {
    /// The message content to be sent.
    public var message: CryptoMessage
    
    /// The identity of the recipient session.
    public let recipientIdentity: SessionIdentity
    
    /// A unique identifier for the local message.
    public let localId: UUID
    
    /// A shared identifier for the message.
    public let sharedId: String
    
    /// Initializes a new instance of `OutboundTaskMessage`.
    /// - Parameters:
    ///   - message: The message content to be sent.
    ///   - recipientIdentity: The identity of the recipient session.
    ///   - localId: A unique identifier for the local message.
    ///   - sharedId: A shared identifier for the message.
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

/// A struct representing an inbound task message received from a sender.
public struct InboundTaskMessage: Codable & Sendable {
    /// The signed ratchet message received.
    public let message: SignedRatchetMessage
    
    /// The secret name of the sender.
    public let senderSecretName: String
    
    /// The unique identifier for the sender's device.
    public let senderDeviceId: UUID
    
    /// A shared identifier for the message.
    public let sharedMessageId: String
    
    /// Initializes a new instance of `InboundTaskMessage`.
    /// - Parameters:
    ///   - message: The signed ratchet message received.
    ///   - senderSecretName: The secret name of the sender.
    ///   - senderDeviceId: The unique identifier for the sender's device.
    ///   - sharedMessageId: A shared identifier for the message.
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

/// An enumeration representing the type of task, which can be either an inbound or outbound message.
public enum TaskType: Codable & Sendable {
    case streamMessage(InboundTaskMessage)
    case writeMessage(OutboundTaskMessage)
}

/// A struct representing an encryptable task with associated priority and scheduling information.
public struct EncrytableTask: Codable & Sendable {
    /// The task type, which can be an inbound or outbound message.
    public let task: TaskType
    
    /// The priority of the task.
    public let priority: Priority
    
    /// The date and time when the task is scheduled.
    public let scheduledAt: Date
    
    /// Initializes a new instance of `EncrytableTask`.
    /// - Parameters:
    ///   - task: The task type (inbound or outbound message).
    ///   - priority: The priority of the task (default is `.standard`).
    ///   - scheduledAt: The date and time when the task is scheduled (default is the current date).
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

/// A struct representing a job that can be scheduled and executed.
public struct Job: Sendable, Codable, Equatable {
    /// A unique identifier for the job.
    public let id: UUID
    
    /// The sequence identifier for the job.
    public let sequenceId: Int
    
    /// A Boolean indicating whether the job is a background task.
    public let isBackgroundTask: Bool
    
    /// The task associated with the job.
    var task: EncrytableTask
    
    /// The date until which the job is delayed, if applicable.
    public var delayedUntil: Date?
    
    /// The date and time when the job is scheduled.
    public var scheduledAt: Date
    
    /// The number of attempts made to execute the job.
    public var attempts: Int
    
    /// Compares two `Job` instances for equality.
    /// - Parameters:
    ///   - lhs: The first `Job` instance.
    ///   - rhs: The second `Job` instance.
    /// - Returns: A Boolean value indicating whether the two instances are equal.
    public static func == (lhs: Job, rhs: Job) -> Bool {
        return lhs.id == rhs.id
    }
}

/// A model representing a job with secure properties and methods for encryption and decryption.
public final class JobModel: SecureModelProtocol, Codable, @unchecked Sendable {
    /// A unique identifier for the job model.
    public let id: UUID
    
    /// The encrypted data associated with the job model.
    public var data: Data
    
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id = "a"
        case data = "b"
    }
    
    /// Asynchronously retrieves the decrypted properties of the job model, if available.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: An optional `UnwrappedProps` containing the decrypted properties.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }

    /// A struct representing the unwrapped properties of the job model.
    public struct UnwrappedProps: Codable & Sendable {
        private enum CodingKeys: String, CodingKey, Sendable {
            case sequenceId = "a"
            case task = "b"
            case isBackgroundTask = "c"
            case delayedUntil = "d"
            case scheduledAt = "e"
            case attempts = "f"
        }
        
        /// The sequence identifier for the job.
        public let sequenceId: Int
        
        /// The task associated with the job.
        public var task: EncrytableTask
        
        /// A Boolean indicating whether the job is a background task.
        public let isBackgroundTask: Bool
        
        /// The date until which the job is delayed, if applicable.
        public var delayedUntil: Date?
        
        /// The date and time when the job is scheduled.
        public var scheduledAt: Date
        
        /// The number of attempts made to execute the job.
        public var attempts: Int
        
        /// Initializes a new instance of `UnwrappedProps`.
        /// - Parameters:
        ///   - sequenceId: The sequence identifier for the job.
        ///   - task: The task associated with the job.
        ///   - isBackgroundTask: A Boolean indicating whether the job is a background task.
        ///   - delayedUntil: The date until which the job is delayed, if applicable.
        ///   - scheduledAt: The date and time when the job is scheduled.
        ///   - attempts: The number of attempts made to execute the job.
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
    
    /// Initializes a new `JobModel` instance.
    /// - Parameters:
    ///   - id: A unique identifier for the job model.
    ///   - props: The unwrapped properties of the job model.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if encryption fails.
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
    
    /// Initializes a new `JobModel` instance with existing encrypted data.
    /// - Parameters:
    ///   - id: A unique identifier for the job model.
    ///   - data: The encrypted data associated with the job model.
    public init(id: UUID, data: Data) {
        self.id = id
        self.data = data
    }
    
    /// Asynchronously decrypts the properties of the job model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties of the job model.
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

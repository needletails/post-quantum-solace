//
//  JobModel.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-15.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//
//
//  This file contains models for job management in the post-quantum solace system.
//  It provides structures for representing outbound and inbound task messages,
//  encryptable tasks with priority and scheduling, and secure job models with
//  encryption/decryption capabilities.
//
import BSON
import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailAsyncSequence
import NeedleTailCrypto

/// A struct representing an outbound task message to be sent to a recipient.
///
/// This struct encapsulates all the necessary information for sending a message
/// to a specific recipient, including the message content, recipient identity,
/// and tracking identifiers.
public struct OutboundTaskMessage: Codable & Sendable {
    /// The encrypted message content to be sent.
    public var message: CryptoMessage

    /// The identity of the recipient session for routing and authentication.
    public let recipientIdentity: SessionIdentity

    /// A unique identifier for the local message used for tracking and deduplication.
    public let localId: UUID

    /// A shared identifier for the message that can be used across devices.
    public let sharedId: String

    /// Initializes a new instance of `OutboundTaskMessage`.
    /// - Parameters:
    ///   - message: The encrypted message content to be sent.
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
///
/// This struct contains all the information needed to process a received message,
/// including the signed ratchet message, sender identification, and message tracking.
public struct InboundTaskMessage: Codable & Sendable {
    /// The signed ratchet message containing the encrypted payload and authentication.
    public let message: SignedRatchetMessage

    /// The secret name of the sender for privacy and identification.
    public let senderSecretName: String

    /// The unique identifier for the sender's device for routing and verification.
    public let senderDeviceId: UUID

    /// A shared identifier for the message that can be used across devices.
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
///
/// This enum provides type safety for distinguishing between incoming and outgoing
/// message processing tasks in the job queue system.
public enum TaskType: Codable & Sendable {
    /// A task for processing an incoming message from a sender.
    case streamMessage(InboundTaskMessage)
    /// A task for sending an outgoing message to a recipient.
    case writeMessage(OutboundTaskMessage)
}

/// A struct representing an encryptable task with associated priority and scheduling information.
///
/// This struct wraps a task with additional metadata for job queue management,
/// including priority levels and scheduling information for optimal processing.
public struct EncryptableTask: Codable & Sendable {
    /// The task type, which can be an inbound or outbound message.
    public let task: TaskType

    /// The priority of the task for queue ordering and resource allocation.
    public let priority: Priority

    /// The date and time when the task is scheduled for execution.
    public let scheduledAt: Date

    /// Initializes a new instance of `EncryptableTask`.
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
///
/// This struct contains all the information needed to manage a job in the queue,
/// including scheduling, retry logic, and task execution details.
public struct Job: Sendable, Codable, Equatable {
    /// A unique identifier for the job.
    public let id: UUID

    /// The sequence identifier for the job used for ordering and tracking.
    public let sequenceId: Int

    /// A Boolean indicating whether the job is a background task.
    public let isBackgroundTask: Bool

    /// The task associated with the job containing the actual work to be performed.
    var task: EncryptableTask

    /// The date until which the job is delayed, if applicable.
    public var delayedUntil: Date?

    /// The date and time when the job is scheduled for execution.
    public var scheduledAt: Date

    /// The number of attempts made to execute the job.
    public var attempts: Int

    /// Compares two `Job` instances for equality based on their unique identifiers.
    /// - Parameters:
    ///   - lhs: The first `Job` instance.
    ///   - rhs: The second `Job` instance.
    /// - Returns: A Boolean value indicating whether the two instances are equal.
    public static func == (lhs: Job, rhs: Job) -> Bool {
        lhs.id == rhs.id
    }
}

/// A model representing a job with secure properties and methods for encryption and decryption.
///
/// This class implements the `SecureModelProtocol` to provide encrypted storage
/// and retrieval of job data, ensuring sensitive information is protected at rest.
/// The encrypted data uses obfuscated coding keys for additional security.
public final class JobModel: SecureModelProtocol, Codable, @unchecked Sendable {
    /// A unique identifier for the job model.
    public let id: UUID

    /// The encrypted data associated with the job model.
    public var data: Data

    /// Coding keys with obfuscated names for enhanced security.
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
    ///
    /// This struct contains all the decrypted job properties that are stored
    /// in an encrypted format within the `JobModel`. The coding keys are
    /// obfuscated for additional security.
    public struct UnwrappedProps: Codable & Sendable {
        /// Coding keys with obfuscated names for enhanced security.
        private enum CodingKeys: String, CodingKey, Sendable {
            case sequenceId = "a"
            case task = "b"
            case isBackgroundTask = "c"
            case delayedUntil = "d"
            case scheduledAt = "e"
            case attempts = "f"
        }

        /// The sequence identifier for the job used for ordering and tracking.
        public let sequenceId: Int

        /// The task associated with the job containing the actual work to be performed.
        public var task: EncryptableTask

        /// A Boolean indicating whether the job is a background task.
        public let isBackgroundTask: Bool

        /// The date until which the job is delayed, if applicable.
        public var delayedUntil: Date?

        /// The date and time when the job is scheduled for execution.
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
            task: EncryptableTask,
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

    /// Initializes a new `JobModel` instance with encrypted properties.
    /// - Parameters:
    ///   - id: A unique identifier for the job model.
    ///   - props: The unwrapped properties of the job model to be encrypted.
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
        guard let decrypted = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionFailed
        }
        return try BSONDecoder().decodeData(UnwrappedProps.self, from: decrypted)
    }

    /// Asynchronously updates the properties of the model with new encrypted data.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - props: The new unwrapped properties to be encrypted and stored.
    /// - Returns: The updated decrypted properties.
    /// - Throws: An error if encryption fails.
    public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps? {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return try await decryptProps(symmetricKey: symmetricKey)
    }

    /// Creates a decrypted model of the specified type from the encrypted job data.
    /// - Parameters:
    ///   - of: The type of the model to create, which must conform to `Sendable` and `Codable`.
    ///   - symmetricKey: The symmetric key used for decryption.
    /// - Returns: An instance of the specified type containing the decrypted job properties.
    /// - Throws: An error if decryption fails or if the properties cannot be cast to the specified type.
    public func makeDecryptedModel<T: Sendable & Codable>(of _: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw Errors.propsError
        }
        return Job(
            id: id,
            sequenceId: props.sequenceId,
            isBackgroundTask: props.isBackgroundTask,
            task: props.task,
            scheduledAt: props.scheduledAt,
            attempts: props.attempts
        ) as! T
    }

    /// Private error types for internal use within the JobModel.
    private enum Errors: Error {
        case propsError
    }
}

//
//  TaskProcessor+Helpers.swift
//  post-quantum-solace
//
//  Created by Cole M on 4/8/25.
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

import Foundation
import Crypto
import BSON
import DoubleRatchetKit
import SessionModels

/// Extension providing cache management and model creation capabilities for the TaskProcessor.
/// This extension handles the creation and management of communication models, message models,
/// and job models used throughout the cryptographic session lifecycle.
extension TaskProcessor {
    
    /// Creates a new communication model for a given recipient group and type.
    ///
    /// This method initializes a new `BaseCommunication` object with encrypted properties
    /// that can be used for secure messaging between participants. The communication model
    /// serves as the foundation for message persistence and metadata management.
    ///
    /// ## Security Considerations
    /// - All communication metadata is encrypted using the provided symmetric key
    /// - The communication ID is generated as a cryptographically secure UUID
    /// - Blocked members list is initialized empty and can be populated later
    ///
    /// ## Usage Example
    /// ```swift
    /// let communication = try await taskProcessor.createCommunicationModel(
    ///     recipients: ["user1", "user2"],
    ///     communicationType: .personalMessage,
    ///     metadata: ["admin": "user1"],
    ///     symmetricKey: sessionKey
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - recipients: A set of user identifiers that are part of this communication.
    ///                 Each identifier should be a valid secret name.
    ///   - communicationType: The type of communication (e.g., personal, nickname, channel).
    ///                        Determines how messages are routed and processed.
    ///   - metadata: Additional communication metadata stored as a BSON document.
    ///               This data is encrypted and can include admin info, settings, etc.
    ///   - symmetricKey: The key used to encrypt communication data. Must be the same
    ///                   key used for all operations within this session.
    /// - Returns: A new `BaseCommunication` object ready to be stored or used.
    /// - Throws: `CryptoError` if encryption fails, `BSONError` if metadata encoding fails.
    func createCommunicationModel(
        recipients: Set<String>,
        communicationType: MessageRecipient,
        metadata: Document,
        symmetricKey: SymmetricKey
    ) async throws -> BaseCommunication {
        return try BaseCommunication(
            id: UUID(),
            props: .init(
                messageCount: 0,
                members: recipients,
                metadata: metadata,
                blockedMembers: [],
                communicationType: communicationType
            ),
            symmetricKey: symmetricKey
        )
    }
    
    /// Creates a message model from a received and decrypted message.
    ///
    /// This function updates the message count for the communication and creates a persistable
    /// message model for storage or dispatch to the user interface. The message is associated
    /// with the sender's identity and includes all necessary metadata for proper routing.
    ///
    /// ## Message Processing Flow
    /// 1. Validates sender identity and session context
    /// 2. Increments communication message count
    /// 3. Creates encrypted message model with sender metadata
    /// 4. Updates communication properties in cache
    /// 5. Returns the message model for further processing
    ///
    /// ## Security Considerations
    /// - Message content is encrypted using session symmetric key
    /// - Sender identity is validated against session context
    /// - Message sequence numbers are managed to prevent replay attacks
    /// - All metadata is encrypted before persistence
    ///
    /// - Parameters:
    ///   - decodedMessage: The parsed and decrypted message contents containing the actual
    ///                     message data, recipient info, and metadata.
    ///   - inboundTask: Metadata about the inbound message, including shared IDs and
    ///                  transport information.
    ///   - senderSecretName: Identifier for the sender, used for message attribution.
    ///   - senderDeviceId: The device UUID of the sender, used for multi-device support.
    ///   - session: The active session that received the message, provides context and keys.
    ///   - communication: The associated communication model this message belongs to.
    ///   - sessionIdentity: Identity model for the sender used to extract session context.
    /// - Returns: An `EncryptedMessage` object ready for persistence or processing.
    /// - Throws: `JobProcessorErrors.missingIdentity` if sender identity cannot be resolved,
    ///           `PQSSession.SessionErrors.propsError` if communication properties cannot be decrypted.
    func createInboundMessageModel(
        decodedMessage: CryptoMessage,
        inboundTask: InboundTaskMessage,
        senderSecretName: String,
        senderDeviceId: UUID,
        session: PQSSession,
        communication: BaseCommunication,
        sessionIdentity: SessionIdentity
    ) async throws -> EncryptedMessage {
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        
        guard let props = await sessionIdentity.props(symmetricKey: symmetricKey) else {
            throw JobProcessorErrors.missingIdentity
        }
        
        guard let communicationProps = await communication.props(symmetricKey: symmetricKey) else {
            throw PQSSession.SessionErrors.propsError
        }
        
        let newMessageCount = communicationProps.messageCount + 1
        let messageId = UUID()
        let messageModel = try EncryptedMessage(
            id: messageId,
            communicationId: communication.id,
            sessionContextId: props.sessionContextId,
            sharedId: inboundTask.sharedMessageId,
            sequenceNumber: newMessageCount,
            props: .init(
                id: messageId,
                base: communication,
                sentDate: decodedMessage.sentDate,
                deliveryState: .received,
                message: decodedMessage,
                senderSecretName: senderSecretName,
                senderDeviceId: senderDeviceId
            ),
            symmetricKey: symmetricKey
        )
        
        var newProps = communicationProps
        newProps.messageCount = newMessageCount
        _ = try await communication.updateProps(symmetricKey: symmetricKey, props: newProps)
        try await session.cache?.updateCommunication(communication)
        
        return messageModel
    }
    
    /// Creates a new outbound message model ready for encryption and persistence.
    ///
    /// This method prepares an outbound message for transmission by creating an encrypted
    /// message model with the current session context and sender information. The message
    /// is marked as "sending" until delivery confirmation is received.
    ///
    /// ## Message Creation Flow
    /// 1. Validates session context and sender information
    /// 2. Creates message model with current timestamp and sender metadata
    /// 3. Optionally updates communication properties if requested
    /// 4. Persists the message model to cache
    /// 5. Notifies delegates of communication updates
    ///
    /// ## Security Considerations
    /// - Message content is encrypted using session symmetric key
    /// - Sender information is validated against session context
    /// - Message IDs are cryptographically secure UUIDs
    /// - All metadata is encrypted before persistence
    ///
    /// ## Usage Example
    /// ```swift
    /// let messageModel = try await taskProcessor.createOutboundMessageModel(
    ///     message: cryptoMessage,
    ///     communication: communication,
    ///     session: session,
    ///     symmetricKey: sessionKey,
    ///     members: ["user1", "user2"],
    ///     sharedId: "shared-message-id",
    ///     shouldUpdateCommunication: true
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - message: The plaintext message contents containing the actual message data
    ///              and recipient information.
    ///   - communication: The `BaseCommunication` model for the conversation this
    ///                    message belongs to.
    ///   - session: The session used to retrieve sender context and validate permissions.
    ///   - symmetricKey: Key used to encrypt the message model and its metadata.
    ///   - members: List of communication participants for delegate notifications.
    ///   - sharedId: Shared message identifier used to group related messages.
    ///   - shouldUpdateCommunication: If true, updates and persists the communication props
    ///                                and notifies delegates of changes.
    /// - Returns: A persistable `EncryptedMessage` object ready for transmission.
    /// - Throws: `PQSSession.SessionErrors.sessionNotInitialized` if session context is missing,
    ///           `PQSSession.SessionErrors.propsError` if communication properties cannot be decrypted,
    ///           `PQSSession.SessionErrors.databaseNotInitialized` if cache is unavailable.
    func createOutboundMessageModel(
        message: CryptoMessage,
        communication: BaseCommunication,
        session: PQSSession,
        symmetricKey: SymmetricKey,
        members: Set<String>,
        sharedId: String,
        shouldUpdateCommunication: Bool = false
    ) async throws -> EncryptedMessage {
        guard let sessionContext = await session.sessionContext else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        
        let sessionUser = sessionContext.sessionUser
        
        guard let communicationProps = await communication.props(symmetricKey: symmetricKey) else {
            throw PQSSession.SessionErrors.propsError
        }
        let messageId = UUID()
        let messageModel = try EncryptedMessage(
            id: messageId,
            communicationId: communication.id,
            sessionContextId: sessionContext.sessionContextId,
            sharedId: sharedId,
            sequenceNumber: communicationProps.messageCount,
            props: .init(
                id: messageId,
                base: communication,
                sentDate: Date(),
                deliveryState: .sending,
                message: message,
                senderSecretName: sessionUser.secretName,
                senderDeviceId: sessionUser.deviceId
            ),
            symmetricKey: symmetricKey
        )
        
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        
        if shouldUpdateCommunication {
            try await cache.updateCommunication(communication)
            await session.receiverDelegate?.updatedCommunication(communication, members: members)
        }
        
        try await cache.createMessage(messageModel, symmetricKey: symmetricKey)
        return messageModel
    }
    
    /// Creates a job model to be scheduled for processing by the task consumer.
    ///
    /// This method prepares a job for execution by creating an encrypted job model with
    /// sequence information and task metadata. The job is assigned a unique sequence ID
    /// to maintain proper execution order.
    ///
    /// ## Job Creation Flow
    /// 1. Generates unique sequence ID for job ordering
    /// 2. Encrypts task data using session symmetric key
    /// 3. Creates job model with scheduling and priority information
    /// 4. Returns job model ready for queue insertion
    ///
    /// ## Security Considerations
    /// - Job data is encrypted using session symmetric key
    /// - Sequence IDs prevent job reordering attacks
    /// - Task priority information is preserved for proper scheduling
    ///
    /// ## Usage Example
    /// ```swift
    /// let job = try taskProcessor.createJobModel(
    ///     sequenceId: 123,
    ///     task: encryptableTask,
    ///     symmetricKey: sessionKey
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - sequenceId: A unique sequence identifier for job ordering. Must be monotonically
    ///                 increasing to maintain proper execution order.
    ///   - task: The encryptable task to execute, containing the actual work to be performed.
    ///   - symmetricKey: Key used to encrypt job metadata and task data.
    /// - Returns: A `JobModel` suitable for enqueuing in the `AsyncConsumer`.
    /// - Throws: `CryptoError` if encryption fails, `BSONError` if task encoding fails.
    func createJobModel(
        sequenceId: Int,
        task: EncryptableTask,
        symmetricKey: SymmetricKey
    ) throws -> JobModel {
        try JobModel(
            id: UUID(),
            props: .init(
                sequenceId: sequenceId,
                task: task,
                isBackgroundTask: task.priority == .background,
                scheduledAt: task.scheduledAt,
                attempts: 0
            ),
            symmetricKey: symmetricKey
        )
    }
    
    /// Retrieves a communication model from cache based on the message recipient type.
    ///
    /// This method searches through cached communications to find a matching conversation
    /// based on the recipient type. It handles decryption of communication properties
    /// and validates the communication type match.
    ///
    /// ## Search Process
    /// 1. Fetches all communications from cache
    /// 2. Decrypts each communication's properties
    /// 3. Compares communication type with target type
    /// 4. Returns first matching communication or throws error
    ///
    /// ## Performance Considerations
    /// - This method performs linear search through all communications
    /// - For large numbers of communications, consider implementing indexing
    /// - Each communication requires decryption, which can be expensive
    ///
    /// ## Security Considerations
    /// - Communication properties are decrypted using session symmetric key
    /// - Failed decryption attempts are handled gracefully
    /// - No sensitive data is leaked during the search process
    ///
    /// ## Usage Example
    /// ```swift
    /// let communication = try await taskProcessor.findCommunicationType(
    ///     cache: sessionCache,
    ///     communicationType: .personalMessage,
    ///     session: session
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - cache: The session's cache containing stored communications.
    ///   - communicationType: The recipient type to search for. Must match exactly
    ///                        the type stored in the communication model.
    ///   - session: The current session used for decryption and key management.
    /// - Returns: A matching `BaseCommunication` if found.
    /// - Throws: `PQSSession.SessionErrors.cannotFindCommunication` if no matching
    ///           communication is found, `CryptoError` if decryption fails.
    func findCommunicationType(
        cache: SessionCache,
        communicationType: MessageRecipient,
        session: PQSSession
    ) async throws -> BaseCommunication {
        let communications = try await cache.fetchCommunications()
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        
        guard let foundCommunication = await communications.asyncFirst(where: { model in
            do {
                let decrypted = try await model.makeDecryptedModel(of: Communication.self, symmetricKey: symmetricKey)
                return decrypted.communicationType == communicationType
            } catch {
                return false
            }
        }) else {
            throw PQSSession.SessionErrors.cannotFindCommunication
        }
        
        return foundCommunication
    }
}

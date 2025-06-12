//
//  TaskProcessor+Helpers.swift
//  post-quantum-solace
//
//  Created by Cole M on 4/8/25.
//

import Foundation
import Crypto
import BSON
import DoubleRatchetKit
import SessionModels

extension TaskProcessor {
    
    /// Creates a new communication model for a given recipient group and type.
    ///
    /// - Parameters:
    ///   - recipients: A set of user identifiers that are part of this communication.
    ///   - communicationType: The type of communication (e.g., personal, nickname, channel).
    ///   - metadata: Additional communication metadata stored as a BSON document.
    ///   - symmetricKey: The key used to encrypt communication data.
    /// - Returns: A new `BaseCommunication` object ready to be stored or used.
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
    /// message model for storage or dispatch to the user interface.
    ///
    /// - Parameters:
    ///   - decodedMessage: The parsed and decrypted message contents.
    ///   - inboundTask: Metadata about the inbound message, including shared IDs.
    ///   - sendersSecretName: Identifier for the sender.
    ///   - senderDeviceId: The device UUID of the sender.
    ///   - session: The active session that received the message.
    ///   - communication: The associated communication model this message belongs to.
    ///   - sessionIdentity: Identity model for the sender used to extract session context.
    /// - Returns: An `EncryptedMessage` object for persistence or processing.
    func createInboundMessageModel(
        decodedMessage: CryptoMessage,
        inboundTask: InboundTaskMessage,
        sendersSecretName: String,
        senderDeviceId: UUID,
        session: CryptoSession,
        communication: BaseCommunication,
        sessionIdentity: SessionIdentity
    ) async throws -> EncryptedMessage {
        let symmetricKey = try await session.getDatabaseSymmetricKey()

        guard let props = await sessionIdentity.props(symmetricKey: symmetricKey) else {
            throw JobProcessorErrors.missingIdentity
        }

        guard let communicationProps = await communication.props(symmetricKey: symmetricKey) else {
            throw CryptoSession.SessionErrors.propsError
        }

        let newMessageCount = communicationProps.messageCount + 1

        let messageModel = try EncryptedMessage(
            id: UUID(),
            communicationId: communication.id,
            sessionContextId: props.sessionContextId,
            sharedId: inboundTask.sharedMessageId,
            sequenceNumber: newMessageCount,
            props: .init(
                base: communication,
                sendDate: decodedMessage.sentDate,
                deliveryState: .received,
                message: decodedMessage,
                sendersSecretName: sendersSecretName,
                sendersDeviceId: senderDeviceId
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
    /// - Parameters:
    ///   - message: The plaintext message contents.
    ///   - communication: The `BaseCommunication` model for the conversation.
    ///   - session: The session used to retrieve sender context.
    ///   - symmetricKey: Key used to encrypt the message model.
    ///   - members: List of communication participants.
    ///   - sharedId: Shared message identifier used to group related messages.
    ///   - shouldUpdateCommunication: If true, updates and persists the communication props.
    /// - Returns: A persistable `EncryptedMessage` object.
    func createOutboundMessageModel(
        message: CryptoMessage,
        communication: BaseCommunication,
        session: CryptoSession,
        symmetricKey: SymmetricKey,
        members: Set<String>,
        sharedId: String,
        shouldUpdateCommunication: Bool = false
    ) async throws -> EncryptedMessage {
        guard let sessionContext = await session.sessionContext else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }

        let sessionUser = sessionContext.sessionUser

        guard let communicationProps = await communication.props(symmetricKey: symmetricKey) else {
            throw CryptoSession.SessionErrors.propsError
        }

        let messageModel = try EncryptedMessage(
            id: UUID(),
            communicationId: communication.id,
            sessionContextId: sessionContext.sessionContextId,
            sharedId: sharedId,
            sequenceNumber: communicationProps.messageCount,
            props: .init(
                base: communication,
                sendDate: Date(),
                deliveryState: .sending,
                message: message,
                sendersSecretName: sessionUser.secretName,
                sendersDeviceId: sessionUser.deviceId
            ),
            symmetricKey: symmetricKey
        )

        guard let cache = await session.cache else {
            throw CryptoSession.SessionErrors.databaseNotInitialized
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
    /// - Parameters:
    ///   - sequenceId: A unique sequence identifier for job ordering.
    ///   - task: The encryptable task to execute.
    ///   - symmetricKey: Key used to encrypt job metadata.
    /// - Returns: A `JobModel` suitable for enqueuing in the `AsyncConsumer`.
    func createJobModel(
        sequenceId: Int,
        task: EncrytableTask,
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
    /// - Parameters:
    ///   - cache: The session's cache containing stored communications.
    ///   - communicationType: The recipient type to search for.
    ///   - session: The current session used for decryption.
    /// - Returns: A matching `BaseCommunication` if found.
    func findCommunicationType(
        cache: SessionCache,
        communicationType: MessageRecipient,
        session: CryptoSession
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
            throw CryptoSession.SessionErrors.cannotFindCommunication
        }

        return foundCommunication
    }
}

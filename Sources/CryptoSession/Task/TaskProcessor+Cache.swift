//
//  TaskProcessor+Cache.swift
//  crypto-session
//
//  Created by Cole M on 4/8/25.
//
import Foundation
import Crypto
import BSON
import DoubleRatchetKit
import SessionModels

extension TaskProcessor {
    
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
                communicationType: communicationType),
            symmetricKey: symmetricKey)
    }
    
    
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
            symmetricKey: symmetricKey)
        
        var newProps = communicationProps
        newProps.messageCount = newMessageCount
        _ = try await communication.updateProps(symmetricKey: symmetricKey, props: newProps)
        try await session.cache?.updateCommunication(communication)
        return messageModel
    }
    
    /// Called on Message Save
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
            symmetricKey: symmetricKey)
        
        guard let cache = await session.cache else {
            throw CryptoSession.SessionErrors.databaseNotInitialized
        }
        if shouldUpdateCommunication {
            do {
                try await cache.updateCommunication(communication)
                await session.receiverDelegate?.updatedCommunication(communication, members: members)
            } catch {
                throw error
            }
        }
        try await cache.createMessage(messageModel, symmetricKey: symmetricKey)
        return messageModel
    }
    
    func createJobModel(
        sequenceId: Int,
        task: EncrytableTask,
        symmetricKey: SymmetricKey
    ) throws -> JobModel {
        try JobModel(
            id: UUID(),
            props:
                    .init(
                        sequenceId: sequenceId,
                        task: task,
                        isBackgroundTask: task.priority == .background ? true : false,
                        scheduledAt: task.scheduledAt,
                        attempts: 0
                    ),
            symmetricKey: symmetricKey)
    }
    
    
    public func findCommunicationType(
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

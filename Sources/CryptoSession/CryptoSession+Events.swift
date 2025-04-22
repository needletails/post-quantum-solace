//
//  SessionEvents.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import BSON
import DoubleRatchetKit
import NeedleTailCrypto
import NeedleTailLogger
import NeedleTailAsyncSequence
import SessionModels
import SessionEvents
import Crypto


//MARK: CryptoSession Events
extension CryptoSession {
    
    /// Sends a text message to a specified recipient with optional metadata and destruction settings.
    ///
    /// This method constructs a `CryptoMessage` object with the provided parameters and sends it asynchronously.
    /// It performs the following actions:
    /// 1. Creates a `CryptoMessage` instance with the specified message type, flags, recipient, text, and metadata.
    /// 2. Sends the message using the `processWrite` method of the `CryptoSession`.
    ///
    /// - Parameters:
    ///   - messageType: The type of the message being sent. This determines how the message is processed and displayed.
    ///   - messageFlag: Flags that provide additional information about the message, such as whether it is urgent or requires acknowledgment.
    ///   - recipient: The recipient of the message, specified as a `MessageRecipient` object. This can include user identifiers or other recipient details.
    ///   - text: The text content of the message. This is an optional parameter and defaults to an empty string if not provided.
    ///   - metadata: A dictionary containing additional metadata associated with the message. This can include information such as timestamps, message IDs, or other relevant data.
    ///   - pushType: The type of push notification to be sent along with the message. This determines how the recipient is notified of the message.
    ///   - destructionTime: An optional time interval after which the message should be destroyed. If provided, the message will be deleted after this duration. Defaults to `nil` if not specified.
    ///
    /// - Throws:
    ///   - Any errors that may occur during the message creation or sending process, such as encryption errors or network issues.
    ///
    /// - Important: This method is asynchronous and should be awaited. Ensure that the session is properly initialized before calling this method.
    public func writeTextMessage(
        recipient: MessageRecipient,
        text: String = "",
        transportInfo: Data? = nil,
        metadata: Document,
        destructionTime: TimeInterval? = nil
    ) async throws {
        do {
            let message = CryptoMessage(
                text: text,
                metadata: metadata,
                recipient: recipient,
                transportInfo: transportInfo,
                sentDate: Date(),
                destructionTime: destructionTime)
            
            try await processWrite(message: message, session: CryptoSession.shared)
        } catch {
            self.logger.log(level: .error, message: "\(error)")
            throw error
        }
    }
    
    //MARK: Inbound
    public func receiveMessage(
        message: SignedRatchetMessage,
        sender: String,
        deviceId: UUID,
        messageId: String
    ) async throws {
        let message = InboundTaskMessage(
            message: message,
            senderSecretName: sender,
            senderDeviceId: deviceId,
            sharedMessageId: messageId
        )
        try await taskProcessor.inboundTask(
            message,
            session: CryptoSession.shared)
    }
    
    //MARK: Outbound
    /// This method will loop through each targets user device configuration and send 1 DoubleRatcheted message for each device per target.
    func processWrite(
        message: CryptoMessage,
        session: CryptoSession
    ) async throws {
        guard let sessionContext = await session.sessionContext else {
            throw SessionErrors.sessionNotInitialized
        }
        guard let cache = await session.cache else {
            throw SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        let mySecretName = sessionContext.sessionUser.secretName
        
        let shouldPersist = sessionDelegate?.shouldPersist(transportInfo: message.transportInfo) == false ? false : true
        
        try await taskProcessor.outboundTask(
            message: message,
            cache: cache,
            symmetricKey: symmetricKey,
            session: session,
            sender: mySecretName,
            type: message.recipient,
            shouldPersist: shouldPersist,
            logger: logger)
    }
}


//MARK: CryptoSession SessionEvents Protocol Conformation
extension CryptoSession: SessionEvents {
    
    
    private func requireAllSessionParameters() async throws -> (sessionContext: SessionContext,
                                                                cache: CryptoSessionStore,
                                                                transportDelegate: SessionTransport,
                                                                receiverDelegate: EventReceiver,
                                                                sessionDelegate: CryptoSessionDelegate,
                                                                symmetricKey: SymmetricKey) {
        guard let sessionContext = await self.sessionContext else {
            throw SessionErrors.sessionNotInitialized
        }
        guard let cache = self.cache else {
            throw SessionErrors.databaseNotInitialized
        }
        guard let transportDelegate = self.transportDelegate else {
            throw SessionErrors.transportNotInitialized
        }
        guard let receiverDelegate = self.receiverDelegate else {
            throw SessionErrors.receiverDelegateNotSet
        }
        guard let sessionDelegate = self.sessionDelegate else {
            throw SessionErrors.sessionDelegateNotSet
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        
        return (sessionContext, cache, transportDelegate, receiverDelegate, sessionDelegate, symmetricKey)
    }
    
    private func requireSessionParametersWithoutTransportDelegate() async throws -> (sessionContext: SessionContext,
                                                                                     cache: CryptoSessionStore,
                                                                                     receiverDelegate: EventReceiver,
                                                                                     sessionDelegate: CryptoSessionDelegate,
                                                                                     symmetricKey: SymmetricKey) {
        guard let sessionContext = await self.sessionContext else {
            throw SessionErrors.sessionNotInitialized
        }
        guard let cache = self.cache else {
            throw SessionErrors.databaseNotInitialized
        }
        guard let receiverDelegate = self.receiverDelegate else {
            throw SessionErrors.receiverDelegateNotSet
        }
        guard let sessionDelegate = self.sessionDelegate else {
            throw SessionErrors.sessionDelegateNotSet
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        
        return (sessionContext, cache, receiverDelegate, sessionDelegate, symmetricKey)
    }
    
    public func addContacts(_ infos: [SharedContactInfo]) async throws {
        let params = try await requireAllSessionParameters()
        
        if let eventDelegate {
            try await eventDelegate.addContacts(
                infos,
                sessionContext: params.sessionContext,
                cache: params.cache,
                transport: params.transportDelegate,
                receiver: params.receiverDelegate,
                sessionDelegate: params.sessionDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger)
        } else {
            try await addContacts(
                infos,
                sessionContext: params.sessionContext,
                cache: params.cache,
                transport: params.transportDelegate,
                receiver: params.receiverDelegate,
                sessionDelegate: params.sessionDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger)
        }
    }
    
    public func updateOrCreateContact(
        secretName: String,
        metadata: Document = [:],
        requestFriendship: Bool
    ) async throws -> ContactModel {
        let params = try await requireAllSessionParameters()
        
        if let eventDelegate {
            return try await eventDelegate.updateOrCreateContact(
                secretName: secretName,
                metadata: metadata,
                requestFriendship: requestFriendship,
                sessionContext: params.sessionContext,
                cache: params.cache,
                transport: params.transportDelegate,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger)
        } else {
            return try await updateOrCreateContact(
                secretName: secretName,
                metadata: metadata,
                requestFriendship: requestFriendship,
                sessionContext: params.sessionContext,
                cache: params.cache,
                transport: params.transportDelegate,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger)
        }
    }
    
    public func sendCommunicationSynchronization(contact secretName: String) async throws {
        let params = try await requireSessionParametersWithoutTransportDelegate()
        
        if let eventDelegate {
            return try await eventDelegate.sendCommunicationSynchronization(
                contact: secretName,
                sessionContext: params.sessionContext,
                sessionDelegate: params.sessionDelegate,
                cache: params.cache,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger)
        } else {
            return try await sendCommunicationSynchronization(
                contact: secretName,
                sessionContext: params.sessionContext,
                sessionDelegate: params.sessionDelegate,
                cache: params.cache,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger)
        }
    }
    
    public func requestFriendshipStateChange(
        state: FriendshipMetadata.State,
        contact: Contact
    ) async throws {
        let params = try await requireSessionParametersWithoutTransportDelegate()
        
        if let eventDelegate {
            return try await eventDelegate.requestFriendshipStateChange(
                state: state,
                contact: contact,
                cache: params.cache,
                receiver: params.receiverDelegate,
                sessionDelegate: params.sessionDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger)
        } else {
            return try await requestFriendshipStateChange(
                state: state,
                contact: contact,
                cache: params.cache,
                receiver: params.receiverDelegate,
                sessionDelegate: params.sessionDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger)
        }
    }
    
    public func updateMessageDeliveryState(_
                                           message: EncryptedMessage,
                                           deliveryState: DeliveryState,
                                           messageRecipient: MessageRecipient,
                                           allowExternalUpdate: Bool = false
    ) async throws {
        let params = try await requireSessionParametersWithoutTransportDelegate()
        
        if let eventDelegate {
            return try await eventDelegate.updateMessageDeliveryState(
                message,
                deliveryState: deliveryState,
                messageRecipient: messageRecipient,
                allowExternalUpdate: allowExternalUpdate,
                sessionDelegate: params.sessionDelegate,
                cache: params.cache,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey)
        } else {
            return try await updateMessageDeliveryState(
                message,
                deliveryState: deliveryState,
                messageRecipient: messageRecipient,
                allowExternalUpdate: allowExternalUpdate,
                sessionDelegate: params.sessionDelegate,
                cache: params.cache,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey)
        }
    }
    
    public func sendContactCreatedAcknowledgment(recipient secretName: String) async throws {
        guard let sessionDelegate = sessionDelegate else { throw SessionErrors.sessionDelegateNotSet }
        if let eventDelegate {
            return try await eventDelegate.sendContactCreatedAcknowledgment(
                recipient: secretName,
                sessionDelegate: sessionDelegate,
                logger: logger)
        } else {
            return try await sendContactCreatedAcknowledgment(
                recipient: secretName,
                sessionDelegate: sessionDelegate,
                logger: logger)
        }
    }
    
    public func requestMetadata(from secretName: String) async throws {
        guard let sessionDelegate = sessionDelegate else { throw SessionErrors.sessionDelegateNotSet }
        if let eventDelegate {
            return try await eventDelegate.requestMetadata(
                from: secretName,
                sessionDelegate: sessionDelegate,
                logger: logger)
        } else {
            return try await requestMetadata(
                from: secretName,
                sessionDelegate: sessionDelegate,
                logger: logger)
        }
    }
    
    public func requestMyMetadata() async throws {
        guard let sessionDelegate = sessionDelegate else { throw SessionErrors.sessionDelegateNotSet }
        if let eventDelegate {
            return try await eventDelegate.requestMyMetadata(
                sessionDelegate: sessionDelegate,
                logger: logger)
        } else {
            return try await requestMyMetadata(
                sessionDelegate: sessionDelegate,
                logger: logger)
        }
    }
    
    public func editCurrentMessage(_ message: EncryptedMessage, newText: String) async throws {
        guard let cache = cache else { throw SessionErrors.databaseNotInitialized }
        guard let receiverDelegate = receiverDelegate else { throw SessionErrors.receiverDelegateNotSet }
        guard let sessionDelegate = sessionDelegate else { throw SessionErrors.sessionDelegateNotSet }
        let symmetricKey = try await getDatabaseSymmetricKey()
        
        if let eventDelegate {
            return try await eventDelegate.editCurrentMessage(
                message,
                newText: newText,
                sessionDelegate: sessionDelegate,
                cache: cache,
                receiver: receiverDelegate,
                symmetricKey: symmetricKey,
                logger: logger)
        } else {
            return try await editCurrentMessage(
                message,
                newText: newText,
                sessionDelegate: sessionDelegate,
                cache: cache,
                receiver: receiverDelegate,
                symmetricKey: symmetricKey,
                logger: logger)
        }
    }
    
    public func findCommunication(for messageRecipient: MessageRecipient) async throws -> BaseCommunication {
        guard let cache = cache else { throw SessionErrors.databaseNotInitialized }
        let symmetricKey = try await getDatabaseSymmetricKey()
        
        if let eventDelegate {
            return try await eventDelegate.findCommunication(
                for: messageRecipient,
                cache: cache,
                symmetricKey: symmetricKey)
        } else {
            return try await findCommunication(
                for: messageRecipient,
                cache: cache,
                symmetricKey: symmetricKey)
        }
    }
}

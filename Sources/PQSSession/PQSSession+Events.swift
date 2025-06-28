//
//  SessionEvents.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import BSON
import NeedleTailAsyncSequence
import SessionModels
import SessionEvents
import Crypto

//MARK: PQSSession Events
extension PQSSession {
    
    /// Sends a text message to a specified recipient with optional metadata and destruction settings.
    ///
    /// This method constructs a `CryptoMessage` object with the provided parameters and sends it asynchronously.
    /// It performs the following actions:
    /// 1. Creates a `CryptoMessage` instance with the specified message type, flags, recipient, text, and metadata.
    /// 2. Sends the message using the `processWrite` method of the `PQSSession`.
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
            if let sessionContext = await sessionContext, sessionContext.lastUserConfiguration.signedOneTimePublicKeys.count <= 10 {
                async let _ = await self.refreshOneTimeKeysTask()
            }
            if let sessionContext = await sessionContext, sessionContext.lastUserConfiguration.signedPQKemOneTimePublicKeys.count <= 10 {
                async let _ = await self.refreshOneTimeKeysTask()
            }
            let message = CryptoMessage(
                text: text,
                metadata: metadata,
                recipient: recipient,
                transportInfo: transportInfo,
                sentDate: Date(),
                destructionTime: destructionTime)
            
            try await processWrite(message: message, session: self)
        } catch {
            self.logger.log(level: .error, message: "\(error)")
            throw error
        }
    }
    
    // MARK: Inbound
    
    /// Receives an inbound message and processes it asynchronously.
    /// - Parameters:
    ///   - message: The signed ratchet message to be received.
    ///   - sender: The identifier of the sender.
    ///   - deviceId: The unique identifier of the sender's device.
    ///   - messageId: The unique identifier for the message.
    /// - Throws: An error if the message processing fails.
    public func receiveMessage(
        message: SignedRatchetMessage,
        sender: String,
        deviceId: UUID,
        messageId: String
    ) async throws {

        //We need to make sure that our remote keys are in sync with local keys before proceeding. We do this if we have less that 10 local keys.
        if let sessionContext = await sessionContext, sessionContext.lastUserConfiguration.signedOneTimePublicKeys.count <= 10 {
            async let _ = await self.refreshOneTimeKeysTask()
        }
        if let sessionContext = await sessionContext, sessionContext.lastUserConfiguration.signedPQKemOneTimePublicKeys.count <= 10 {
            async let _ = await self.refreshOneTimeKeysTask()
        }
        
        let message = InboundTaskMessage(
            message: message,
            senderSecretName: sender,
            senderDeviceId: deviceId,
            sharedMessageId: messageId
        )
        try await taskProcessor.inboundTask(
            message,
            session: self)
    }
    
    // MARK: Outbound
    
    /// Processes the outbound message by sending it to the appropriate target devices.
    /// This method loops through each target's device configuration and sends a DoubleRatcheted message.
    /// - Parameters:
    ///   - message: The cryptographic message to be sent.
    ///   - session: The current cryptographic session.
    /// - Throws: An error if the message processing fails.
    func processWrite(
        message: CryptoMessage,
        session: PQSSession
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

// MARK: - PQSSession SessionEvents Protocol Conformance

extension PQSSession: SessionEvents {
    
    /// Requires all necessary session parameters for processing.
    /// - Returns: A tuple containing all required session parameters.
    /// - Throws: An error if any of the required parameters are not initialized.
    private func requireAllSessionParameters() async throws -> (sessionContext: SessionContext,
                                                                cache: PQSSessionStore,
                                                                transportDelegate: SessionTransport,
                                                                receiverDelegate: EventReceiver,
                                                                sessionDelegate: PQSSessionDelegate,
                                                                symmetricKey: SymmetricKey) {
        guard let sessionContext = await self.sessionContext else {
            throw SessionErrors.sessionNotInitialized
        }
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        guard let transportDelegate else {
            throw SessionErrors.transportNotInitialized
        }
        guard let receiverDelegate else {
            throw SessionErrors.receiverDelegateNotSet
        }
        guard let sessionDelegate else {
            throw SessionErrors.sessionNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        
        return (sessionContext, cache, transportDelegate, receiverDelegate, sessionDelegate, symmetricKey)
    }
    
    /// Requires session parameters excluding the transport delegate.
    /// - Returns: A tuple containing the required session parameters.
    /// - Throws: An error if any of the required parameters are not initialized.
    private func requireSessionParametersWithoutTransportDelegate() async throws -> (sessionContext: SessionContext,
                                                                                     cache: PQSSessionStore,
                                                                                     receiverDelegate: EventReceiver,
                                                                                     sessionDelegate: PQSSessionDelegate,
                                                                                     symmetricKey: SymmetricKey) {
        guard let sessionContext = await self.sessionContext else {
            throw SessionErrors.sessionNotInitialized
        }
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        guard let receiverDelegate else {
            throw SessionErrors.receiverDelegateNotSet
        }
        guard let sessionDelegate else {
            throw SessionErrors.sessionNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        
        return (sessionContext, cache, receiverDelegate, sessionDelegate, symmetricKey)
    }
    
    // MARK: - Contact Management
    
    /// Adds a list of contacts to the session.
    /// - Parameter infos: An array of shared contact information to be added.
    /// - Throws: An error if the addition of contacts fails.
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
    
    /// Updates or creates a contact with the specified secret name and metadata.
    /// - Parameters:
    ///   - secretName: The secret name of the contact to be updated or created.
    ///   - metadata: Additional metadata associated with the contact.
    ///   - requestFriendship: A boolean indicating whether to request friendship.
    /// - Returns: A `ContactModel` representing the updated or created contact.
    /// - Throws: An error if the operation fails.
    public func updateOrCreateContact(
        secretName: String,
        metadata: Document = [:],
        requestFriendship: Bool
    ) async throws -> ContactModel {
        let params = try await requireAllSessionParameters()
        _ = try await refreshIdentities(secretName: secretName, forceRefresh: true)
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
    
    /// Sends a communication synchronization request for the specified contact.
    /// - Parameter secretName: The secret name of the contact to synchronize with.
    /// - Throws: An error if the synchronization request fails.
    public func sendCommunicationSynchronization(contact secretName: String) async throws {
        let params = try await requireSessionParametersWithoutTransportDelegate()
        //On Contact Created attempt to create session identities
        _ = try await refreshIdentities(secretName: secretName, forceRefresh: true)
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
    
    /// Requests a change in the friendship state for a specified contact.
    /// - Parameters:
    ///   - state: The new friendship state to be set.
    ///   - contact: The contact whose friendship state is to be changed.
    /// - Throws: An error if the request fails.
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
    
    /// Updates the delivery state of a specified message.
    /// - Parameters:
    ///   - message: The encrypted message whose delivery state is to be updated.
    ///   - deliveryState: The new delivery state to be set.
    ///   - messageRecipient: The recipient of the message.
    ///   - allowExternalUpdate: A boolean indicating whether to allow external updates.
    /// - Throws: An error if the update fails.
    public func updateMessageDeliveryState(
        _ message: EncryptedMessage,
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
    
    /// Sends an acknowledgment that a contact has been created to the specified recipient.
    /// - Parameter secretName: The secret name of the recipient to acknowledge.
    /// - Throws: An error if the acknowledgment fails.
    public func sendContactCreatedAcknowledgment(recipient secretName: String) async throws {
        guard let sessionDelegate else { throw SessionErrors.sessionNotInitialized }
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
    
    /// Requests metadata from a specified contact.
    /// - Parameter secretName: The secret name of the contact to request metadata from.
    /// - Throws: An error if the request fails.
    public func requestMetadata(from secretName: String) async throws {
        guard let sessionDelegate else { throw SessionErrors.sessionNotInitialized }
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
    
    /// Requests the metadata of the current user.
    /// - Throws: An error if the request fails.
    public func requestMyMetadata() async throws {
        guard let sessionDelegate else { throw SessionErrors.sessionNotInitialized }
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
    
    /// Edits the current message with new text.
    /// - Parameters:
    ///   - message: The encrypted message to be edited.
    ///   - newText: The new text to replace the current message text.
    /// - Throws: An error if the editing fails.
    public func editCurrentMessage(_ message: EncryptedMessage, newText: String) async throws {
        guard let cache = cache else { throw SessionErrors.databaseNotInitialized }
        guard let receiverDelegate else { throw SessionErrors.receiverDelegateNotSet }
        guard let sessionDelegate else { throw SessionErrors.sessionNotInitialized }
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
    
    /// Finds the communication associated with a specified message recipient.
    /// - Parameter messageRecipient: The recipient of the message to find communication for.
    /// - Returns: A `BaseCommunication` object representing the found communication.
    /// - Throws: An error if the communication cannot be found.
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

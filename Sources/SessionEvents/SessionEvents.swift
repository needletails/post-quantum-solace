//
//  SessionEvents.swift
//  crypto-session
//
//  Created by Cole M on 4/19/25.
//
import BSON
import Foundation
import SessionModels
import Crypto
import NeedleTailLogger

enum EventErrors: Error {
    case sessionNotInitialized, databaseNotInitialized, transportNotInitialized, propsError, invalidSecretName, missingMetadata, cannotFindCommunication, cannotFindContact, userIsBlocked
}

public protocol SessionEvents: Sendable {
    func addContacts(_
                            infos: [SharedContactInfo],
                            sessionContext: SessionContext,
                            cache: CryptoSessionStore,
                            transport: SessionTransport,
                            receiver: EventReceiver,
                            sessionDelegate: CryptoSessionDelegate,
                            symmetricKey: SymmetricKey,
                            logger: NeedleTailLogger
    ) async throws
    func updateOrCreateContact(
       secretName: String,
       metadata: Document,
       requestFriendship: Bool,
       sessionContext: SessionContext,
       cache: CryptoSessionStore,
       transport: SessionTransport,
       receiver: EventReceiver,
       symmetricKey: SymmetricKey,
       logger: NeedleTailLogger
   ) async throws -> ContactModel
    func sendCommunicationSynchronization(
        contact secretName: String,
        sessionContext: SessionContext,
        sessionDelegate: CryptoSessionDelegate,
        cache: CryptoSessionStore,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws 
    func requestFriendshipStateChange(
        state: FriendshipMetadata.State,
        contact: Contact,
        cache: CryptoSessionStore,
        receiver: EventReceiver,
        sessionDelegate: CryptoSessionDelegate,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws
    func updateMessageDeliveryState(_
                                    message: EncryptedMessage,
                                    deliveryState: DeliveryState,
                                    messageRecipient: MessageRecipient,
                                    allowExternalUpdate: Bool,
                                    sessionDelegate: CryptoSessionDelegate,
                                    cache: CryptoSessionStore,
                                    receiver: EventReceiver,
                                    symmetricKey: SymmetricKey
    ) async throws
    func sendContactCreatedAcknowledgment(
        recipient secretName: String,
        sessionDelegate: CryptoSessionDelegate,
        logger: NeedleTailLogger
    ) async throws
    func requestMetadata(
        from secretName: String,
        sessionDelegate: CryptoSessionDelegate,
        logger: NeedleTailLogger
    ) async throws
    func requestMyMetadata(
        sessionDelegate: CryptoSessionDelegate,
        logger: NeedleTailLogger
    ) async throws
    func editCurrentMessage(_
                            message: EncryptedMessage,
                            newText: String,
                            sessionDelegate: CryptoSessionDelegate,
                            cache: CryptoSessionStore,
                            receiver: EventReceiver,
                            symmetricKey: SymmetricKey,
                            logger: NeedleTailLogger
    ) async throws
    func findCommunication(
        for messageRecipient: MessageRecipient,
        cache: CryptoSessionStore,
        symmetricKey: SymmetricKey
    ) async throws -> BaseCommunication
}

extension SessionEvents {
    //For Device Contact and Communication Synchronization
    public func addContacts(_
                            infos: [SharedContactInfo],
                            sessionContext: SessionContext,
                            cache: CryptoSessionStore,
                            transport: SessionTransport,
                            receiver: EventReceiver,
                            sessionDelegate: CryptoSessionDelegate,
                            symmetricKey: SymmetricKey,
                            logger: NeedleTailLogger
    ) async throws {
        let mySecretName = sessionContext.sessionUser.secretName
        let contacts = try await cache.fetchContacts()
        
        let filteredInfos = await infos.asyncFilter { info in
            // Check if contacts is not nil and does not contain the secretName
            let containsSecretName = await contacts.asyncContains { contact in
                if let secretName = await contact.props(symmetricKey: symmetricKey)?.secretName {
                    return info.secretName == secretName
                }
                return false
            }
            
            // We want to include `info` only if `containsSecretName` is false
            return !containsSecretName
        }
        
        for info in filteredInfos {
            
            let userConfiguration = try await transport.findConfiguration(for: info.secretName)
            
            let contact = Contact(
                id: UUID(), // Consider using the same UUID for both Contact and ContactModel if they are linked
                secretName: info.secretName,
                configuration: userConfiguration,
                metadata: info.metadata)
            
            let contactModel = try ContactModel(
                id: contact.id, // Use the same UUID
                props: .init(
                    secretName: contact.secretName,
                    configuration: contact.configuration,
                    metadata: contact.metadata),
                symmetricKey: symmetricKey)
            
            try await cache.createContact(contactModel)
            try await receiver.createdContact(contact)
            
            logger.log(level: .debug, message: "Creating Communication Model")
            // Create communication model
            let communicationModel = try await createCommunicationModel(
                recipients: [mySecretName, info.secretName],
                communicationType: .nickname(info.secretName),
                metadata: [:],
                symmetricKey: symmetricKey
            )
            
            guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
                throw EventErrors.propsError
            }
            
            props.sharedId = info.sharedCommunicationId
            
            _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
            try await cache.createCommunication(communicationModel)
            await receiver.updatedCommunication(communicationModel, members: [info.secretName])
            logger.log(level: .debug, message: "Created Communication Model")
            
            try await requestMetadata(
                from: contact.secretName,
                sessionDelegate: sessionDelegate,
                logger: logger)
            
            try await sendCommunicationSynchronization(
                contact: info.secretName,
                sessionContext: sessionContext,
                sessionDelegate: sessionDelegate,
                cache: cache,
                receiver: receiver,
                symmetricKey: symmetricKey,
                logger: logger)
            
        }
        
        try await requestMyMetadata(sessionDelegate: sessionDelegate, logger: logger)
        
        //Schronize other device?
    }
    /// Updates or creates a contact in the local cached database and notifies the client of the changes.
    ///
    /// This method performs the following actions:
    /// 1. Creates a new contact or updates an existing contact in the local cached database.
    /// 2. Notifies the local client that a contact has been created or updated.
    /// 3. Notifies the local client of any changes to the contact's metadata.
    ///
    /// **Important:** After the client is notified of the local contact creation, the method
    /// `requestFriendshipStateChange` must be called to notify the recipient of the friendship request.
    /// This establishes a communication model that allows both parties to communicate with each other.
    ///
    /// - Parameters:
    ///   - secretName: The name of the contact to be added or updated.
    ///   - metadata: A dictionary containing predefined metadata for the contact. This is a base metadata that users can insert metadata into, they are responsible for proper keying and document retieval.
    ///     This can include nicknames and other relevant data. The default value is an empty dictionary.
    ///
    /// - Returns: A `ContactModel` representing the created or updated contact.
    ///
    /// - Throws: An error if the operation fails due to issues such as invalid parameters or database errors.
    public func updateOrCreateContact(
        secretName: String,
        metadata: Document = [:],
        requestFriendship: Bool,
        sessionContext: SessionContext,
        cache: CryptoSessionStore,
        transport: SessionTransport,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws -> ContactModel {
        
        let newContactSecretName = secretName.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        let mySecretName = sessionContext.sessionUser.secretName
        
        guard newContactSecretName != mySecretName else {
            throw EventErrors.invalidSecretName
        }
        
        // Check if the contact already exists
        if let foundContact = try await cache.fetchContacts().asyncFirst(where: { await $0.props(symmetricKey: symmetricKey)?.secretName == newContactSecretName }) {
            guard let props = await foundContact.props(symmetricKey: symmetricKey) else {
                throw EventErrors.propsError
            }
            
            // Simplified metadata handling
            let configuration = props.configuration
            let contactMetadata = metadata.isEmpty ? (props.metadata) : metadata
            
            guard let friendshipMetadata = contactMetadata["friendshipMetadata"] as? Document else { throw EventErrors.missingMetadata }
            
            let updatedProps = try await foundContact.updatePropsMetadata(
                symmetricKey: symmetricKey,
                metadata: friendshipMetadata,
                with: "friendshipMetadata")
            
            try await cache.updateContact(foundContact)
            
            guard let updatedMetadata = updatedProps?.metadata else {
                throw EventErrors.propsError
            }
            
            let updatedContact = Contact(
                id: foundContact.id,
                secretName: newContactSecretName,
                configuration: configuration,
                metadata: updatedMetadata)
            
            try await receiver.updateContact(updatedContact)
            return foundContact
        } else {
            
            let userConfiguration = try await transport.findConfiguration(for: newContactSecretName)
            
            let contact = Contact(
                id: UUID(), // Consider using the same UUID for both Contact and ContactModel if they are linked
                secretName: newContactSecretName,
                configuration: userConfiguration,
                metadata: metadata)
            
            let contactModel = try ContactModel(
                id: contact.id, // Use the same UUID
                props: .init(
                    secretName: contact.secretName,
                    configuration: contact.configuration,
                    metadata: contact.metadata
                ),
                symmetricKey: symmetricKey
            )
            
            try await cache.createContact(contactModel)
            try await receiver.createdContact(contact)
            try await receiver.synchronize(
                contact: contact,
                requestFriendship: requestFriendship)
            
            _ = try await updateOrCreateCommunication(
                mySecretName: mySecretName,
                theirSecretName: newContactSecretName,
                cache: cache,
                receiver: receiver,
                symmetricKey: symmetricKey,
                logger: logger)
            
            return contactModel
        }
    }
    
    //For Contact to Contact Communication Synchronization
    private func updateOrCreateCommunication(
        mySecretName: String,
        theirSecretName: String,
        cache: CryptoSessionStore,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws -> String? {
        
        var communicationModel: BaseCommunication?
        var shouldUpdateCommunication = false
        do {
            communicationModel = try await findCommunicationType(
                cache: cache,
                communicationType: .nickname(theirSecretName),
                symmetricKey: symmetricKey)
            logger.log(level: .debug, message: "Found Communication Model")
            shouldUpdateCommunication = true
        } catch {
            logger.log(level: .debug, message: "Creating Communication Model")
            // Create communication model
            communicationModel = try await createCommunicationModel(
                recipients: [mySecretName, theirSecretName],
                communicationType: .nickname(theirSecretName),
                metadata: [:],
                symmetricKey: symmetricKey
            )
        }
        
        guard let communicationModel else {
            throw EventErrors.cannotFindCommunication
        }
        guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
            throw EventErrors.propsError
        }
        
        if props.sharedId == nil {
            
            let sharedIdentifier = UUID()
            props.sharedId = sharedIdentifier
            
            _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
                await receiver.updatedCommunication(communicationModel, members: [theirSecretName])
                logger.log(level: .debug, message: "Updated Communication Model")
            } else {
                try await cache.createCommunication(communicationModel)
                await receiver.updatedCommunication(communicationModel, members: [theirSecretName])
                logger.log(level: .debug, message: "Created Communication Model")
            }
            return sharedIdentifier.uuidString
        } else {
            logger.log(level: .debug, message: "Shared Id already exists")
            return nil
        }
    }
    
    //For Contact to Contact Communication Synchronization
    public func sendCommunicationSynchronization(
        contact secretName: String,
        sessionContext: SessionContext,
        sessionDelegate: CryptoSessionDelegate,
        cache: CryptoSessionStore,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws {
        logger.log(level: .debug, message: "Sending communication synchronization to \(secretName)")
        let mySecretName = sessionContext.sessionUser.secretName
        
        guard secretName != mySecretName else {
            throw EventErrors.invalidSecretName
        }
        
        guard let sharedIdentifier = try await updateOrCreateCommunication(
            mySecretName: mySecretName,
            theirSecretName: secretName,
            cache: cache,
            receiver: receiver,
            symmetricKey: symmetricKey,
            logger: logger) else { return }
        
        try await sessionDelegate.communicationSynchonization(recipient: .nickname(secretName), sharedIdentifier: sharedIdentifier)
        logger.log(level: .debug, message: "Sent communication synchronization")
    }
    
    /// Requests a change in the friendship state for a specified contact.
    ///
    /// This method allows the user to request a change in the friendship state with a contact.
    /// It performs the following actions:
    /// 1. Validates the session and cache state.
    /// 2. Fetches the specified contact from the local cache.
    /// 3. Retrieves the symmetric key for encryption.
    /// 4. Updates the friendship metadata based on the requested state.
    /// 5. Notifies the receiver delegate of the metadata change.
    /// 6. Updates the contact in the local cache.
    /// 7. Sends a message to the recipient regarding the friendship state change.
    ///
    /// - Parameters:
    ///   - state: The desired friendship state to be set for the contact. This can be one of the following:
    ///     - `.pending`: Indicates that a friend request should be revoked.
    ///     - `.requested`: Indicates that a friend request should be sent.
    ///     - `.accepted`: Indicates that a friend request should be accepted.
    ///     - `.rejected`: Indicates that a friend request should be rejected.
    ///     - `.blocked`: Indicates that the contact should be blocked.
    ///     - `.unblock`: Indicates that the contact should be unblocked.
    ///   - contact: The `Contact` object representing the contact whose friendship state is being changed.
    ///
    /// - Throws:
    ///   - `EventErrors.databaseNotInitialized`: If the cache is not initialized.
    ///   - `EventErrors.sessionNotInitialized`: If the session context is not initialized.
    ///   - `EventErrors.cannotFindContact`: If the specified contact cannot be found in the cache.
    ///   - `EventErrors.propsError`: If there is an error updating the contact's properties.
    ///   - Any other errors that may occur during the process, such as encoding errors or network issues.
    ///
    /// - Important: Ensure that the session and cache are properly initialized before calling this method.
    ///
    /// - Note: This method is asynchronous and should be awaited.
    public func requestFriendshipStateChange(
        state: FriendshipMetadata.State,
        contact: Contact,
        cache: CryptoSessionStore,
        receiver: EventReceiver,
        sessionDelegate: CryptoSessionDelegate,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws {
        logger.log(level: .info, message: "Requesting friendship state change for \(contact.secretName) to state \(state).")
        
        guard let foundContact = try await cache.fetchContacts().asyncFirst(where: { await $0.props(symmetricKey: symmetricKey)?.secretName == contact.secretName }) else { throw EventErrors.cannotFindContact }
        
        var currentMetadata: FriendshipMetadata?
        
        if let friendshipDocument = contact.metadata["friendshipMetadata"] as? Document, !friendshipDocument.isEmpty {
            currentMetadata = try contact.metadata.decode(forKey: "friendshipMetadata")
        }
        if currentMetadata == nil {
            currentMetadata = FriendshipMetadata()
        }
        
        if currentMetadata?.myState == .blocked {
            throw EventErrors.userIsBlocked
        }
        
        guard var currentMetadata = currentMetadata else { return }
        
        //Do not allow state changes that are not different, i.e. my state is .accepted cannot acceptFriendRequest() again
        if currentMetadata.ourState == .accepted && state == .accepted { return }
        if currentMetadata.myState == .rejected { return }
        switch state {
        case .pending:
            currentMetadata.synchronizePendingState()
        case .requested:
            currentMetadata.synchronizeRequestedState()
        case .accepted:
            currentMetadata.synchronizeAcceptedState()
        case .blocked, .blockedUser:
            currentMetadata.synchronizeBlockState(receivedBlock: false)
        case .unblock:
            currentMetadata.synchronizeAcceptedState()
        case .rejectedRequest, .friendshipRejected, .rejected:
            currentMetadata.rejectFriendRequest()
        }
        
        let metadata = try BSONEncoder().encode(currentMetadata)
        let updatedProps = try await foundContact.updatePropsMetadata(
            symmetricKey: symmetricKey,
            metadata: metadata,
            with: "friendshipMetadata")
        
        try await cache.updateContact(foundContact)
        
        guard let updatedMetadata = updatedProps?.metadata else {
            throw EventErrors.propsError
        }
        
        let updatedContact = Contact(
            id: contact.id,
            secretName: contact.secretName,
            configuration: contact.configuration,
            metadata: updatedMetadata)
        
        try await receiver.updateContact(updatedContact)
        
        func dataFromBool(_ value: Bool) -> Data {
            // Convert Bool to UInt8 (0 for false, 1 for true)
            let byte: UInt8 = value ? 1 : 0
            // Create Data from the byte
            return Data([byte])
        }
        
        var blockUnblockData: Data?
        if currentMetadata.theirState == .blocked || currentMetadata.theirState == .blockedUser {
            blockUnblockData = dataFromBool(true)
        }
        
        if currentMetadata.theirState == .unblock {
            blockUnblockData = dataFromBool(false)
        }
        
        //Transport
        try await sessionDelegate.blockUnblock(recipient: .nickname(contact.secretName), data: blockUnblockData, metadata: ["friendshipMetadata": metadata], myState: currentMetadata.myState)
        logger.log(level: .info, message: "Sent Friendship State Change Request")
    }
    
    
    
    public func updateMessageDeliveryState(_
                                           message: EncryptedMessage,
                                           deliveryState: DeliveryState,
                                           messageRecipient: MessageRecipient,
                                           allowExternalUpdate: Bool = false,
                                           sessionDelegate: CryptoSessionDelegate,
                                           cache: CryptoSessionStore,
                                           receiver: EventReceiver,
                                           symmetricKey: SymmetricKey
    ) async throws {
        guard var props = await message.props(symmetricKey: symmetricKey) else { throw EventErrors.propsError }
        props.deliveryState = deliveryState
        let updatedMessage = try await message.updateMessage(with: props, symmetricKey: symmetricKey)
        try await cache.updateMessage(updatedMessage, symmetricKey: symmetricKey)
        await receiver.updatedMessage(updatedMessage)
        if allowExternalUpdate {
            let metadata = DeliveryStateMetadata(state: props.deliveryState, sharedId: updatedMessage.sharedId)
            let encodedDeliveryState = try BSONEncoder().encode(metadata)
            try await sessionDelegate.deliveryStateChanged(recipient: messageRecipient, metadata: encodedDeliveryState)
        }
    }
    
    public func sendContactCreatedAcknowledgment(
        recipient secretName: String,
        sessionDelegate: CryptoSessionDelegate,
        logger: NeedleTailLogger
    ) async throws {
        logger.log(level: .debug, message: "Sending Contact Created Acknowledgment")
        try await sessionDelegate.contactCreated(recipient: .nickname(secretName))
        logger.log(level: .debug, message: "Sent Contact Created Acknowledgment")
    }
    
    public func requestMetadata(
        from secretName: String,
        sessionDelegate: CryptoSessionDelegate,
        logger: NeedleTailLogger
    ) async throws {
        logger.log(level: .debug, message: "Requesting metadata from \(secretName)")
        try await sessionDelegate.requestMetadata(recipient: .nickname(secretName))
        logger.log(level: .debug, message: "Requested metadata from \(secretName)")
    }
    
    public func requestMyMetadata(
        sessionDelegate: CryptoSessionDelegate,
        logger: NeedleTailLogger
    ) async throws {
        logger.log(level: .debug, message: "Requesting my metadata")
        try await sessionDelegate.requestMetadata(recipient: .personalMessage)
        logger.log(level: .debug, message: "Requested my metadata")
    }
    
    public func editCurrentMessage(_
                                   message: EncryptedMessage,
                                   newText: String,
                                   sessionDelegate: CryptoSessionDelegate,
                                   cache: CryptoSessionStore,
                                   receiver: EventReceiver,
                                   symmetricKey: SymmetricKey,
                                   logger: NeedleTailLogger
    ) async throws {
        
        guard var props = await message.props(symmetricKey: symmetricKey) else { return }
        
        props.message.text = newText
        _ = try await message.updateProps(symmetricKey: symmetricKey, props: props)
        let updatedMessage = try await message.updateMessage(with: props, symmetricKey: symmetricKey)
        
        try await cache.updateMessage(updatedMessage, symmetricKey: symmetricKey)
        await receiver.updatedMessage(updatedMessage)
        
        let editMetadata = EditMessageMetadata(value: newText, sharedId: message.sharedId, sender: "")
        let metadata = try BSONEncoder().encode(editMetadata)
        try await sessionDelegate.editMessage(recipient: props.message.recipient, metadata: metadata)
    }
    
    public func findCommunication(
        for messageRecipient: MessageRecipient,
        cache: CryptoSessionStore,
        symmetricKey: SymmetricKey
    ) async throws -> BaseCommunication {
        return try await findCommunicationType(
            cache: cache,
            communicationType: messageRecipient,
            symmetricKey: symmetricKey)
    }
    
    public func findCommunicationType(
        cache: CryptoSessionStore,
        communicationType: MessageRecipient,
        symmetricKey: SymmetricKey
    ) async throws -> BaseCommunication {
        let communications = try await cache.fetchCommunications()
        guard let foundCommunication = await communications.asyncFirst(where: { model in
            do {
                let decrypted = try await model.makeDecryptedModel(of: Communication.self, symmetricKey: symmetricKey)
                return decrypted.communicationType == communicationType
            } catch {
                return false
            }
        }) else {
            throw EventErrors.cannotFindCommunication
        }
        
        return foundCommunication
    }
    
    public func createCommunicationModel(
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
}

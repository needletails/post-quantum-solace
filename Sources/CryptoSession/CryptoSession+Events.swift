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
@preconcurrency import Crypto
/*
 # Messaging Data Structure
 
 ## Communication Sessions
 
 A **Communication Session** is a protocol that establishes a common framework for metadata associated with various communication types. This protocol defines the essential properties and behaviors that all communication sessions must implement, ensuring consistency across different messaging formats. Each specific communication type (e.g., private messages, channels, personal notes) will extend this protocol to include its own unique metadata relevant to that type of communication.
 
 ---
 
 ## Private Message
 
 A **Private Message** is a specific type of communication session that conforms to the Communication Session protocol. In a Private Message session, two users can exchange messages while sharing a common set of metadata, such as timestamps and message IDs. However, each user may have unique metadata that governs their interaction, such as blocking or muting the other user. While both users are aware of each other's existence within the messaging system, they may choose not to interact based on their individual privacy settings. This allows for a flexible and user-controlled communication experience.
 
 ---
 
 ## Channels
 
 A **Channel** is a designated space created and managed by an administrator where multiple users can engage in discussions. Channels facilitate group communication and can be configured with various roles and permissions for participants, allowing for a structured interaction environment. Each user within a channel may have different metadata, such as their role (e.g., admin, moderator, member) and specific permissions (e.g., ability to post messages, manage users). Despite these individual differences, all users share a common subset of channel metadata, which includes channel name, description, and general settings. This structure promotes organized communication while allowing for diverse user interactions.
 
 ---
 
 ## Personal Notes
 
 A **Personal Note** is a private communication tool designed exclusively for the user who created it. This type of message is associated with the username and devices of the creator, allowing them to store and manage notes across multiple devices. Each Personal Note retains metadata related to the creator's devices, enabling seamless message creation and retrieval from any registered device. This functionality ensures that users can access their notes anytime, anywhere, while maintaining the privacy and integrity of their personal information.
 
 ---
 
 ## Summary
 
 This refined structure provides a clear and comprehensive overview of the messaging data objects, emphasizing the roles and functionalities of each component within the messaging system. By adhering to industry standards, these descriptions facilitate better understanding and implementation of the messaging protocol, ensuring a robust and user-friendly communication experience.
 */

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
    ///   - messageFlags: Flags that provide additional information about the message, such as whether it is urgent or requires acknowledgment.
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
        messageType: MessageType,
        messageFlags: MessageFlags,
        recipient: MessageRecipient,
        text: String = "",
        metadata: Document,
        pushType: PushNotificationType,
        destructionTime: TimeInterval? = nil
    ) async throws {
        do {
            let message = CryptoMessage(
                messageType: messageType,
                messageFlags: messageFlags,
                recipient: recipient,
                text: text,
                pushType: pushType,
                metadata: metadata,
                sentDate: Date(),
                destructionTime: destructionTime
            )
            
            try await processWrite(message: message, session: CryptoSession.shared)
        } catch {
            await self.logger.log(level: .error, message: "\(error)")
            throw error
        }
    }
    
    
    public struct SharedContactInfo: Codable, Sendable {
        public let secretName: String
        public let metadata: Document
        public let sharedCommunicationId: UUID?
        
        public init(secretName: String, metadata: Document, sharedCommunicationId: UUID?) {
            self.secretName = secretName
            self.metadata = metadata
            self.sharedCommunicationId = sharedCommunicationId
        }
    }
    
    //For Device Contact and Communication Synchronization
    public func addContacts(_ infos: [SharedContactInfo]) async throws {
        guard let mySecretName = await sessionContext?.sessionUser.secretName else { return }
        let contacts = try await cache?.fetchContacts()
        let symmetricKey = try await getAppSymmetricKey()
        
        let filteredInfos = await infos.asyncFilter { info in
            // Check if contacts is not nil and does not contain the secretName
            let containsSecretName = await contacts?.asyncContains { contact in
                if let secretName = await contact.props(symmetricKey: symmetricKey)?.secretName {
                    return info.secretName == secretName
                }
                return false
            } ?? false // If contacts is nil, return false

            // We want to include `info` only if `containsSecretName` is false
            return !containsSecretName
        }
        
        for info in filteredInfos {
            guard let transportDelegate = transportDelegate else { throw SessionErrors.transportNotInitialized }
            guard let cache = cache else { throw SessionErrors.databaseNotInitialized }
            let userConfiguration = try await transportDelegate.findConfiguration(for: info.secretName)
            
            let contact = Contact(
                id: UUID(), // Consider using the same UUID for both Contact and ContactModel if they are linked
                secretName: info.secretName,
                configuration: userConfiguration,
                metadata: info.metadata
            )
            
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
            
//            await messageObserver?.setCreatedContact(contact)
//            var nicks = [NeedleTailNick]()
//            for device in try contact.configuration.getVerifiedDevices() {
//                if let nick = NeedleTailNick(name: contact.secretName, deviceId: device.deviceId) {
//                    nicks.append(nick)
//                }
//            }
//            try await ntSession.getIRCConnection().writer?.requestOnlineNicks(nicks)
            
            await self.logger.log(level: .debug, message: "Creating Communication Model")
            // Create communication model
            let communicationModel = try await taskProcessor.jobProcessor.createCommunicationModel(
                recipients: [mySecretName, info.secretName],
                communicationType: .nickname(info.secretName),
                metadata: [:],
                symmetricKey: symmetricKey
            )
            
            guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
                throw CryptoSession.SessionErrors.propsError
            }
            
            props.sharedId = info.sharedCommunicationId
            
            try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
            try await cache.createCommunication(communicationModel)
            try await receiverDelegate?.updatedCommunication(communicationModel, members: [info.secretName])
            await self.logger.log(level: .debug, message: "Created Communication Model")
        }
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
        needsSynchronization: Bool
    ) async throws -> ContactModel {
        guard let sessionContext = await sessionContext else {
            throw SessionErrors.sessionNotInitialized
        }
        
        let newContactSecretName = secretName.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        let mySecretName = await sessionContext.sessionUser.secretName
        
        guard newContactSecretName != mySecretName else {
            throw CryptoSession.SessionErrors.invalidSecretName
        }
        
        let appSymmetricKey = try await getAppSymmetricKey()
        
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        
        // Check if the contact already exists
        if let contactModel = try await cache.fetchContacts().asyncFirst(where: { await $0.props(symmetricKey: appSymmetricKey)?.secretName == newContactSecretName }) {
            guard let props = await contactModel.props(symmetricKey: appSymmetricKey) else {
                throw SessionErrors.configurationError
            }
            
            // Simplified metadata handling
            let configuration = props.configuration
            let contactMetadata = metadata.isEmpty ? (props.metadata ?? [:]) : metadata
            
            let contact = Contact(
                id: contactModel.id,
                secretName: newContactSecretName,
                configuration: configuration,
                metadata: contactMetadata
            )
            
            _ = try await contactModel.updatePropsMetadata(
                symmetricKey: appSymmetricKey,
                metadata: contactMetadata)
            
            try await cache.updateContact(contactModel)
            try await receiverDelegate?.updateContact(contact)
            return contactModel
        } else {
            guard let transportDelegate = transportDelegate else {
                throw SessionErrors.transportNotInitialized
            }
            
            let userConfiguration = try await transportDelegate.findConfiguration(for: newContactSecretName)
            
            let contact = Contact(
                id: UUID(), // Consider using the same UUID for both Contact and ContactModel if they are linked
                secretName: newContactSecretName,
                configuration: userConfiguration,
                metadata: metadata
            )
            
            let contactModel = try ContactModel(
                id: contact.id, // Use the same UUID
                props: .init(
                    secretName: contact.secretName,
                    configuration: contact.configuration,
                    metadata: contact.metadata
                ),
                symmetricKey: appSymmetricKey
            )
            
            try await cache.createContact(contactModel)
            try await receiverDelegate?.createContact(contact, needsSynchronization: needsSynchronization)
            
            _ = try await updateOrCreateCommunication(
                mySecretName: mySecretName,
                theirSecretName: newContactSecretName)
            
            return contactModel
        }
    }
    
    //For Contact to Contact Communication Synchronization
    private func updateOrCreateCommunication(mySecretName: String, theirSecretName: String) async throws -> String? {
        
        guard let cache = cache else {
            throw SessionErrors.databaseNotInitialized
        }
        
        let symmetricKey = try await getAppSymmetricKey()
        
        var communicationModel: BaseCommunication?
        var shouldUpdateCommunication = false
        do {
            communicationModel = try await taskProcessor.jobProcessor.findCommunicationType(
                cache: cache,
                communicationType: .nickname(theirSecretName),
                session: self)
            await self.logger.log(level: .debug, message: "Found Communication Model")
            shouldUpdateCommunication = true
        } catch {
            await self.logger.log(level: .debug, message: "Creating Communication Model")
            // Create communication model
            communicationModel = try await taskProcessor.jobProcessor.createCommunicationModel(
                recipients: [mySecretName, theirSecretName],
                communicationType: .nickname(theirSecretName),
                metadata: [:],
                symmetricKey: symmetricKey
            )
        }
        
        guard let communicationModel = communicationModel else {
            throw CryptoSession.SessionErrors.cannotFindCommunication
        }
        guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
            throw CryptoSession.SessionErrors.propsError
        }
        
        if props.sharedId == nil {
            
            let sharedIdentifier = UUID()
            props.sharedId = sharedIdentifier
            
            try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
                try await receiverDelegate?.updatedCommunication(communicationModel, members: [theirSecretName])
                await self.logger.log(level: .debug, message: "Updated Communication Model")
            } else {
                try await cache.createCommunication(communicationModel)
                try await receiverDelegate?.updatedCommunication(communicationModel, members: [theirSecretName])
                await self.logger.log(level: .debug, message: "Created Communication Model")
            }
            return sharedIdentifier.uuidString
        } else {
            await self.logger.log(level: .debug, message: "Shared Id already exists")
            return nil
        }
    }
    
    //For Contact to Contact Communication Synchronization
    public func sendCommunicationSynchronization(contact secretName: String) async throws {
        await self.logger.log(level: .debug, message: "Sending communication synchronization to \(secretName)")
        guard let sessionContext = await sessionContext else { throw SessionErrors.sessionNotInitialized }
        let mySecretName = await sessionContext.sessionUser.secretName
        
        guard secretName != mySecretName else {
            throw CryptoSession.SessionErrors.invalidSecretName
        }
        
        guard let sharedIdentifier = try await updateOrCreateCommunication(
            mySecretName: mySecretName,
            theirSecretName: secretName
        ) else { return }
        
        //Send Communication Synchronization Message Once
        try await writeTextMessage(
            messageType: .nudgeLocal,
            messageFlags: .communicationSynchronization,
            recipient: .nickname(secretName),
            text: sharedIdentifier,
            metadata: [:],
            pushType: .none,
            destructionTime: nil)
        await self.logger.log(level: .debug, message: "Sent communication synchronization")
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
    ///   - `SessionErrors.databaseNotInitialized`: If the cache is not initialized.
    ///   - `SessionErrors.sessionNotInitialized`: If the session context is not initialized.
    ///   - `SessionErrors.cannotFindContact`: If the specified contact cannot be found in the cache.
    ///   - `SessionErrors.propsError`: If there is an error updating the contact's properties.
    ///   - Any other errors that may occur during the process, such as encoding errors or network issues.
    ///
    /// - Important: Ensure that the session and cache are properly initialized before calling this method.
    ///
    /// - Note: This method is asynchronous and should be awaited.
    public func requestFriendshipStateChange(
        state: FriendshipMetadata.State,
        contact: Contact
    ) async throws {
        await self.logger.log(level: .info, message: "Requesting friendship state change for \(contact.secretName) to state \(state).")
        guard let cache = cache else { throw SessionErrors.databaseNotInitialized }
        guard let sessionContext = await sessionContext else { throw SessionErrors.sessionNotInitialized }
        let appSymmetricKey = try await getAppSymmetricKey()
        guard let foundContact = try await cache.fetchContacts().asyncFirst(where: { await $0.props(symmetricKey: appSymmetricKey)?.secretName == contact.secretName }) else { throw SessionErrors.cannotFindContact }
        let symmetricKey = try await getAppSymmetricKey()
        var currentMetadata: FriendshipMetadata?
        
        if let friendshipDocument = contact.metadata["friendshipMetadata"] as? Document, !friendshipDocument.isEmpty {
            currentMetadata = try contact.metadata.decode(forKey: "friendshipMetadata")
        }
        if currentMetadata == nil {
            currentMetadata = FriendshipMetadata()
        }
        guard var currentMetadata = currentMetadata else { return }
        //Do not allow state changes that are not different, i.e. my state is .accepted cannot acceptFriendRequest() again
        if currentMetadata.myState == .accepted && state == .accepted { return }
        switch state {
        case .pending:
            currentMetadata.revokeFriendRequest()
        case .requested:
            currentMetadata.sendFriendRequest()
        case .accepted:
            currentMetadata.acceptFriendRequest()
        case .blocked, .blockedUser:
            currentMetadata.blockFriend()
        case .unblock:
            currentMetadata.unBlockFriend()
        case .rejectedRequest, .friendshipRejected, .rejected:
            currentMetadata.rejectFriendRequest()
        }
        
        let metadata = try BSONEncoder().encode(currentMetadata)
        let updatedProps = try await foundContact.updatePropsMetadata(
            symmetricKey: symmetricKey,
            metadata: metadata)
        
        guard let updatedMetadata = updatedProps?.metadata else {
            throw SessionErrors.propsError
        }
        
        await receiverDelegate?.contactMetadata(
            changed: .init(
                id: contact.id,
                secretName: contact.secretName,
                configuration: contact.configuration,
                metadata: updatedMetadata))
        
        let updatedContact = try await foundContact.makeDecryptedModel(of: Contact.self, symmetricKey: symmetricKey)
        
        try await cache.updateContact(foundContact)
        guard let recachedModel = try await cache.fetchContacts().asyncFirst(where: { await $0.props(symmetricKey: appSymmetricKey)?.secretName == contact.secretName }) else { return }
        let recachedContact = try await recachedModel.makeDecryptedModel(of: Contact.self, symmetricKey: symmetricKey)
        try await receiverDelegate?.updateContact(recachedContact)
        
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
        try await writeTextMessage(
            messageType: .nudgeLocal,
            messageFlags: .friendshipStateRequest(blockUnblockData),
            recipient: .nickname(contact.secretName),
            metadata: ["friendshipMetadata": metadata],
            pushType: .contactRequest,
            destructionTime: nil)
            
        await self.logger.log(level: .info, message: "Sent Friendship State Change Request")
    }
    

    
    public func updateMessageDeliveryState(_
                                           message: PrivateMessage,
                                           deliveryState: DeliveryState,
                                           messageRecipient: MessageRecipient,
                                           allowExternalUpdate: Bool = false
    ) async throws {
        guard let sessionContext = await sessionContext else { throw SessionErrors.sessionNotInitialized }
        guard let cache = cache else { throw SessionErrors.databaseNotInitialized }
        let appSymmetricKey = try await getAppSymmetricKey()
        guard var props = await message.props(symmetricKey: appSymmetricKey) else { throw SessionErrors.propsError }
        props.deliveryState = deliveryState
        _ = try await message.updateProps(symmetricKey: appSymmetricKey, props: props)
        try await cache.updateMessage(message, symmetricKey: appSymmetricKey)
        await receiverDelegate?.updatedMessage(message)
        
        if allowExternalUpdate {
            let metadata = DeliveryStateMetadata(state: props.deliveryState, sharedId: message.sharedId)
            let encodedDeliveryState = try BSONEncoder().encode(metadata)
            //Need to flop recipient
            try await writeTextMessage(
                messageType: .nudgeLocal,
                messageFlags: .deliveryStateChange,
                recipient: messageRecipient,
                metadata: encodedDeliveryState,
                pushType: .none)
        }
    }
    
    public func sendContactCreatedAcknowledgment(recipient secretName: String) async throws {
        await self.logger.log(level: .debug, message: "Sending Contact Created Acknowledgment")
        guard let sessionContext = await sessionContext else { throw SessionErrors.sessionNotInitialized }
        try await writeTextMessage(
            messageType: .nudgeLocal,
            messageFlags: .contactCreated,
            recipient: .nickname(secretName),
            metadata: [:],
            pushType: .none)
        await self.logger.log(level: .debug, message: "Sent Contact Created Acknowledgment")
    }
    
    public func editCurrentMessage(_ message: PrivateMessage, newText: String) async throws {
        guard let sessionContext = await sessionContext else { throw SessionErrors.sessionNotInitialized }
        guard let cache = cache else { throw SessionErrors.databaseNotInitialized }
        let appSymmetricKey = try await getAppSymmetricKey()
        guard var props = await message.props(symmetricKey: appSymmetricKey) else { fatalError() }
        
        props.message.text = newText
        _ = try await message.updateProps(symmetricKey: appSymmetricKey, props: props)

        try await cache.updateMessage(message, symmetricKey: appSymmetricKey)
        await receiverDelegate?.updatedMessage(message)
        
        
        let editMetadata = EditMessageMetadata(value: newText, sharedId: message.sharedId, sender: "")
        let metadata = try BSONEncoder().encode(editMetadata)
        //2. re-send
        try await writeTextMessage(
            messageType: .nudgeLocal,
            messageFlags: .editMessage,
            recipient: props.message.recipient,
            metadata: metadata,
            pushType: .none)
    }
    
    public func findCommunication(for messageRecipient: MessageRecipient) async throws -> BaseCommunication {
        guard let cache = cache else { throw SessionErrors.databaseNotInitialized }
        return try await taskProcessor.jobProcessor.findCommunicationType(
            cache: cache,
            communicationType: messageRecipient,
            session: self)
    }
}

public struct DeliveryStateMetadata: Codable, Sendable {
    public let state: DeliveryState
    public let sharedId: String
    
    public init(state: DeliveryState, sharedId: String) {
        self.state = state
        self.sharedId = sharedId
    }
}

public struct EditMessageMetadata<T: Codable & Sendable>: Codable, Sendable {
    public let value: T
    public let sharedId: String
    public let sender: String
    
    public init(value: T, sharedId: String, sender: String) {
        self.value = value
        self.sharedId = sharedId
        self.sender = sender
    }
}

public struct RevokeMessageMetadata: Codable, Sendable {
    public let sharedId: String
    
    public init(sharedId: String) {
        self.sharedId = sharedId
    }
}


//MARK: Outbound
extension CryptoSession {
    
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
        let appSymmetricKey = try await getAppSymmetricKey()
        let mySecretName = await sessionContext.sessionUser.secretName
        
        
        try await taskProcessor.outboundTask(
            message: message,
            cache: cache,
            symmetricKey: appSymmetricKey,
            session: session,
            sender: mySecretName,
            type: message.recipient,
            shouldPersist: message.messageType == .nudgeLocal ? false : true,
            logger: logger)
    }
}

//MARK: Inbound
extension CryptoSession {
    
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
}

actor TaskProcessor {
    
    let jobProcessor = JobProcessor()
    let crypto = NeedleTailCrypto()
    
    
    //Outbound
    func outboundTask(
        message: CryptoMessage,
        cache: SessionCache,
        symmetricKey: SymmetricKey,
        session: CryptoSession,
        sender: String,
        type: MessageRecipient,
        shouldPersist: Bool,
        logger: NeedleTailLogger
    ) async throws {
        
        var identities = [SessionIdentity]()
        var recipients = Set<String>()
        
        defer {
            identities.removeAll()
            recipients.removeAll()
        }
        
        switch type {
        case .personalMessage:
            
            identities = try await gatherPersonalIdentities(
                session: session,
                sender: sender,
                logger: logger)
            
            recipients.insert(sender)
            
        case .nickname(let nickname):
            
            identities = try await gatherPrivateMessageIdentities(
                session: session,
                target: nickname,
                logger: logger)
            recipients.insert(sender)
            recipients.insert(nickname)
            
        case .channel(_): //We pass the entire type for members look up
            
            let (channelIdentities, members) = try await gatherChannelIdentities(
                cache: cache,
                session: session,
                symmetricKey: symmetricKey,
                type: type,
                logger: logger)
            identities = channelIdentities
            recipients.union(members)
         
        case .broadcast:
           break
        }
        
        try await queueEncryptableTask(
            for: identities,
            message: message,
            cache: cache,
            session: session,
            symmetricKey: symmetricKey,
            sender: sender,
            recipients: recipients,
            shouldPersist: shouldPersist,
            logger: logger)
    }
    
    
    private func gatherPersonalIdentities(
        session: CryptoSession,
        sender: String,
        logger: NeedleTailLogger
    ) async throws -> [SessionIdentity] {
        //Get Identities only for me
        var identities = try await session.getSessionIdentities(with: sender)
        if identities.isEmpty {
            identities = try await session.refreshSessionIdentities(for: sender, from: [])
        }
        await logger.log(level: .info, message: "Gathered \(identities.count) Personal Session Identities")
        return identities
    }
    
    private func gatherPrivateMessageIdentities(
        session: CryptoSession,
        target: String,
        logger: NeedleTailLogger
    ) async throws -> [SessionIdentity] {
        //Get Identities only for me
        var identities = try await session.getSessionIdentities(with: target)
        if identities.isEmpty {
            identities = try await session.refreshSessionIdentities(for: target, from: [])
        }
        await logger.log(level: .info, message: "Gathered \(identities.count) Private Message Session Identities")
        return identities
    }
    private func gatherChannelIdentities(
        cache: SessionCache,
        session: CryptoSession,
        symmetricKey: SymmetricKey,
        type: MessageRecipient,
        logger: NeedleTailLogger
    ) async throws -> ([SessionIdentity], Set<String>) {
        var communicationModel: BaseCommunication
        var shouldUpdateCommunication = false
        do {
            communicationModel = try await jobProcessor.findCommunicationType(
                cache: cache,
                communicationType: type,
                session: session
            )
            
            guard var newProps = await communicationModel.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
            newProps.messageCount += 1
            _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: newProps)
            shouldUpdateCommunication = true
        } catch {
            throw CryptoSession.SessionErrors.channelNotCreated
        }

        
        //1. Collect Members of channel
        guard let props = await communicationModel.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
        let members = props.members
        
        var identities = [SessionIdentity]()
        //3. Double Ratchet for all memebers and their devices
        for member in members {
            identities = try await session.getSessionIdentities(with: member)
            if identities.isEmpty {
                identities = try await session.refreshSessionIdentities(for: member, from: [])
            }
        }
        await logger.log(level: .info, message: "Gathered \(identities.count) Channel Session Identities")
        return (identities, members)
    }
    
    private func queueEncryptableTask(for
                                      sessionIdentities: [SessionIdentity],
                                      message: CryptoMessage,
                                      cache: SessionCache,
                                      session: CryptoSession,
                                      symmetricKey: SymmetricKey,
                                      sender: String,
                                      recipients: Set<String>,
                                      shouldPersist: Bool,
                                      logger: NeedleTailLogger
    ) async throws {
        var task: EncrytableTask
        var message = message
        var encryptableMessage: PrivateMessage?
        
        if shouldPersist {
            //1. Pass messages to be cached and saved on the local database
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            do {
                communicationModel = try await jobProcessor.findCommunicationType(
                    cache: cache,
                    communicationType: message.recipient,
                    session: session)
                
                guard var newProps = await communicationModel.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
                
                newProps.messageCount += 1
                _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: newProps)
                shouldUpdateCommunication = true
            } catch {
                communicationModel = try await jobProcessor.createCommunicationModel(
                    recipients: recipients,
                    communicationType: message.recipient,
                    metadata: message.metadata,
                    symmetricKey: symmetricKey)
                
                try await session.receiverDelegate?.updatedCommunication(communicationModel, members: recipients)
            }
            
            /// Create the message model and save locally
            let message = try await createOutboundMessageModel(
                message: message,
                communication: communicationModel,
                session: session,
                symmetricKey: symmetricKey,
                members: recipients,
                sharedId: UUID().uuidString,
                shouldUpdateCommunication: shouldUpdateCommunication)
            
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(message)
            encryptableMessage = message
        }
        
        for identity in sessionIdentities {
        
            switch message.messageType {
            case .media:
                //If we are media we need to send a media packet. Due to how large media is and the load it would place on the crypto layer we never double ratchet the actual media. The following is the basic process.
                
                // 1. We send the media message using the double ratchet. This contains the needed symmetric key in order to decrypt the media once it has been downloaded from storage. It is a one time key and is destroyed and replaced with the app symmetric key each and everytime the media is retrieve from the local disk after the download has completed.
                
                // 2. We generate an upload packet for each media message recipient. This includes all devices for a recipient and the current users devices
                
                // 3. After the media message is sent on the transport layer, if we have created upload packets we send them via the proper upload to storage method.
                
                if let props = try await identity.props(symmetricKey: symmetricKey) {
                    guard let encryptableMessage else { fatalError() }
                    guard var messageProps = try await encryptableMessage.props(symmetricKey: symmetricKey) else { fatalError() }
                    let mediaSymmetricKey = try crypto.userInfoKey(UUID().uuidString)
                    let encodedKey = try BSONEncoder().encodeData(mediaSymmetricKey)
                    let synchronizationIdentifier = UUID().uuidString
                    messageProps.message.metadata["symmetricKey"] = encodedKey
                    messageProps.message.metadata["synchronizationIdentifier"] = synchronizationIdentifier
                    try await encryptableMessage.updateProps(symmetricKey: symmetricKey, props: messageProps)
                    try await session.cache?.updateMessage(encryptableMessage, symmetricKey: symmetricKey)

                    await session.transportDelegate?.createUploadPacket(
                        secretName: props.secretName,
                        deviceId: props.deviceId,
                        recipient: message.recipient,
                        metadata:  messageProps.message.metadata)
                }
            default:
                break
            }
            
            //Only Persist local
            if shouldPersist {
                guard let encryptableMessage else { return }
                guard let messageProps = await encryptableMessage.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
                guard let identityProps = await identity.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
                task = EncrytableTask(
                    task: .writeMessage(OutboundTaskMessage(
                        message: messageProps.message,
                        recipientSecretName: identityProps.secretName,
                        recipientDeviceId: identityProps.deviceId,
                        localId: encryptableMessage.id,
                        sharedId: encryptableMessage.sharedId))
                )
                
            } else {
                switch message.messageFlags {
                    //This updates our communication Model for us locally on outbound writes
                case .communicationSynchronization:
                    guard !message.text.isEmpty else { return }
                    await logger.log(level: .debug, message: "Requester Synchronizing Communication Message")
                    let communicationModel = try await jobProcessor.findCommunicationType(
                        cache: cache,
                        communicationType: message.recipient,
                        session: session
                    )
                    await logger.log(level: .debug, message: "Found Communication Model For Synchronization: \(communicationModel)")
                    var props = try await communicationModel.props(symmetricKey: symmetricKey)
                    props?.sharedId = UUID(uuidString: message.text)
                    try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
                    try await cache.updateCommunication(communicationModel)
                    await logger.log(level: .debug, message: "Updated Communication Model For Synchronization with Shared Id: \(props?.sharedId)")
                default:
                    break
                }
                
                guard let identityProps = await identity.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
                
                task = EncrytableTask(
                    task: .writeMessage(OutboundTaskMessage(
                        message: message,
                        recipientSecretName: identityProps.secretName,
                        recipientDeviceId: identityProps.deviceId,
                        localId: UUID(),
                        sharedId: UUID().uuidString))
                )
            }
            
            try await jobProcessor.queueTask(task, session: session)
        }
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
    ) async throws -> PrivateMessage {
        guard let sessionContext = await session.sessionContext else { throw CryptoSession.SessionErrors.sessionNotInitialized }
        let sessionUser = sessionContext.sessionUser
        guard let communicationProps = await communication.props(symmetricKey: symmetricKey) else { fatalError() }
        let messageModel = try await PrivateMessage(
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
                sendersId: sessionUser.deviceId
            ),
            symmetricKey: symmetricKey)
        
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        if shouldUpdateCommunication {
            do {
                try await cache.updateCommunication(communication)
                try await session.receiverDelegate?.updatedCommunication(communication, members: members)
            } catch {
                throw error
            }
        }
        try await cache.createMessage(messageModel, symmetricKey: try await session.getAppSymmetricKey())
        return messageModel
    }
}

//MARK: Inbound
extension TaskProcessor {
    func inboundTask(_ message: InboundTaskMessage, session: CryptoSession) async throws {
        try await jobProcessor.queueTask(
            EncrytableTask(task: .streamMessage(message)),
            session: session)
        
    }
}

struct OutboundTaskMessage: Codable & Sendable {
    var message: CryptoMessage
    let recipientSecretName: String
    let recipientDeviceId: UUID
    let localId: UUID
    let sharedId: String
}


struct InboundTaskMessage: Codable & Sendable {
    let message: SignedRatchetMessage
    let senderSecretName: String
    let senderDeviceId: UUID
    let sharedMessageId: String
}

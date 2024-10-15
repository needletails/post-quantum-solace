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
    
    public func writeTextMessage(
        messageType: MessageType,
        messageFlags: MessageFlags,
        recipient: MessageRecipient,
        text: String = "",
        metadata: Document,
        pushType: PushNotificationType,
        destructionTime: TimeInterval? = nil
    ) async throws {
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
    }
    
    public func updateOrCreateContact(
        secretName: String,
        metadata: Document = [:]
    ) async throws -> ContactModel {
        guard let sessionContext = await sessionContext else { throw SessionErrors.sessionNotInitialized }
        guard secretName != sessionContext.sessionUser.secretName else {
            throw CryptoSession.SessionErrors.invalidSecretName
        }
        let symmetricKey = try await getAppSymmetricKey(password: sessionContext.sessionUser.secretName)
        guard let cache = cache else { throw SessionErrors.databaseNotInitialized }
        //2. Check to see if we aleady have this contact
        if let contactModel = try await cache.fetchContacts().asyncFirst(where: { await $0.props?.secretName == secretName }) {
            guard let configuration = await contactModel.props?.configuration else { fatalError() }
            var contactMetadata: Document
            if metadata.isEmpty {
                contactMetadata = await contactModel.props?.metadata ?? [:]
            } else {
                contactMetadata = metadata
            }
            let contact = Contact(
                id: contactModel.id,
                secretName: secretName,
                configuration: configuration,
                metadata: contactMetadata)
            _ = try await contactModel.updatePropsMetadata(symmetricKey: symmetricKey, metadata: metadata)
            try await cache.updateContact(contactModel)
            await receiverDelegate?.contactMetadata(changed: contact)
            return contactModel
        } else {
            guard let transportDelegate = transportDelegate else { throw SessionErrors.transportNotInitialized }
            let userConfiguration = try await transportDelegate.findConfiguration(for: secretName)
            
            let contact = Contact(
                id: UUID(),
                secretName: secretName,
                configuration: userConfiguration,
                metadata: metadata)
            
            let contactModel = try ContactModel(
                props: .init(
                    secretName: contact.secretName,
                    configuration: contact.configuration,
                    metadata: contact.metadata),
                symmetricKey: symmetricKey
            )
            
            try await cache.createContact(contactModel)
            await receiverDelegate?.createContact(contact)
            return contactModel
        }
    }
    
    public func requestFriendshipStateChange(state: FriendshipMetadata.State, contact: Contact) async throws {
        guard let cache = cache else { throw SessionErrors.databaseNotInitialized }
        guard let sessionContext = await sessionContext else { throw SessionErrors.sessionNotInitialized }
        guard let foundContact = try await cache.fetchContacts().asyncFirst(where: { await $0.props?.secretName == contact.secretName }) else { throw SessionErrors.cannotFindContact }
        let symmetricKey = try await getAppSymmetricKey(password: sessionContext.sessionUser.secretName)
        
        var friendshipMetadata = FriendshipMetadata()
        switch state {
        case .pending:
            friendshipMetadata.revokeFriendRequest()
        case .requested:
            friendshipMetadata.sendFriendRequest()
        case .accepted:
            friendshipMetadata.acceptFriendRequest()
        case .rejected:
            friendshipMetadata.rejectFriendRequest()
        case .blocked:
            friendshipMetadata.blockFriend()
        case .unblock:
            friendshipMetadata.unBlockFriend()
        }
        
        let metadata = try BSONEncoder().encode(friendshipMetadata)
        let updatedProps = try await foundContact.updatePropsMetadata(symmetricKey: symmetricKey, metadata: metadata)
        guard let updatedMetadata = updatedProps?.metadata else { throw SessionErrors.propsError }
        await receiverDelegate?.contactMetadata(
            changed: .init(
                id: contact.id,
                secretName: contact.secretName,
                configuration: contact.configuration,
                metadata: updatedMetadata)
        )
        try await cache.updateContact(foundContact)
     
        //Transport
        try await writeTextMessage(
            messageType: .nudgeLocal,
            messageFlags: .friendshipStateRequest,
            recipient: .nickname(contact.secretName),
            metadata: metadata,
            pushType: .contactRequest,
            destructionTime: nil)
    }
    
    public func updateMessageDeliveryState(_
                                           message: PrivateMessage,
                                           deliveryState: DeliveryState,
                                           allowExternalUpdate: Bool = false
    ) async throws {
        guard let sessionContext = await sessionContext else { throw SessionErrors.sessionNotInitialized }
        let symmetricKey = try await getAppSymmetricKey(password: sessionContext.sessionUser.secretName)
        guard var props = await message.props else { fatalError() }
        props.deliveryState = deliveryState
        _ = try await message.updateProps(symmetricKey: symmetricKey, props: props)
        await receiverDelegate?.updatedMessage(message)
        
        if allowExternalUpdate {
            
            let metadata = DeliveryStateMetadata(state: props.deliveryState, messageId: message.sharedMessageIdentity)
            let encodedDeliveryState = try BSONEncoder().encode(metadata)
            
            try await writeTextMessage(
                messageType: .nudgeLocal,
                messageFlags: .deliveryStateChange,
                recipient: props.message.recipient,
                metadata: encodedDeliveryState,
                pushType: .none)
        }
    }
    
    public func editCurrentMessage(_ message: PrivateMessage, newMessage: CryptoMessage) async throws {
        guard let sessionContext = await sessionContext else { throw SessionErrors.sessionNotInitialized }
        let symmetricKey = try await getAppSymmetricKey(password: sessionContext.sessionUser.secretName)
        guard var props = await message.props else { fatalError() }
        props.message = newMessage
        _ = try await message.updateProps(symmetricKey: symmetricKey, props: props)
        await receiverDelegate?.updatedMessage(message)
        
        //2. re-send
        try await writeTextMessage(
            messageType: .text,
            messageFlags: .editMessage,
            recipient: props.message.recipient,
            metadata: props.message.metadata,
            pushType: .message)
        
        
    }
}

public struct DeliveryStateMetadata: Codable, Sendable {
    public let state: DeliveryState
    public let messageId: String
}


//MARK: Outbound
extension CryptoSession {
    
    func processWrite(
        message: CryptoMessage,
        session: CryptoSession
    ) async throws {
        
        guard let sessionContext = await session.sessionContext else { throw SessionErrors.sessionNotInitialized }
        guard let cache = await session.cache else { throw SessionErrors.databaseNotInitialized }
        
        switch message.recipient {
        case .nickname(let recipient):
            switch message.messageType {
                //Dont save locally on any local device, but still saves the Job if we are offline and can save the SignedRatchetMessage remotely for future deliverly.
            case .nudgeLocal:
                for identity in try await taskProcessor.getOurSessionIdentities(with: recipient, session: session) {
                    guard let identityProps = await identity.props else { fatalError() }
                    
                    let task = EncrytableTask(
                        task: .writeMessage(OutboundTaskMessage(
                            message: message,
                            recipientSecretName: identityProps.secretName,
                            recipientDeviceIdentity: identityProps.deviceIdentity,
                            localId: UUID(),
                            sharedMessageIdentity: UUID().uuidString
                        )
                        )
                    )
                    try await taskProcessor.jobProcessor.queueTask(task, session: session)
                }
            default:
                // Saves the message locally on all devices directed to.
                let symmetricKey = try await session.getAppSymmetricKey(password: session.appPassword)
                var communicationModel: BaseCommunication
                var shouldUpdateCommunication = false
                do {
                    communicationModel = try await taskProcessor.jobProcessor.findCommunicationType(
                        cache: cache,
                        communicationType: message.recipient
                    )
                    
                    guard var newProps = await communicationModel.props else { fatalError() }
                    newProps.messageCount += 1
                    _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: newProps)
                    shouldUpdateCommunication = true
                } catch {
                    communicationModel = try await taskProcessor.jobProcessor.createCommunicationModel(
                        recipients: [sessionContext.sessionUser.secretName, recipient],
                        communicationType: message.recipient,
                        metadata: message.metadata,
                        symmetricKey: symmetricKey
                    )
                }
                
                /// Create the message model and save locally
                let encryptableMessage = try await taskProcessor.createOutboundMessageModel(
                    message: message,
                    communication: communicationModel,
                    session: session,
                    symmetricKey: symmetricKey,
                    shouldUpdateCommunication: shouldUpdateCommunication
                )
                
                /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
                await session.receiverDelegate?.createdMessage(encryptableMessage)

                /// Send to Targets incluning my other devices
                try await taskProcessor.processMessageTask(
                    message: encryptableMessage,
                    session: session
                )
            }
        case .channel(_):
            break
        case .personalMessage:
            break
        case .broadcast:
            break
        }
    }
}

//MARK: Inbound
extension CryptoSession {
    
    public func receiveMessage(
        message: SignedRatchetMessage,
        sender: String,
        deviceIdentity: UUID,
        messageId: String
    ) async throws {
        let message = InboundTaskMessage(
            message: message,
            senderSecretName: sender,
            senderDeviceIdentity: deviceIdentity,
            sharedMessageIdentity: messageId
        )
        try await taskProcessor.receiveMessageTask(
            message,
            session: CryptoSession.shared)
    }
    
    
}

struct OutboundTaskMessage: Codable & Sendable {
    let message: CryptoMessage
    let recipientSecretName: String
    let recipientDeviceIdentity: UUID
    let localId: UUID
    let sharedMessageIdentity: String
}


struct InboundTaskMessage: Codable & Sendable {
    let message: SignedRatchetMessage
    let senderSecretName: String
    let senderDeviceIdentity: UUID
    let sharedMessageIdentity: String
}

actor TaskProcessor {
    
    let jobProcessor = JobProcessor()
    let crypto = NeedleTailCrypto()
    
    
    //Outbound
    func processMessageTask(
        message: PrivateMessage,
        session: CryptoSession
    ) async throws {
        guard let messageProps = await message.props else { fatalError() }
        guard session.isViable == true else {
            throw CryptoSession.SessionErrors.connectionIsNonViable
        }
        switch messageProps.message.recipient {
        case .nickname(let recipientName):
            let identites = try await getOurSessionIdentities(with: recipientName, session: session)
            if identites.isEmpty {
                throw CryptoSession.SessionErrors.missingSessionIdentity
            }
            
            for identity in identites {
                try await writeEncryptableTask(identity: identity, message: message)
            }
        case .channel(_):
            //Look up members of this channel name. THen we can do a batch process of what is done for nickname
            break
        case .broadcast:
            break
        case .personalMessage:
            break
        }
        
        func writeEncryptableTask(
            identity: SessionIdentity,
            message: PrivateMessage
        ) async throws {
            guard let messageProps = await message.props else { fatalError() }
            guard let identityProps = await identity.props else { fatalError() }
            let task = EncrytableTask(
                task: .writeMessage(OutboundTaskMessage(
                    message: messageProps.message,
                    recipientSecretName: identityProps.secretName,
                    recipientDeviceIdentity: identityProps.deviceIdentity,
                    localId: message.id,
                    sharedMessageIdentity: message.sharedMessageIdentity
                )
                )
            )
            try await jobProcessor.queueTask(task, session: session)
        }
    }
    
    func getOurSessionIdentities(with recipientName: String, session: CryptoSession) async throws -> [SessionIdentity] {
        var sessions = [SessionIdentity]()
        
        guard let sessionContext = await session.sessionContext else { throw CryptoSession.SessionErrors.sessionNotInitialized }
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        
        let currentSessions = try await cache.fetchSessionIdentities()
        
        let filtered = await currentSessions.asyncFilter { identity in
            // Safely cast the props to the expected type
            guard let props = await identity.props else {
                return false // Exclude this identity if casting fails
            }
            
            // Check if the identity is not the current user's identity
            let isDifferentIdentity = props.deviceIdentity != sessionContext.sessionUser.deviceIdentity &&
            props.secretName != sessionContext.sessionUser.secretName
            
            // Return true if the secret name matches the recipient name or if it's a different identity
            return props.secretName == recipientName || isDifferentIdentity
        }
        
        // Return filtered identities if not empty and is not the current session
        let foundRecipients = await filtered.asyncContains(where: { await $0.props?.secretName == recipientName })
        if foundRecipients {
            sessions.append(contentsOf: filtered)
        }
        
        // If we are empty we did not find a recipient... Let's create one
        if filtered.isEmpty {
            //first append our Identites, but not this current session
            sessions.append(contentsOf: filtered)
            
            guard let transport = await session.transportDelegate else { throw CryptoSession.SessionErrors.transportNotInitialized }
            
            // Get the user configuration for the recipient
            let configuration = try await transport.findConfiguration(for: recipientName)
            
            // Make sure that the identities of the user configuration are legit
            let publicSigningKey = try Curve25519SigningPublicKey(rawRepresentation: configuration.publicSigningKey)
            if try configuration.signed?.verifySignature(publicKey: publicSigningKey) == false {
                throw SigningErrors.signingFailedOnVerfication
            }
            
            // Loop over each device, create and cache the identity, and append it to the array
            for device in configuration.devices {
               let sessionIdentity = try await createEncryptableSessionIdentityModel(with: device, session: session)
                sessions.append(sessionIdentity)
            }
        }
        return sessions
    }
    
    /// A user only ever has session identies for it's self.
    func refreshLocalSessionIdentities(session: CryptoSession) async throws -> [SessionIdentity] {
        var sessions = [SessionIdentity]()
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        //This will refresh our local SessionIdentityModel
        let data = try await cache.findLocalDeviceConfiguration()
        guard let decryptedData = try await crypto.decrypt(data: data, symmetricKey: session.getAppSymmetricKey(password: session.appPassword)) else {
            throw CryptoSession.SessionErrors.sessionDecryptionError
        }
        let decodedContext = try BSONDecoder().decodeData(SessionContext.self, from: decryptedData)
        for device in decodedContext.lastUserConfiguration.devices {
            sessions.append(try await createEncryptableSessionIdentityModel(with: device, session: session))
        }
        return sessions
    }
    
    func createEncryptableSessionIdentityModel(with device: UserDeviceConfiguration, session: CryptoSession) async throws -> SessionIdentity {
        guard let sessionContext = await session.sessionContext else { throw CryptoSession.SessionErrors.sessionNotInitialized }
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        let identity = try await SessionIdentity(
            props: .init(
                secretName: sessionContext.sessionUser.secretName,
                deviceIdentity: sessionContext.sessionUser.deviceIdentity,
                senderIdentity: sessionContext.sessionContextId,
                publicKeyRepesentable: device.publicKey,
                publicSigningRepresentable: device.publicSigningKey,
                state: nil,
                deviceName: ""
            ),
            symmetricKey: session.getAppSymmetricKey(password: session.appPassword)
        )
        try await cache.createSessionIdentity(identity)
        return identity
    }
    
    /// Called on Message Save
    func createOutboundMessageModel(
        message: CryptoMessage,
        communication: BaseCommunication,
        session: CryptoSession,
        symmetricKey: SymmetricKey,
        shouldUpdateCommunication: Bool = false
    ) async throws -> PrivateMessage {
        guard let sessionContext = await session.sessionContext else { throw CryptoSession.SessionErrors.sessionNotInitialized }
        let sessionUser = sessionContext.sessionUser
        guard let communicationProps = await communication.props else { fatalError() }
        let messageModel = try await PrivateMessage(
            communicationIdentity: UUID(),
            senderIdentity: sessionContext.sessionContextId,
            sharedMessageIdentity: UUID().uuidString,
            sequenceId: communicationProps.messageCount,
            props: .init(
                base: communication,
                sendDate: Date(),
                deliveryState: .sending,
                message: message,
                sendersSecretName: sessionUser.secretName,
                sendersIdentity: sessionUser.deviceIdentity
            ),
            symmetricKey: symmetricKey
        )
        
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        if shouldUpdateCommunication {
            try await cache.updateCommunication(communication)
        }
        try await cache.createMessage(messageModel)
        return messageModel
    }
}

//MARK: Inbound
extension TaskProcessor {
    func receiveMessageTask(_ message: InboundTaskMessage, session: CryptoSession) async throws {
        try await jobProcessor.queueTask(
            EncrytableTask(task: .streamMessage(message)),
            session: session)
        
    }
}

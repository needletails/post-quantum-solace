//
//  JobProcessor.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//

import BSON
import Foundation
import NeedleTailCrypto
import DoubleRatchetKit
import SessionModels
import SessionEvents

/// Extension of `TaskProcessor` conforming to `SessionIdentityDelegate`.
/// This extension handles session identity management, including updating and fetching one-time keys,
/// performing message ratcheting, and managing session contexts.
extension TaskProcessor: SessionIdentityDelegate {
    
    /// Updates the session identity with the provided identity.
    /// - Parameter identity: The new session identity to be updated.
    /// - Throws: An error if the update fails.
    func updateSessionIdentity(_ identity: DoubleRatchetKit.SessionIdentity) async throws {}
    
    /// Fetches a private one-time key by its identifier.
    /// - Parameter id: The UUID of the one-time key to fetch.
    /// - Returns: The corresponding private one-time key.
    /// - Throws: `CryptoSession.SessionErrors.sessionNotInitialized` if the session is not initialized,
    ///           or `CryptoSession.SessionErrors.invalidKeyId` if the key ID is invalid.
    func fetchPrivateOneTimeKey(_ id: UUID) async throws -> DoubleRatchetKit.Curve25519PrivateKeyRepresentable {
        guard let sessionContext = await session?.sessionContext else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        guard let key = sessionContext.sessionUser.deviceKeys.privateOneTimeKeys.first(where: { $0.id == id }) else {
            throw CryptoSession.SessionErrors.invalidKeyId
        }
        return key
    }
    
    /// Updates the one-time key for the current session.
    /// - Throws: `CryptoSession.SessionErrors.sessionNotInitialized` if the session is not initialized.
    ///           Logs an error if the update fails.
    func updateOneTimeKey() async {
        do {
            guard let session = session else {
                throw CryptoSession.SessionErrors.sessionNotInitialized
            }
            guard let secretName = await session.sessionContext?.sessionUser.secretName else {
                throw CryptoSession.SessionErrors.sessionNotInitialized
            }
            try await session.transportDelegate?.updateOneTimeKeys(for: secretName)
        } catch {
            logger.log(level: .error, message: "Failed to update one time key: \(error)")
        }
    }
    
    /// Removes a private one-time key by its identifier.
    /// - Parameter id: The UUID of the one-time key to remove.
    /// - Throws: `CryptoSession.SessionErrors.sessionNotInitialized` if the session is not initialized.
    ///           Logs an error if the removal fails.
    func removePrivateOneTimeKey(_ id: UUID) async {
        do {
            guard let session = session else {
                throw CryptoSession.SessionErrors.sessionNotInitialized
            }
            guard var sessionContext = await session.sessionContext else {
                throw CryptoSession.SessionErrors.sessionNotInitialized
            }
            
            var deviceKeys = sessionContext.sessionUser.deviceKeys
            deviceKeys.privateOneTimeKeys.removeAll { $0.id == id }
            
            sessionContext.sessionUser.deviceKeys = deviceKeys
            sessionContext.updateSessionUser(sessionContext.sessionUser)
            await session.setSessionContext(sessionContext)
            
            // Encrypt and persist
            let encodedData = try BSONEncoder().encode(sessionContext)
            guard let encryptedConfig = try await crypto.encrypt(data: encodedData.makeData(), symmetricKey: session.getAppSymmetricKey()) else {
                throw CryptoSession.SessionErrors.sessionEncryptionError
            }
            
            try await session.cache?.updateLocalSessionContext(encryptedConfig)
        } catch {
            logger.log(level: .error, message: "Failed to remove private one time key: \(error)")
        }
    }
    
    /// Removes a public one-time key by its identifier.
    /// - Parameter id: The UUID of the one-time key to remove.
    /// - Throws: `CryptoSession.SessionErrors.sessionNotInitialized` if the session is not initialized.
    ///           Logs an error if the removal fails.
    func removePublicOneTimeKey(_ id: UUID) async {
        do {
            guard let session = session else {
                throw CryptoSession.SessionErrors.sessionNotInitialized
            }
            guard let secretName = await session.sessionContext?.sessionUser.secretName else {
                throw CryptoSession.SessionErrors.sessionNotInitialized
            }
            try await session.transportDelegate?.deleteOneTimeKey(for: secretName, with: id.uuidString)
        } catch {
            logger.log(level: .error, message: "Failed to remove public one time key: \(error)")
        }
    }
    
    /// Performs a ratchet operation based on the specified task.
    /// - Parameters:
    ///   - task: The task to perform, which can be either writing or streaming a message.
    ///   - session: The current crypto session.
    /// - Throws: An error if the ratchet operation fails.
    func performRatchet(
        task: TaskType,
        session: CryptoSession
    ) async throws {
        await self.ratchetManager.setDelegate(self)
        switch task {
        case .writeMessage(let outboundTask):
            try await handleWriteMessage(
                outboundTask: outboundTask,
                session: session)
        case .streamMessage(let inboundTask):
            try await handleStreamMessage(
                inboundTask: inboundTask,
                session: session
            )
        }
    }
    
    // MARK: - Outbound Message Handling
    
    /// Handles writing a message and performing the necessary ratchet operations.
    /// - Parameters:
    ///   - outboundTask: The outbound task message to be processed.
    ///   - session: The current crypto session.
    /// - Throws: An error if the message handling fails.
    private func handleWriteMessage(
        outboundTask: OutboundTaskMessage,
        session: CryptoSession
    ) async throws {
        self.session = session
        var outboundTask = outboundTask
        self.logger.log(level: .debug, message: "Performing Ratchet")
        
        guard let sessionContext = await session.sessionContext else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        guard let props = await outboundTask.recipientIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw CryptoSession.SessionErrors.propsError
        }
        
        guard let privateOneTimeKey = sessionContext.sessionUser.deviceKeys.privateOneTimeKeys.randomElement() else {
            throw CryptoSession.SessionErrors.invalidKeyId
        }
        
        guard let delegate else {
            throw CryptoSession.SessionErrors.transportNotInitialized
        }
        
        //Fetch the recipient's one time key
        let remotePublicOneTimeKey = try await delegate.fetchOneTimeKey(for: props.secretName, deviceId: props.deviceId.uuidString)
        
        try await ratchetManager.senderInitialization(
            sessionIdentity: outboundTask.recipientIdentity,
            sessionSymmetricKey: databaseSymmetricKey,
            remoteKeys: RemoteKeys(
                longTerm: .init(props.publicLongTermKey),
                oneTime: remotePublicOneTimeKey,
                kyber: .init(props.kyber1024PublicKey)),
            localKeys: LocalKeys(
                longTerm: .init(sessionContext.sessionUser.deviceKeys.privateLongTermKey),
                oneTime: privateOneTimeKey,
                kyber: .init(sessionContext.sessionUser.deviceKeys.kyber1024PrivateKey)))
        
        if let sessionDelegate = await session.sessionDelegate {
            outboundTask.message = try sessionDelegate.updateCryptoMessageMetadata(
                outboundTask.message,
                sharedMessageId: outboundTask.sharedId)
        }
        
        let encodedData = try BSONEncoder().encodeData(outboundTask.message)
        let ratchetedMessage = try await ratchetManager.ratchetEncrypt(plainText: encodedData)
        let signedMessage = try await signRatchetMessage(message: ratchetedMessage, session: session)
        
        try await session.transportDelegate?.sendMessage(signedMessage, metadata: SignedRatchetMessageMetadata(
            secretName: props.secretName,
            deviceId: props.deviceId,
            recipient: outboundTask.message.recipient,
            transportMetadata: outboundTask.message.transportInfo,
            sharedMessageIdentifier: outboundTask.sharedId))
    }
    
    // MARK: - Inbound Message Handling
    
    /// Handles streaming a message and performing the necessary ratchet operations.
    /// - Parameters:
    ///   - inboundTask: The inbound task message to be processed.
    ///   - session: The current crypto session.
    /// - Throws: An error if the message handling fails.
    private func handleStreamMessage(
        inboundTask: InboundTaskMessage,
        session: CryptoSession
    ) async throws {
        
        let (ratchetMessage, sessionIdentity) = try await verifyEncryptedMessage(session: session, inboundTask: inboundTask)
        
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw JobProcessorErrors.missingIdentity
        }
        
        let decryptedData: Data
        if props.state != nil {
            decryptedData = try await ratchetManager.ratchetDecrypt(ratchetMessage)
        } else {
            decryptedData = try await initializeRecipient(
                sessionIdentity: sessionIdentity,
                session: session,
                ratchetMessage: ratchetMessage
            )
        }
        
        let decodedMessage = try BSONDecoder().decode(CryptoMessage.self, from: Document(data: decryptedData))
        
        if let sessionDelegate = await session.sessionDelegate {
            try await sessionDelegate.processUnpersistedMessage(
                decodedMessage,
                senderSecretName: inboundTask.senderSecretName,
                senderDeviceId: inboundTask.senderDeviceId)
        }
        /// Now we can handle the message
        try await handleDecodedMessage(
            decodedMessage,
            inboundTask: inboundTask,
            session: session,
            sessionIdentity: sessionIdentity)
    }
    
    /// Initializes the recipient for a session based on the provided ratchet message.
    /// - Parameters:
    ///   - sessionIdentity: The session identity of the recipient.
    ///   - session: The current crypto session.
    ///   - ratchetMessage: The ratchet message to initialize with.
    /// - Returns: The decrypted data from the ratchet message.
    /// - Throws: An error if the initialization fails.
    private func initializeRecipient(
        sessionIdentity: SessionIdentity,
        session: CryptoSession,
        ratchetMessage: RatchetMessage
    ) async throws -> Data {
        self.session = session
        guard let sessionContext = await session.sessionContext else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        
        guard delegate != nil else {
            throw CryptoSession.SessionErrors.transportNotInitialized
        }
        
        //Fetch the recipient's one time key
        let localPrivateOneTimeKey = try await fetchPrivateOneTimeKey(ratchetMessage.header.oneTimeId)
        
        return try await ratchetManager.recipientInitialization(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: databaseSymmetricKey,
            remoteKeys: RemoteKeys(
                longTerm: .init(ratchetMessage.header.remotePublicLongTermKey),
                oneTime: ratchetMessage.header.remotePublicOneTimeKey,
                kyber: .init(ratchetMessage.header.remoteKyber1024PublicKey)),
            localKeys: LocalKeys(
                longTerm: .init(sessionContext.sessionUser.deviceKeys.privateLongTermKey),
                oneTime: localPrivateOneTimeKey,
                kyber: .init(sessionContext.sessionUser.deviceKeys.kyber1024PrivateKey)),
            initialMessage: ratchetMessage)
    }
    
    /// Handles the processing of a decoded message, specifically for private messages,
    /// regardless of their communication type. This method utilizes the recipient information
    /// for reference when looking up communication models, but the recipient itself is not persisted.
    ///
    /// On the initial creation of the communication model, necessary metadata must be provided.
    /// If the required metadata is not present in the decoded recipient and the communication model
    /// does not already exist, it should be included in the message metadata (e.g., members, admin, organizers).
    ///
    /// - Parameters:
    ///   - decodedMessage: The decoded `CryptoMessage` that needs to be processed.
    ///   - inboundTask: The `InboundTaskMessage` associated with the incoming message.
    ///   - session: The current `CryptoSession` in which the message is being processed.
    ///   - sessionIdentity: The `SessionIdentity` associated with the recipient of the message.
    /// - Throws: An error if the message processing fails due to issues such as missing metadata,
    ///           session errors, or communication model errors.
    private func handleDecodedMessage(_
                                      decodedMessage: CryptoMessage,
                                      inboundTask: InboundTaskMessage,
                                      session: CryptoSession,
                                      sessionIdentity: SessionIdentity
    ) async throws {
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        
        switch decodedMessage.recipient {
        case .nickname(let recipient):
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            //This can happen on multidevice support when a sender is also sending a message to it's master/child device.
            let isMe = await inboundTask.senderSecretName == session.sessionContext?.sessionUser.secretName
            do {
                
                //Need to flip recipient
                communicationModel = try await findCommunicationType(
                    cache: cache,
                    communicationType: .nickname(isMe ? recipient : inboundTask.senderSecretName),
                    session: session)
                
                var communication = try await communicationModel.makeDecryptedModel(of: Communication.self, symmetricKey: databaseSymmetricKey)
                communication.messageCount += 1
                
                _ = try await communicationModel.updateProps(
                    symmetricKey: databaseSymmetricKey,
                    props: BaseCommunication.UnwrappedProps(
                        sharedId: communication.sharedId,
                        messageCount: communication.messageCount,
                        administrator: communication.administrator,
                        operators: communication.operators,
                        members: communication.members,
                        metadata: communication.metadata,
                        blockedMembers: communication.blockedMembers,
                        communicationType: communication.communicationType))
                
                shouldUpdateCommunication = true
            } catch {
                //Need to flip recipient
                communicationModel = try await createCommunicationModel(
                    recipients: [recipient, inboundTask.senderSecretName],
                    communicationType: .nickname(isMe ? recipient : inboundTask.senderSecretName),
                    metadata: decodedMessage.metadata,
                    symmetricKey: databaseSymmetricKey
                )
                try await cache.createCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: [recipient, inboundTask.senderSecretName])
            }
            
            let messageModel = try await createInboundMessageModel(
                decodedMessage: decodedMessage,
                inboundTask: inboundTask,
                sendersSecretName: inboundTask.senderSecretName,
                senderDeviceId: inboundTask.senderDeviceId,
                session: session,
                communication: communicationModel,
                sessionIdentity: sessionIdentity
            )
            
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
                if let members = await communicationModel.props(symmetricKey: databaseSymmetricKey)?.members {
                    await session.receiverDelegate?.updatedCommunication(communicationModel, members: members)
                }
            }
            
            try await cache.createMessage(messageModel, symmetricKey: databaseSymmetricKey)
            
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
        case .personalMessage:
            let sender = inboundTask.senderSecretName
            guard let mySecretName = await session.sessionContext?.sessionUser.secretName else { return }
            
            let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            do {
                communicationModel = try await findCommunicationType(
                    cache: cache,
                    communicationType: decodedMessage.recipient,
                    session: session
                )
                
                var communication = try await communicationModel.makeDecryptedModel(of: Communication.self, symmetricKey: databaseSymmetricKey)
                communication.messageCount += 1
                
                _ = try await communicationModel.updateProps(
                    symmetricKey: databaseSymmetricKey,
                    props: BaseCommunication.UnwrappedProps(
                        sharedId: communication.sharedId,
                        messageCount: communication.messageCount,
                        administrator: communication.administrator,
                        operators: communication.operators,
                        members: communication.members,
                        metadata: communication.metadata,
                        blockedMembers: communication.blockedMembers,
                        communicationType: communication.communicationType))
                
                shouldUpdateCommunication = true
            } catch {
                
                communicationModel = try await createCommunicationModel(
                    recipients: [sender],
                    communicationType: decodedMessage.recipient,
                    metadata: decodedMessage.metadata,
                    symmetricKey: databaseSymmetricKey)
                
                try await cache.createCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: [mySecretName])
            }
            
            let messageModel = try await createInboundMessageModel(
                decodedMessage: decodedMessage,
                inboundTask: inboundTask,
                sendersSecretName: sender,
                senderDeviceId: inboundTask.senderDeviceId,
                session: session,
                communication: communicationModel,
                sessionIdentity: sessionIdentity
            )
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: [mySecretName])
            }
            
            try await cache.createMessage(messageModel, symmetricKey: databaseSymmetricKey)
            
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
        case .channel(_):
            
            let sender = inboundTask.senderSecretName
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            
            //Channel Models need to be created before a message is sent or received
            communicationModel = try await findCommunicationType(
                cache: cache,
                communicationType: decodedMessage.recipient,
                session: session
            )
            
            guard var newProps = await communicationModel.props(symmetricKey: databaseSymmetricKey) else { return }
            newProps.messageCount += 1
            _ = try await communicationModel.updateProps(symmetricKey: databaseSymmetricKey, props: newProps)
            shouldUpdateCommunication = true
            
            let messageModel = try await createInboundMessageModel(
                decodedMessage: decodedMessage,
                inboundTask: inboundTask,
                sendersSecretName: sender,
                senderDeviceId: inboundTask.senderDeviceId,
                session: session,
                communication: communicationModel,
                sessionIdentity: sessionIdentity
            )
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
            }
            try await cache.createMessage(messageModel, symmetricKey: databaseSymmetricKey)
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
            
        case .broadcast:
            //Broadcast messages are not persiseted yet
            break
        }
    }
    
    /// Verifies and decrypts an encrypted message received in an inbound task.
    /// This method extracts the ratchet message and the associated session identity
    /// from the inbound task, ensuring that the message is valid and can be processed.
    ///
    /// - Parameters:
    ///   - session: The current `CryptoSession` in which the message verification is taking place.
    ///   - inboundTask: The `InboundTaskMessage` containing the encrypted message to be verified.
    /// - Returns: A tuple containing the verified `RatchetMessage` and the associated `SessionIdentity`.
    /// - Throws: An error if the verification or decryption fails due to issues such as invalid message format,
    ///           session errors, or decryption errors.
    private func verifyEncryptedMessage(
        session: CryptoSession,
        inboundTask: InboundTaskMessage
    ) async throws -> (RatchetMessage, SessionIdentity) {
        
        let identities = try await session.refreshIdentities(secretName: inboundTask.senderSecretName)
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        
        guard let sessionIdentity = await identities.asyncFirst(where: { identity in
            guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else { return false }
            return props.deviceId == inboundTask.senderDeviceId
        }) else {
            //If we did not have an identity we need to create it
            throw JobProcessorErrors.missingIdentity
        }
        
        // Unwrap properties and retrieve the public signing key
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else { throw JobProcessorErrors.missingIdentity }
        let sendersPublicSigningKey = try Curve25519SigningPublicKey(rawRepresentation: props.publicSigningKey)
        
        // Verify the signature
        guard let signedMessage = inboundTask.message.signed else {
            throw CryptoSession.SessionErrors.missingSignature
        }
        
        let isSignatureValid = try signedMessage.verifySignature(publicKey: sendersPublicSigningKey)
        // If the signature is valid, decode and return the EncryptedMessage
        if isSignatureValid {
            let document = Document(data: signedMessage.data)
            return (try BSONDecoder().decode(RatchetMessage.self, from: document), sessionIdentity)
        } else {
            //If this happens the public key is not the same as the one that signed it or the data has been tampered with
            throw CryptoSession.SessionErrors.invalidSignature
        }
    }
    
    /// Signs a ratchet message using the cryptographic session's signing capabilities.
    /// This method ensures the integrity and authenticity of the ratchet message by applying a digital signature.
    ///
    /// - Parameters:
    ///   - message: The `RatchetMessage` that needs to be signed.
    ///   - session: The current `CryptoSession` used to access the signing keys and perform the signing operation.
    /// - Returns: A `SignedRatchetMessage` that contains the original ratchet message along with its digital signature.
    /// - Throws: An error if the signing process fails due to issues such as missing signing keys,
    ///           session errors, or cryptographic errors.
    func signRatchetMessage(message: RatchetMessage, session: CryptoSession) async throws -> SignedRatchetMessage {
        guard let deviceKeys = await session.sessionContext?.sessionUser.deviceKeys else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        return try SignedRatchetMessage(
            message: message,
            privateSigningKey: deviceKeys.privateSigningKey)
    }
}

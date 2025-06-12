//
//  JobProcessor.swift
//  post-quantum-solace
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
    func updateSessionIdentity(_ identity: DoubleRatchetKit.SessionIdentity) async throws {
        try await session?.cache?.updateSessionIdentity(identity)
    }
    
    /// Fetches a private one-time key by its identifier.
    /// - Parameter id: The UUID of the one-time key to fetch.
    /// - Returns: The corresponding private one-time key.
    /// - Throws: `CryptoSession.SessionErrors.sessionNotInitialized` if the session is not initialized,
    ///           or `CryptoSession.SessionErrors.invalidKeyId` if the key ID is invalid.
    func fetchPrivateOneTimeKey(_ id: UUID?) async throws -> DoubleRatchetKit.Curve25519PrivateKeyRepresentable? {
        guard let sessionContext = await session?.sessionContext else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        guard let key = sessionContext.sessionUser.deviceKeys.privateOneTimeKeys.first(where: { $0.id == id }) else {
            return nil
        }
        return key
    }
    
    /// Updates the one-time key for the current session.
    /// - Throws: `CryptoSession.SessionErrors.sessionNotInitialized` if the session is not initialized.
    ///           Logs an error if the update fails.
    func updateOneTimeKey(remove id: UUID) async {
        //If we do not detach then the ratchet encrypt takes too long due to the network
        updateKeyTasks.append(Task(executorPreference: keyTransportExecutor) { [weak self] in
            guard let self else { return }
            do {
                guard let session = await self.session else {
                    throw CryptoSession.SessionErrors.sessionNotInitialized
                }
                guard var sessionContext = await session.sessionContext else {
                    throw CryptoSession.SessionErrors.sessionNotInitialized
                }
                
                let newID = UUID()
                let keypair = crypto.generateCurve25519PrivateKey()
                let privateKeyRep = try Curve25519PrivateKeyRepresentable(id: newID, keypair.rawRepresentation)
                let publicKey = try Curve25519PublicKeyRepresentable(id: newID, keypair.publicKey.rawRepresentation)
                
                var deviceKeys = sessionContext.sessionUser.deviceKeys
                deviceKeys.privateOneTimeKeys.removeAll { $0.id == id }
                deviceKeys.privateOneTimeKeys.append(privateKeyRep)
                
                sessionContext.sessionUser.deviceKeys = deviceKeys
                sessionContext.updateSessionUser(sessionContext.sessionUser)
                
                guard var signedKeys = await session
                    .sessionContext?
                    .lastUserConfiguration
                    .signedPublicOneTimeKeys
                else { return }
                
                let signingKey = try Curve25519SigningPrivateKey(rawRepresentation: sessionContext.sessionUser.deviceKeys.privateSigningKey)
                let newSignedKey = try UserConfiguration.SignedPublicOneTimeKey(key: publicKey, deviceId: sessionContext.sessionUser.deviceId, signingKey: signingKey)
                
                signedKeys.removeAll { $0.id == id }
                signedKeys.append(newSignedKey)
                
                // Update the user configuration with the new signed keys
                sessionContext.lastUserConfiguration.signedPublicOneTimeKeys = signedKeys
                await session.setSessionContext(sessionContext)
                
                // Encrypt and persist
                let encodedData = try BSONEncoder().encodeData(sessionContext)
                guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: session.getAppSymmetricKey()) else {
                    throw CryptoSession.SessionErrors.sessionEncryptionError
                }
                
                try await session.cache?.updateLocalSessionContext(encryptedConfig)
                
                try await session.transportDelegate?.updateOneTimeKeys(
                    for: sessionContext.sessionUser.secretName,
                    deviceId: sessionContext.sessionUser.deviceId.uuidString,
                    keys: [newSignedKey])
                await cancelAndRemoveUpdateKeyTasks()
            } catch {
                await cancelAndRemoveUpdateKeyTasks()
                self.logger.log(level: .error, message: "Failed to update one time key: \(error)")
            }
        })
    }
    
    
    private func cancelAndRemoveUpdateKeyTasks() async {
        guard !updateKeyTasks.isEmpty else { return }
        let item = updateKeyTasks.removeFirst()
        item.cancel()
    }
    
    private func cancelAndRemoveDeleteKeyTasks() async {
        guard !deleteKeyTasks.isEmpty else { return }
        let item = deleteKeyTasks.removeFirst()
        item.cancel()
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
        
        guard let sessionIdentity = try await session.cache?.fetchSessionIdentities().first(where: { $0.id == outboundTask.recipientIdentity.id }) else {
            throw CryptoSession.SessionErrors.missingSessionIdentity
        }
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw CryptoSession.SessionErrors.propsError
        }
        
        var localPrivateOneTimeKey: Curve25519PrivateKeyRepresentable?
        var remotePublicOneTimeKey: Curve25519PublicKeyRepresentable?
        var localPrivateKyberKey: Kyber1024PrivateKeyRepresentable
        
        if props.state == nil {
            if let privateOneTimeKey = sessionContext.sessionUser.deviceKeys.privateOneTimeKeys.last {
                localPrivateOneTimeKey = privateOneTimeKey
            }
            
            if let remotePublicOneTimeKeyData = props.publicOneTimeKey {
                remotePublicOneTimeKey = remotePublicOneTimeKeyData
            }
            
            if let privateKyberOneTimeKey = sessionContext.sessionUser.deviceKeys.privateKyberOneTimeKeys.last {
                localPrivateKyberKey = privateKyberOneTimeKey
            } else {
                localPrivateKyberKey = sessionContext.sessionUser.deviceKeys.finalKyberPrivateKey
            }
        } else {
            guard let state = props.state else {
                throw CryptoError.propsError
            }
            remotePublicOneTimeKey = state.remotePublicOneTimeKey
            localPrivateOneTimeKey = state.localPrivateOneTimeKey
            localPrivateKyberKey = state.localKyber1024PrivateKey
        }
        try await ratchetManager.senderInitialization(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: databaseSymmetricKey,
            remoteKeys: RemoteKeys(
                longTerm: .init(props.publicLongTermKey),
                oneTime: remotePublicOneTimeKey,
                kyber: props.kyber1024PublicKey),
            localKeys: LocalKeys(
                longTerm: .init(sessionContext.sessionUser.deviceKeys.privateLongTermKey),
                oneTime: localPrivateOneTimeKey,
                kyber: localPrivateKyberKey))
        
        if props.state == nil {
            try await removeUsedKeys(
                session: session,
                sessionContext: sessionContext,
                localPrivateOneTimeKey: localPrivateOneTimeKey,
                localPrivateKyberKey: localPrivateKyberKey)
        }
        
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
        
        for stashed in stashedMessages {

            let (ratchetMessage, sessionIdentity) = try await verifyEncryptedMessage(session: session, inboundTask: stashed.task)
            
            guard let sessionIdentity = try await session.cache?.fetchSessionIdentities().first(where: { $0.id == sessionIdentity.id }) else {
                throw CryptoSession.SessionErrors.missingSessionIdentity
            }
            
            try await initializeRecipient(
                sessionIdentity: sessionIdentity,
                session: session,
                ratchetMessage: ratchetMessage)
            
            
            guard let decryptedData = try? await ratchetManager.ratchetDecrypt(ratchetMessage) else {
                continue
            }
            
            
            let decodedMessage = try BSONDecoder().decode(CryptoMessage.self, from: Document(data: decryptedData))
            var canSaveMessage = true
            
            if let sessionDelegate = await session.sessionDelegate {
                canSaveMessage = try await sessionDelegate.processUnpersistedMessage(
                    decodedMessage,
                    senderSecretName: inboundTask.senderSecretName,
                    senderDeviceId: inboundTask.senderDeviceId)
            }
            
            if canSaveMessage {
                /// Now we can handle the message
                try await handleDecodedMessage(
                    decodedMessage,
                    inboundTask: inboundTask,
                    session: session,
                    sessionIdentity: sessionIdentity)
            }
            stashedMessages.remove(stashed)
        }
        
        let (ratchetMessage, sessionIdentity) = try await verifyEncryptedMessage(session: session, inboundTask: inboundTask)
        
        do {
            guard let sessionIdentity = try await session.cache?.fetchSessionIdentities().first(where: { $0.id == sessionIdentity.id }) else {
                throw CryptoSession.SessionErrors.missingSessionIdentity
            }
            
            try await initializeRecipient(
                sessionIdentity: sessionIdentity,
                session: session,
                ratchetMessage: ratchetMessage)
            
            let decryptedData = try await ratchetManager.ratchetDecrypt(ratchetMessage)
            
            
            let decodedMessage = try BSONDecoder().decode(CryptoMessage.self, from: Document(data: decryptedData))
            var canSaveMessage = true
            
            if let sessionDelegate = await session.sessionDelegate {
                canSaveMessage = try await sessionDelegate.processUnpersistedMessage(
                    decodedMessage,
                    senderSecretName: inboundTask.senderSecretName,
                    senderDeviceId: inboundTask.senderDeviceId)
            }
            
            if canSaveMessage {
                /// Now we can handle the message
                try await handleDecodedMessage(
                    decodedMessage,
                    inboundTask: inboundTask,
                    session: session,
                    sessionIdentity: sessionIdentity)
            }
        } catch {
            if let ratchetError = error as? RatchetError {
                switch ratchetError {
                case .initialMessageNotReceived:
                    stashedMessages.insert(StashedTask(task: inboundTask))
                default:
                    throw ratchetError
                }
            } else {
                throw error
            }
        }
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
    ) async throws {
        self.session = session
        guard let sessionContext = await session.sessionContext else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        
        var localPrivateOneTimeKey: Curve25519PrivateKeyRepresentable?
        var localPrivateKyberKey: Kyber1024PrivateKeyRepresentable
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw CryptoError.propsError
        }
        if props.state == nil {
            if let privateOneTimeKey = sessionContext.sessionUser.deviceKeys.privateOneTimeKeys.first(where: { $0.id == ratchetMessage.header.curveOneTimeKeyId }) {
                localPrivateOneTimeKey = privateOneTimeKey
            }
            if let privateKyberOneTimeKey = sessionContext.sessionUser.deviceKeys.privateKyberOneTimeKeys.first(where: { $0.id == ratchetMessage.header.kyberOneTimeKeyId}) {
                localPrivateKyberKey = privateKyberOneTimeKey
            } else {
                localPrivateKyberKey = sessionContext.sessionUser.deviceKeys.finalKyberPrivateKey
            }
        } else {
            guard let state = props.state else {
                throw CryptoError.propsError
            }
            localPrivateOneTimeKey = state.localPrivateOneTimeKey
            localPrivateKyberKey = state.localKyber1024PrivateKey
        }
        
        try await ratchetManager.recipientInitialization(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: databaseSymmetricKey,
            remoteKeys: RemoteKeys(
                longTerm: .init(ratchetMessage.header.remotePublicLongTermKey),
                oneTime: ratchetMessage.header.remotePublicOneTimeKey,
                kyber: ratchetMessage.header.remoteKyber1024PublicKey),
            localKeys: LocalKeys(
                longTerm: .init(sessionContext.sessionUser.deviceKeys.privateLongTermKey),
                oneTime: localPrivateOneTimeKey,
                kyber: localPrivateKyberKey))
        
        if props.state == nil {
            try await removeUsedKeys(
                session: session,
                sessionContext: sessionContext,
                localPrivateOneTimeKey: localPrivateOneTimeKey,
                localPrivateKyberKey: localPrivateKyberKey)
        }
    }
    
    
    private func removeUsedKeys(
        session: CryptoSession,
        sessionContext: SessionContext,
        localPrivateOneTimeKey: Curve25519PrivateKeyRepresentable?,
        localPrivateKyberKey: Kyber1024PrivateKeyRepresentable
    ) async throws {
        if let curveId = localPrivateOneTimeKey?.id.uuidString {
            try await delegate?.deleteOneTimeKeys(for: sessionContext.sessionUser.secretName, with: curveId, type: .curve)
        }
        try await delegate?.deleteOneTimeKeys(for: sessionContext.sessionUser.secretName, with: localPrivateKyberKey.id.uuidString, type: .kyber)
        
        guard let localIdentityData = try await session.cache?.findLocalSessionContext() else {
            fatalError()
        }
        
        guard let configurationData = try await crypto.decrypt(data: localIdentityData, symmetricKey: session.getAppSymmetricKey()) else {
            fatalError()
        }
        
        // Decode the session context from the decrypted data
        var fetchedContext = try BSONDecoder().decode(SessionContext.self, from: Document(data: configurationData))
        if let curveId = localPrivateOneTimeKey?.id.uuidString {
            fetchedContext.lastUserConfiguration.signedPublicOneTimeKeys.removeAll(where: { $0.id.uuidString == curveId })
            fetchedContext.sessionUser.deviceKeys.privateOneTimeKeys.removeAll(where: { $0.id.uuidString == curveId })
            
        }
        fetchedContext.lastUserConfiguration.signedPublicKyberOneTimeKeys.removeAll(where: { $0.id.uuidString == localPrivateKyberKey.id.uuidString })
        fetchedContext.sessionUser.deviceKeys.privateKyberOneTimeKeys.removeAll(where: { $0.id.uuidString == localPrivateKyberKey.id.uuidString })
        
        
        let encodedContext = try BSONEncoder().encodeData(fetchedContext)
        guard let encryptedData = try await crypto.encrypt(data: encodedContext, symmetricKey: session.getAppSymmetricKey()) else {
            fatalError()
        }
        
        try await session.cache?.updateLocalSessionContext(encryptedData)
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
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw JobProcessorErrors.missingIdentity
        }
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

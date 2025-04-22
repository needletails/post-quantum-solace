//
//  JobProcessor.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//

import BSON
import Foundation
import NeedleTailLogger
import NeedleTailAsyncSequence
import NeedleTailCrypto
import DoubleRatchetKit
import Crypto
import SessionModels
import SessionEvents

extension TaskProcessor {

    func performRatchet(
        task: TaskType,
        session: CryptoSession
    ) async throws {
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

    //Outbound
    private func handleWriteMessage(
        outboundTask: OutboundTaskMessage,
        session: CryptoSession
    ) async throws {
        var outboundTask = outboundTask
        self.logger.log(level: .debug, message: "Performing Ratchet")
        
        guard let sessionContext = await session.sessionContext else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }

        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        guard let props = await outboundTask.recipientIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw CryptoSession.SessionErrors.propsError
        }
        
        let recipientPublicKeyRepresentable = props.publicKeyRepesentable
        let recipientPublicKey = try Curve25519PublicKey(rawRepresentation: recipientPublicKeyRepresentable)
        let secretName = props.secretName
        
        let symmetricKey = try await deriveSymmetricKey(
            for: secretName,
            my: sessionContext.sessionUser.deviceKeys.privateKey,
            their: recipientPublicKey
        )
        
        try await ratchetManager.senderInitialization(
            sessionIdentity: outboundTask.recipientIdentity,
            secretKey: symmetricKey,
            sessionSymmetricKey: databaseSymmetricKey,
            recipientPublicKey: recipientPublicKey)

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
    
    //Inbound
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

    /// Derives a symmetric key for secure communication using the Curve25519 key agreement protocol.
    ///
    /// This method takes the private key of the current device and the public key of the session user
    /// to compute a shared secret. The shared secret is then used to derive a symmetric key using
    /// HKDF (HMAC-based Key Derivation Function) with a specified salt and shared info.
    ///
    /// - Parameters:
    ///   - sessionUser: The `SessionUser` object containing the device's private key and other user-specific information.
    ///   - publicKey: The `Curve25519PublicKey` of the other party (the other session user) with whom the symmetric key will be shared.
    ///
    /// - Throws:
    ///   - An error of type `CryptoKitError` if the key agreement or key derivation fails. This can occur if the
    ///     provided public key is invalid or if there are issues with the private key representation.
    ///
    /// - Returns:
    ///   A `SymmetricKey` derived from the shared secret, which can be used for encryption and decryption
    ///   in secure communication.
    private func deriveSymmetricKey(
        for secretName: String,
        my privateKeyRespresentation: Data,
        their publicKey: Curve25519PublicKey
    ) async throws -> SymmetricKey {
        let privateKey = try Curve25519PrivateKey(rawRepresentation: privateKeyRespresentation)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let salt = Data(SHA512.hash(data: secretName.data(using: .ascii)!))
        
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA512.self,
            salt: salt,
            sharedInfo: "X3DHTemporaryReplacement".data(using: .ascii)!,
            outputByteCount: 32
        )
    }
    
    private func initializeRecipient(
        sessionIdentity: SessionIdentity,
        session: CryptoSession,
        ratchetMessage: RatchetMessage
    ) async throws -> Data {
        guard let sessionUser = await session.sessionContext?.sessionUser else {
            throw JobProcessorErrors.missingIdentity
        }
        
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else { throw JobProcessorErrors.missingIdentity }
        
        let sendersPublicKeyRepresentable = props.publicKeyRepesentable
        let symmetricKey = try await deriveSymmetricKey(
            for: sessionUser.secretName,
            my: sessionUser.deviceKeys.privateKey,
            their: try Curve25519PublicKey(rawRepresentation: sendersPublicKeyRepresentable)
        )
        
        let localPrivateKey = try Curve25519PrivateKey(rawRepresentation: sessionUser.deviceKeys.privateKey)
        
        return try await ratchetManager.recipientInitialization(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: databaseSymmetricKey,
            secretKey: symmetricKey,
            localPrivateKey: localPrivateKey,
            initialMessage: ratchetMessage
        )
    }
    
    /// This only handles Private Messages desipite their Communication Type. The Recipient is for reference in looking up communication models, but is not actually persisted. On initial creation of the Communication Model we need to tell it the needed metadata. If it is not on the decoded recipient and the communicationModel is not already existing, then it should be in the message metadata. like the members, admin, organizers, etc.
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
        let sendersPublicSigningKey = try Curve25519SigningPublicKey(rawRepresentation: props.publicSigningRepresentable)
        
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
    
    
    //TODO: Do we need to rekey? If a message fails to decrypted what does that indicate? Is rekeying really the proper option. Or do we have larger issues?
    func signRatchetMessage(message: RatchetMessage, session: CryptoSession) async throws -> SignedRatchetMessage {
        guard let deviceKeys = await session.sessionContext?.sessionUser.deviceKeys else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        return try SignedRatchetMessage(
            message: message,
            privateSigningKey: deviceKeys.privateSigningKey)
    }
}

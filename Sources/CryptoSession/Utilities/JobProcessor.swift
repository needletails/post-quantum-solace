//
//  JobProcessor.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//

import BSON
import Foundation
import NeedleTailAsyncSequence
import NeedleTailLogger
import DequeModule
import NIOConcurrencyHelpers
import NeedleTailCrypto
import DoubleRatchetKit
@preconcurrency import Crypto

enum JobPriority: Sendable {
    case delayed, background, urgent, standard
}


enum TaskType: Codable & Sendable {
    case streamMessage(InboundTaskMessage), writeMessage(OutboundTaskMessage)
}

struct EncrytableTask: Codable & Sendable {
    let task: TaskType
    let priority: Priority
    let scheduledAt: Date
    
    init(
        task: TaskType,
        priority: Priority = .standard,
        scheduledAt: Date = Date()
    ) {
        self.task = task
        self.priority = priority
        self.scheduledAt = scheduledAt
    }
}
extension Priority: Codable {}


extension NeedleTailAsyncConsumer{
    
    func loadAndOrganizeJobs(_ job: JobModel) async {
        //TODO: Delayed Tasks
        
        //        let originalDeque: Deque<TaskJob<T>> = deque
        //        var deque = Deque<TaskJob<_DecryptedModel<JobModel>>>()
        //
        //        for taskJob in originalDeque {
        //            if let decryptedModel = taskJob.item as? _DecryptedModel<JobModel> {
        //                let newTaskJob = TaskJob<_DecryptedModel<JobModel>>(item: decryptedModel, priority: .standard)
        //                deque.append(newTaskJob)
        //            }
        //        }
        //
        //        //1. Check if we are a delayed task. If we are delayed we want to hold off sending this task until the appointed time.
        //        if let delayedUntil = await job.delayedUntil, delayedUntil <= Date() {
        //            //Send delayed task to back of the deque
        //            await feedConsumer(job as! T, priority: .background)
        //            return
        //        } else if let delayedUntil = await job.delayedUntil, delayedUntil >= Date() {
        //            // We are at the appointed time, or past the appointed time send delayed task to the front of the deque
        //            await feedConsumer(job as! T, priority: .urgent)
        //            return
        //        }
        //
        //        //2. Check if background task. If we are background send the message after scheduled but before delayed
        //        if await job.isBackgroundTask {
        //        // We are not a delayed task. We are a specififed background task. Send the message to the back of the deque, but before delayed tasks.
        //            await feedConsumer(job as! T, priority: .background)
        //            return
        //        }
        //
        //
        //            //3. Send all messages. We are neither delayed or background so we are a scheduled task. Organize and send.
        //           // Iterate through the deque to find the correct insertion point
        guard let props = await job.props else { fatalError() }
        let currentSequenceId = props.sequenceId
        let isDelayed = props.delayedUntil != nil
        if !props.isBackgroundTask || !isDelayed {
            // We order messages according to a sequence. This way if we have a message created at the same time order is still kept.
            if props.sequenceId >= currentSequenceId {
                await feedConsumer(job as! T, priority: props.task.priority)
                return
            } else if props.sequenceId < currentSequenceId {
                //if We are an old message try first
                await feedConsumer(job as! T, priority: props.task.priority)
                return
            }
        }
        
        // We are an empty deque and are not a background or delayed task
        if self.deque.isEmpty {
            await feedConsumer(job as! T, priority: .standard)
        }
    }
}

final class JobProcessor: @unchecked Sendable {
    
    let logger = NeedleTailLogger()
    let jobConsumer = NeedleTailAsyncConsumer<JobModel>()
    var sequenceId = 0
    var isRunning = false
    let lock = NIOLock()
    
    func setIsRunning(_ isRunning: Bool) {
        lock.lock()
        defer {
            lock.unlock()
        }
        self.isRunning = isRunning
    }
    func incrementId() {
        lock.lock()
        defer {
            lock.unlock()
        }
        sequenceId += 1
    }
    
    func loadJobs(_ job: JobModel? = nil, cache: SessionCache) async throws {
        if let job = job {
            await jobConsumer.loadAndOrganizeJobs(job)
        } else {
            for job in try await cache.readJobs() {
                await jobConsumer.loadAndOrganizeJobs(job)
            }
        }
    }
    
    func createJobModel(
        sequenceId: Int,
        task: EncrytableTask,
        symmetricKey: SymmetricKey
    ) throws -> JobModel {
        try JobModel(
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
    
    
    //TODO: DO BATCH LOADING
    public func queueTask(_
                          task: EncrytableTask,
                          session: CryptoSession) async throws {
        
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        incrementId()
        let symmetricKey = try await session.getAppSymmetricKey(password: session.appPassword)
        let job = try createJobModel(
            sequenceId: sequenceId,
            task: task,
            symmetricKey: symmetricKey)
        await jobConsumer.loadAndOrganizeJobs(job)
        try await cache.createJob(job)
        try await attemptTaskSequence(session: session)
    }
    
    /// This method processes each job via an AsyncSequence that has been arrange per queue requirements. Rather than spinning off an unstructured Task at the root of the call and then a detached task to run jobs. we use 1 child task from the current task running this actor. This allows us to keep track and control of task cancellation. It also helps us to reason about task execution serialization more easily.
    func attemptTaskSequence(session: CryptoSession) async throws {
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        if !isRunning {
            logger.log(level: .debug, message: "Starting job queue")
            isRunning = true
            try await withThrowingTaskGroup(of: Void.self) { [weak self] group in
                guard let self else { fatalError() }
                group.addTask { [weak self] in
                    guard let self else { fatalError() }
                    for try await result in NeedleTailAsyncSequence(consumer: jobConsumer) {
                        switch result {
                        case .success(let job):
                            guard let props = await job.props else { fatalError() }
                            logger.log(level: .debug, message: "Running job \(props.sequenceId)")
                            
                            //TODO: Handle If offline
                            if session.isViable == false {
                                logger.log(level: .debug, message: "Skipping job \(props.sequenceId) as we are offline")
                                await jobConsumer.loadAndOrganizeJobs(job)
                                return
                            }
                            
                            if let delayedUntil = props.delayedUntil, delayedUntil >= Date() {
                                logger.log(level: .debug, message: "Task was delayed into the future")
                                
                                //This is urgent, We want to try this job first always until the designated time arrives. we sort via sequenceId. so old messages are always done first.
                                await jobConsumer.loadAndOrganizeJobs(job)
                                if await jobConsumer.deque.count == 0 {
                                    setIsRunning(false)
                                }
                                break
                            }
                            
                            
                            do {
                                logger.log(level: .debug, message: "Executing Job \(props.sequenceId)")
                                
                                try await performRatchet(
                                    task: props.task.task,
                                    session: session
                                )
                                
                                try await cache.removeJob(job)
                            } catch {
                                logger.log(level: .error, message: "Job error \(error)")
                                
                                //TODO: Work in delay logic on fail
                                
                                if await jobConsumer.deque.count == 0 {
                                    setIsRunning(false)
                                }
                            }
                            
                            if await jobConsumer.deque.count == 0 {
                                setIsRunning(false)
                                try await loadJobs(nil, cache: cache)
                            }
                        case .consumed:
                            await consumedSequence()
                            setIsRunning(false)
                            try await loadJobs(nil, cache: cache)
                        }
                    }
                }
                try await group.next()
                if await jobConsumer.deque.count == 0 {
                    setIsRunning(false)
                }
            }
        }
    }
    
    func consumedSequence() async {
        logger.log(level: .debug, message: "No jobs to run")
        //TODO: Clean up
    }
    
    enum JobProcessorErrors: Error {
        case missingIdentity
    }
    
    let ratchetManager = RatchetStateManager<SHA256>.shared
    
    private func performRatchet(
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
    
    private func handleWriteMessage(
        outboundTask: OutboundTaskMessage,
        session: CryptoSession
    ) async throws {
        logger.log(level: .debug, message: "Performing Ratchet")
        
        guard let sessionContext = await session.sessionContext else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        
        let sessionUser = sessionContext.sessionUser
        guard let cache = await session.cache else {
            throw CryptoSession.SessionErrors.databaseNotInitialized
        }
        
        guard let sessionIdentity = try await fetchSessionIdentity(for: outboundTask, cache: cache) else {
            throw JobProcessorErrors.missingIdentity
        }
        
        guard let recipientPublicKeyRepresentable = await sessionIdentity.props?.publicKeyRepesentable else { fatalError() }
        let recipientPublicKey = try Curve25519PublicKey(rawRepresentation: recipientPublicKeyRepresentable)
        guard let secretName = await sessionIdentity.props?.secretName else { fatalError() }
        
        let symmetricKey = try await deriveSymmetricKey(
            for: secretName,
            my: sessionUser.deviceKeys.privateKey,
            their: recipientPublicKey
        )
        
        try await ratchetManager.senderInitialization(
            deviceIdentity: sessionIdentity,
            secretKey: symmetricKey,
            recipientPublicKey: recipientPublicKey)
        
        let encodedData = try BSONEncoder().encodeData(outboundTask.message)
        let ratchetedMessage = try await ratchetManager.ratchetEncrypt(plainText: encodedData)
        let signedMessage = try await signRatchetMessage(message: ratchetedMessage, session: session)
        
        try await session.transportDelegate?.sendMessage(
            signedMessage,
            to: sessionUser.secretName,
            with: sessionUser.deviceIdentity,
            pushType: outboundTask.message.pushType,
            remoteId: outboundTask.sharedMessageIdentity
        )
    }
    
    private func handleStreamMessage(
        inboundTask: InboundTaskMessage,
        session: CryptoSession
    ) async throws {
        guard let cache = await session.cache else {
            throw CryptoSession.SessionErrors.databaseNotInitialized
        }
        
        let (encryptedMessage, sessionIdentity) = try await verifyEncryptedMessage(cache: cache, inboundTask: inboundTask)
        
        guard let identityProps = await sessionIdentity.props else { fatalError() }
        
        let decryptedData: Data
        if identityProps.state != nil {
            decryptedData = try await ratchetManager.ratchetDecrypt(encryptedMessage)
        } else {
            decryptedData = try await initializeRecipient(
                sessionIdentity: sessionIdentity,
                session: session,
                encryptedMessage: encryptedMessage
            )
        }
        
        let decodedMessage = try BSONDecoder().decode(CryptoMessage.self, from: Document(data: decryptedData))
        guard let sessionContext = await session.sessionContext else { throw CryptoSession.SessionErrors.sessionNotInitialized }
        
        //Decryption has occured
        switch decodedMessage.messageType {
            
            //Don't Save received Message
        case .nudgeLocal:
            //TODO: Is this valid for channel communications????? Or do we place it in the Private Message case???? We do not save this message!!!!
            switch decodedMessage.messageFlags {
            case .friendshipStateRequest:
                // Create/Update Contact and modify metadata
                
                var decodedMetadata = try BSONDecoder().decode(FriendshipMetadata.self, from: decodedMessage.metadata)
                //Switch states mine is theirs and theirs is mine
                decodedMetadata.switchStates()
                let encodedMetadata = try BSONEncoder().encode(decodedMetadata)
                //Create or update contact including new metadata
                _ = try await session.createContact(secretName: sessionContext.sessionUser.secretName, metadata: encodedMetadata)
            case .deliveryStateChange:
                let decodedMetadata = try BSONDecoder().decode(DeliverStateMetadata.self, from: decodedMessage.metadata)
                let symmetricKey = try await session.getAppSymmetricKey(password: session.appPassword)
                let foundMessage = try await cache.fetchMessage(by: decodedMetadata.messageId)
                guard var props = await foundMessage.props else { fatalError() }
                props.deliveryState = decodedMetadata.state
                _ = try await foundMessage.updateProps(symmetricKey: symmetricKey, props: props)
                await session.receiverDelegate?.updatedMessage(foundMessage)
            case .editMessage:
                let symmetricKey = try await session.getAppSymmetricKey(password: session.appPassword)
                let foundMessage = try await cache.fetchMessage(by: inboundTask.sharedMessageIdentity)
                guard var props = await foundMessage.props else { fatalError() }
                props.message = decodedMessage
                _ = try await foundMessage.updateProps(symmetricKey: symmetricKey, props: props)
                await session.receiverDelegate?.updatedMessage(foundMessage)
            case .none:
                break
            }
            // Save
        default:
            /// Now we can handle the message
            try await handleDecodedMessage(
                decodedMessage,
                inboundTask: inboundTask,
                session: session,
                sessionIdentity: sessionIdentity
            )
        }
    }
    
    func fetchSessionIdentity(for
                              outboundTask: OutboundTaskMessage,
                              cache: SessionCache
    ) async throws -> SessionIdentityModel? {
        for identity in try await cache.fetchSessionIdentities() {
            guard let props = await identity.props else { fatalError() }
            if props.secretName == outboundTask.recipientSecretName, props.deviceIdentity == outboundTask.recipientDeviceIdentity {
                return identity
            }
        }
        return nil
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
    func deriveSymmetricKey(
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
        sessionIdentity: SessionIdentityModel,
        session: CryptoSession,
        encryptedMessage: EncryptedMessage
    ) async throws -> Data {
        guard let sessionUser = await session.sessionContext?.sessionUser else {
            throw JobProcessorErrors.missingIdentity
        }
        
        guard let sendersPublicKeyRepresentable = await sessionIdentity.props?.publicKeyRepesentable else { fatalError() }
        
        let symmetricKey = try await deriveSymmetricKey(
            for: sessionUser.secretName,
            my: sessionUser.deviceKeys.privateKey,
            their: try Curve25519PublicKey(rawRepresentation: sendersPublicKeyRepresentable)
        )
        
        let localPrivateKey = try Curve25519PrivateKey(rawRepresentation: sessionUser.deviceKeys.privateKey)
        
        return try await ratchetManager.recipientInitialization(
            deviceIdentity: sessionIdentity,
            secretKey: symmetricKey,
            localPrivateKey: localPrivateKey,
            initialMessage: encryptedMessage
        )
    }
    
    private func handleDecodedMessage(_
                                      decodedMessage: CryptoMessage,
                                      inboundTask: InboundTaskMessage,
                                      session: CryptoSession,
                                      sessionIdentity: SessionIdentityModel
    ) async throws {
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        switch decodedMessage.recipient {
        case .nickname(let recipient):
            let sender = inboundTask.senderSecretName
            
            let symmetricKey = try await session.getAppSymmetricKey(password: session.appPassword)
            var communicationModel: CommunicationModel
            var shouldUpdateCommunication = false
            do {
                communicationModel = try await findCommunicationType(
                    for: recipient,
                    sender: sender,
                    cache: cache
                )
                
                guard var newProps = await communicationModel.props else { fatalError() }
                newProps.messageCount += 1
                _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: newProps)
                shouldUpdateCommunication = true
            } catch {
                communicationModel = try await createCommunicationModel(
                    recipients: [sender, recipient],
                    metadata: decodedMessage.metadata,
                    symmetricKey: symmetricKey
                )
                try await cache.createCommunication(communicationModel)
            }
            
            let messageModel = try await createInboundMessageModel(
                decodedMessage: decodedMessage,
                inboundTask: inboundTask,
                session: session,
                communication: communicationModel,
                sessionIdentity: sessionIdentity
            )
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
            }
            try await cache.createMessage(messageModel)
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
        case .channel, .broadcast, .personalMessage:
            break
        }
    }
    
    internal func createCommunicationModel(
        recipients: Set<String>,
        metadata: Document,
        symmetricKey: SymmetricKey
    ) async throws -> CommunicationModel {
        return try CommunicationModel(
            props: .init(
                messageCount: 0,
                members: recipients,
                metadata: metadata,
                blockedMembers: []
            ),
            symmetricKey: symmetricKey
        )
    }
    
    internal func findCommunicationType(
        for recipient: String,
        sender: String,
        cache: SessionCache
    ) async throws -> CommunicationModel {
        guard let foundCommunication = try await cache.fetchCommunications().asyncFirst(where: { model in
            guard let props = await model.props else { fatalError() }
            return props.members.contains(recipient) && props.members.contains(sender)
        }) else {
            throw CryptoSession.SessionErrors.cannotFindCommunication // Replace with your specific error type
        }
        
        return foundCommunication
    }
    
    private func createInboundMessageModel(
        decodedMessage: CryptoMessage,
        inboundTask: InboundTaskMessage,
        session: CryptoSession,
        communication: CommunicationModel,
        sessionIdentity: SessionIdentityModel
    ) async throws -> MessageModel {
        guard let identityProps = await sessionIdentity.props else { fatalError() }
        guard let communicationProps = await communication.props else {
            throw CryptoSession.SessionErrors.cannotFindCommunication
        }
        
        let newMessageCount = communicationProps.messageCount + 1
        let symmetricKey = try await session.getAppSymmetricKey(password: session.appPassword)
        let messageModel = try await MessageModel(
            communicationID: communication.id,
            senderIdentity: identityProps.senderIdentity,
            sharedMessageIdentity: UUID().uuidString,
            sequenceId: newMessageCount,
            props: .init(
                base: communication,
                sendDate: decodedMessage.sentDate,
                deliveryState: .received,
                message: decodedMessage,
                sendersSecretName: inboundTask.senderSecretName,
                sendersIdentity: inboundTask.senderDeviceIdentity
            ),
            symmetricKey: symmetricKey
        )
        var newProps = communicationProps
        newProps.messageCount = newMessageCount
        _ = try await communication.updateProps(symmetricKey: symmetricKey, props: newProps)
        try await session.cache?.updateCommunication(communication)
        return messageModel
    }
    
    private func verifyEncryptedMessage(cache: SessionCache, inboundTask: InboundTaskMessage) async throws -> (EncryptedMessage, SessionIdentityModel) {
        // Fetch identities from the session cache
        let identities = try await cache.fetchSessionIdentities()
        
        // Filter to find the matching identity based on senderSecretName
        let sessionSpecificIdentities = await identities.asyncFilter { identity in
            guard let props = await identity.props else { fatalError() }
            return props.secretName == inboundTask.senderSecretName
        }
        
        // Find the corresponding device identity
        guard let sessionIdentity = await sessionSpecificIdentities.asyncFirst(where: { identity in
            guard let props = await identity.props else { fatalError() }
            return props.deviceIdentity == inboundTask.senderDeviceIdentity
        }) else {
            throw CryptoSession.SessionErrors.missingSessionIdentity
        }
        
        // Unwrap properties and retrieve the public signing key
        guard let unwrappedProps = await sessionIdentity.props else { fatalError() }
        let sendersPublicSigningKey = try Curve25519SigningPublicKey(rawRepresentation: unwrappedProps.publicSigningRepresentable)
        
        // Verify the signature
        guard let signedMessage = inboundTask.message.signed else {
            throw CryptoSession.SessionErrors.missingSignature
        }
        
        let isSignatureValid = try signedMessage.verifySignature(publicKey: sendersPublicSigningKey)
        // If the signature is valid, decode and return the EncryptedMessage
        if isSignatureValid {
            let document = Document(data: signedMessage.data)
            return (try BSONDecoder().decode(EncryptedMessage.self, from: document), sessionIdentity)
        } else {
            //If this happens the public key is not the  same as the one that signed it or the data has been tampered with
            throw CryptoSession.SessionErrors.invalidSignature
        }
    }
    
    
    //TODO: Do we need to rekey? If a message fails to decrypted what does that indicate? Is rekeying really the proper option. Or do we have larger issues?
    func signRatchetMessage(message: EncryptedMessage, session: CryptoSession) async throws -> SignedRatchetMessage {
        guard let deviceKeys = await session.sessionContext?.sessionUser.deviceKeys else { throw CryptoSession.SessionErrors.sessionNotInitialized }
        return try SignedRatchetMessage(
            message: message,
            privateSigningKey: deviceKeys.privateSigningKey)
    }
}

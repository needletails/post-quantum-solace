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
    
    func loadAndOrganizeJobs(_ job: JobModel, symmetricKey: SymmetricKey) async {
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
        guard let props = await job.props(symmetricKey: symmetricKey) else { fatalError() }
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
    
    func loadJobs(_
                  job: JobModel? = nil,
                  cache: SessionCache,
                  symmetricKey: SymmetricKey,
                  session: CryptoSession? = nil
    ) async throws {
        if let job = job {
            await jobConsumer.loadAndOrganizeJobs(job, symmetricKey: symmetricKey)
            if let session = session {
                try await attemptTaskSequence(session: session)
            }
        } else {
            for job in try await cache.readJobs() {
                await jobConsumer.loadAndOrganizeJobs(job, symmetricKey: symmetricKey)
                if let session = session {
                    try await attemptTaskSequence(session: session)
                }
            }
        }
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
    
    
    //TODO: DO BATCH LOADING
    public func queueTask(_
                          task: EncrytableTask,
                          session: CryptoSession) async throws {
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        incrementId()
        let symmetricKey = try await session.getAppSymmetricKey()
        let job = try createJobModel(
            sequenceId: sequenceId,
            task: task,
            symmetricKey: symmetricKey)
        await jobConsumer.loadAndOrganizeJobs(job, symmetricKey: symmetricKey)
        try await cache.createJob(job)
        try await attemptTaskSequence(session: session)
    }
    
    /// This method processes each job via an AsyncSequence that has been arrange per queue requirements. Rather than spinning off an unstructured Task at the root of the call and then a detached task to run jobs. we use 1 child task from the current task running this actor. This allows us to keep track and control of task cancellation. It also helps us to reason about task execution serialization more easily.
    func attemptTaskSequence(session: CryptoSession) async throws {
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        if !isRunning {
            await self.logger.log(level: .debug, message: "Starting job queue")
            isRunning = true
            let symmetricKey = try await session.getAppSymmetricKey()
            for try await result in NeedleTailAsyncSequence(consumer: jobConsumer) {
                switch result {
                case .success(let job):
                    
                    guard let props = await job.props(symmetricKey: symmetricKey) else { fatalError() }
                    await self.logger.log(level: .debug, message: "Running job \(props.sequenceId)")
                    
                    if session.isViable == false {
                        await self.logger.log(level: .debug, message: "Skipping job \(props.sequenceId) as we are offline")
                        await jobConsumer.loadAndOrganizeJobs(job, symmetricKey: symmetricKey)
                        isRunning = false
                        return
                    }
                    
                    if let delayedUntil = props.delayedUntil, delayedUntil >= Date() {
                        await self.logger.log(level: .debug, message: "Task was delayed into the future")
                        
                        //This is urgent, We want to try this job first always until the designated time arrives. we sort via sequenceId. so old messages are always done first.
                        await jobConsumer.loadAndOrganizeJobs(job, symmetricKey: symmetricKey)
                        if await jobConsumer.deque.count == 0 {
                            setIsRunning(false)
                        }
                        break
                    }
                    
                    do {
                        await self.logger.log(level: .debug, message: "Executing Job \(props.sequenceId)")
                        
                        try await performRatchet(
                            task: props.task.task,
                            session: session)
                        
                        try await cache.removeJob(job)
                    } catch {
                        await self.logger.log(level: .error, message: "Job error \(error)")
                        
                        //TODO: Work in delay logic on fail
                        
                        if await jobConsumer.deque.count == 0 || Task.isCancelled {
                            setIsRunning(false)
                            return
                        }
                    }
                    
                    if await jobConsumer.deque.count == 0 {
                        setIsRunning(false)
                        try await loadJobs(nil, cache: cache, symmetricKey: symmetricKey)
                    }
                case .consumed:
                    let symmetricKey = try await session.getAppSymmetricKey()
                    await consumedSequence()
                    setIsRunning(false)
                    try await loadJobs(nil, cache: cache, symmetricKey: symmetricKey)
                }
            }
        }
        if await jobConsumer.deque.count == 0 {
            setIsRunning(false)
        }
    }
    
    func consumedSequence() async {
        await self.logger.log(level: .debug, message: "No jobs to run")
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
    
    //Outbound
    private func handleWriteMessage(
        outboundTask: OutboundTaskMessage,
        session: CryptoSession
    ) async throws {
        await self.logger.log(level: .debug, message: "Performing Ratchet")
        
        guard let sessionContext = await session.sessionContext else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        
        guard let cache = await session.cache else {
            throw CryptoSession.SessionErrors.databaseNotInitialized
        }
        
        guard let sessionIdentity = try await fetchSessionIdentity(
            for: outboundTask,
            cache: cache,
            session: session
        ) else {
            throw JobProcessorErrors.missingIdentity
        }
        
        let appSymmetricKey = try await session.getAppSymmetricKey()
        guard let props = await sessionIdentity.props(symmetricKey: appSymmetricKey) else {
            throw JobProcessorErrors.missingIdentity
        }
        
        let recipientPublicKeyRepresentable = props.publicKeyRepesentable
        let recipientPublicKey = try Curve25519PublicKey(rawRepresentation: recipientPublicKeyRepresentable)
        let secretName = await props.secretName
        
        let symmetricKey = try await deriveSymmetricKey(
            for: secretName,
            my: sessionContext.sessionUser.deviceKeys.privateKey,
            their: recipientPublicKey
        )
        
        try await ratchetManager.senderInitialization(
            sessionIdentity: sessionIdentity,
            secretKey: symmetricKey,
            sessionSymmetricKey: appSymmetricKey,
            recipientPublicKey: recipientPublicKey)
        
        //Remove file locations before sending
        var outboundTask = outboundTask
        if outboundTask.message.messageType == .media {
            outboundTask.message.metadata["fileLocation"] = ""
            outboundTask.message.metadata["thumbnailLocation"] = ""
        }
        
        let encodedData = try BSONEncoder().encodeData(outboundTask.message)
        let ratchetedMessage = try await ratchetManager.ratchetEncrypt(plainText: encodedData)
        let signedMessage = try await signRatchetMessage(message: ratchetedMessage, session: session)

        try await session.transportDelegate?.sendMessage(
            signedMessage,
            metadata: SignedRatchetMessageMetadata(
                secretName: outboundTask.recipientSecretName,
                deviceId: outboundTask.recipientDeviceId,
                pushType: outboundTask.message.pushType,
                sharedMessageIdentifier: outboundTask.sharedId,
                messageType: outboundTask.message.messageType,
                messageFlags: outboundTask.message.messageFlags,
                recipient: outboundTask.message.recipient
            ))
    }
    
    
    //Inbound
    private func handleStreamMessage(
        inboundTask: InboundTaskMessage,
        session: CryptoSession
    ) async throws {
        guard let cache = await session.cache else {
            throw CryptoSession.SessionErrors.databaseNotInitialized
        }
        
        let (encryptedMessage, sessionIdentity) = try await verifyEncryptedMessage(session: session, inboundTask: inboundTask)
        
        let appSymmetricKey = try await session.getAppSymmetricKey()
        guard let props = await sessionIdentity.props(symmetricKey: appSymmetricKey) else {
            throw JobProcessorErrors.missingIdentity
        }
        
        let decryptedData: Data
        if props.state != nil {
            decryptedData = try await ratchetManager.ratchetDecrypt(encryptedMessage)
        } else {
            decryptedData = try await initializeRecipient(
                sessionIdentity: sessionIdentity,
                session: session,
                encryptedMessage: encryptedMessage
            )
        }
        
        let decodedMessage = try BSONDecoder().decode(CryptoMessage.self, from: Document(data: decryptedData))
        
        //Decryption has occured
        switch decodedMessage.messageType {
            //Don't Save received Message
        case .nudgeLocal:
            switch decodedMessage.messageFlags {
            case .friendshipStateRequest(let data):
                // Create/Update Contact and modify metadata
                var decodedMetadata = try BSONDecoder().decode(FriendshipMetadata.self, from: decodedMessage.metadata["friendshipMetadata"] as? Document ?? [:])
                //Update our state based on the state of the sender and it's metadata.
                switch decodedMetadata.theirState {
                case .pending:
                    decodedMetadata.revokeFriendRequest()
                case .requested:
                    decodedMetadata.sendFriendRequest()
                case .accepted:
                    decodedMetadata.acceptFriendRequest()
                case .blocked, .blockedUser:
                    decodedMetadata.blockFriend()
                case .unblock:
                    decodedMetadata.unBlockFriend()
                case .rejectedRequest, .friendshipRejected, .rejected:
                    decodedMetadata.rejectFriendRequest()
                }
                
                let encodedMetadata = try BSONEncoder().encode(["friendshipMetadata": decodedMetadata])
                
                //Create or update contact including new metadata
                _ = try await session.updateOrCreateContact(
                    secretName: inboundTask.senderSecretName,
                    metadata: encodedMetadata,
                    needsSynchronization: false
                )
            case .deliveryStateChange:
                do {
                    let decodedMetadata = try BSONDecoder().decode(DeliveryStateMetadata.self, from: decodedMessage.metadata)
                    let symmetricKey = try await session.getAppSymmetricKey()
                    let foundMessage = try await cache.fetchMessage(by: decodedMetadata.sharedId)
                    
                    let appSymmetricKey = try await session.getAppSymmetricKey()
                    guard var props = await foundMessage.props(symmetricKey: appSymmetricKey) else { throw JobProcessorErrors.missingIdentity }
                    props.deliveryState = decodedMetadata.state
                    _ = try await foundMessage.updateProps(symmetricKey: symmetricKey, props: props)
                    try await cache.updateMessage(foundMessage, symmetricKey: appSymmetricKey)
                    await session.receiverDelegate?.updatedMessage(foundMessage)
                } catch {
                    await self.logger.log(level: .error, message: "Error Changing Delivery State: \(error)")
                }
            case .editMessage:
                do {
                    let decodedMetadata = try BSONDecoder().decode(EditMessageMetadata<String>.self, from: decodedMessage.metadata)
                    let foundMessage = try await cache.fetchMessage(by: decodedMetadata.sharedId)
                    let appSymmetricKey = try await session.getAppSymmetricKey()
                    guard var props = await foundMessage.props(symmetricKey: appSymmetricKey) else { throw JobProcessorErrors.missingIdentity }
                    props.message.text = decodedMetadata.value
                    _ = try await foundMessage.updateProps(symmetricKey: appSymmetricKey, props: props)
                    try await cache.updateMessage(foundMessage, symmetricKey: appSymmetricKey)
                    await session.receiverDelegate?.updatedMessage(foundMessage)
                } catch {
                    await self.logger.log(level: .error, message: "Error Editing Message: \(error)")
                }
            case .editMessageMetadata(let key):
                do {
                    let appSymmetricKey = try await session.getAppSymmetricKey()
                    
                    //We receive messsage metadata, this is not the actual prrivate messages metadata yet. We will insert it into the CryptoMessage's metadata after decoding
                    let receivedMetadata = try BSONDecoder().decode([EditMessageMetadata<Data>].self, from: decodedMessage.metadata)
                    
                    //1. Find this current message's metadata
                    guard let newReaction = receivedMetadata.first(where: { $0.sender == inboundTask.senderSecretName }) else { return }
                    let foundMessage = try await cache.fetchMessage(by: newReaction.sharedId)
                    
                    let decryptedMessage = try await foundMessage.makeDecryptedModel(of: _PrivateMessage.self, symmetricKey: appSymmetricKey)
                    
                    var currentMetadata = [EditMessageMetadata<Data>]()
                    
                    do {
                        let binary: Binary = try decryptedMessage.message.metadata.decode(forKey: key)
                        currentMetadata = try BSONDecoder().decode([EditMessageMetadata<Data>].self, from: Document(data: binary.data))
                    } catch {}
                    
                    if let reaction = currentMetadata.first(where: { $0.sender == inboundTask.senderSecretName }) {
                        currentMetadata.removeAll(where: { $0.sender == inboundTask.senderSecretName })
                        currentMetadata.append(EditMessageMetadata(value: newReaction.value, sharedId: newReaction.sharedId, sender: newReaction.sender))
                    } else {
                        currentMetadata.append(EditMessageMetadata(value: newReaction.value, sharedId: newReaction.sharedId, sender: newReaction.sender))
                    }
                    
                    let newMetadata = try BSONEncoder().encode(currentMetadata)
                    _ = try await foundMessage.updatePropsMetadata(
                        symmetricKey: appSymmetricKey,
                        metadata: newMetadata.makeData(),
                        with: key)
                    try await cache.updateMessage(foundMessage, symmetricKey: appSymmetricKey)
                    await session.receiverDelegate?.updatedMessage(foundMessage)
                } catch {
                    await self.logger.log(level: .error, message: "Error Updating Message Metadata: \(error)")
                }
                //This updates our communication Model for us locally on Inbound writes
            case .communicationSynchronization:
                guard !decodedMessage.text.isEmpty else { return }
                await self.logger.log(level: .debug, message: "Received Communication Synchronization Message")
                let symmetricKey = try await session.getAppSymmetricKey()
                
                //This can happen on multidevice support when a sender is also sending a message to it's master/child device.
                let isMe = await inboundTask.senderSecretName == session.sessionContext?.sessionUser.secretName
                
                var communicationModel: BaseCommunication?
                do {
                    //Need to flop sender/recipient
                    communicationModel = try await findCommunicationType(
                        cache: cache,
                        communicationType: .nickname(isMe ? decodedMessage.recipient.nicknameDescription : inboundTask.senderSecretName),
                        session: session
                    )
                } catch {
                    //Need to flop sender/recipient
                    communicationModel = try await createCommunicationModel(
                        recipients: [decodedMessage.recipient.nicknameDescription, inboundTask.senderSecretName],
                        communicationType: .nickname(isMe ? decodedMessage.recipient.nicknameDescription : inboundTask.senderSecretName),
                        metadata: decodedMessage.metadata,
                        symmetricKey: symmetricKey
                    )
                    guard let communicationModel = communicationModel else { return }
                    try await cache.createCommunication(communicationModel)
                }
                
                guard let communicationModel = communicationModel else { return }
                await self.logger.log(level: .debug, message: "Found Communication Model For Synchronization: \(communicationModel)")
                var props = try await communicationModel.props(symmetricKey: symmetricKey)
                props?.sharedId = UUID(uuidString: decodedMessage.text)
                try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
                try await cache.updateCommunication(communicationModel)
                if let members = props?.members {
                    try await session.receiverDelegate?.updatedCommunication(communicationModel, members: members)
                }
                await self.logger.log(level: .debug, message: "Updated Communication Model For Synchronization with Shared Id: \(props?.sharedId)")
            case .contactCreated:
                //This can happen on multidevice support when a sender is also sending a message to it's master/child device.
                let isMe = await inboundTask.senderSecretName == session.sessionContext?.sessionUser.secretName
                await self.logger.log(level: .debug, message: "Received Contact Request Recipient Created Contact Message")
                try await session.sendCommunicationSynchronization(contact: isMe ? decodedMessage.recipient.nicknameDescription : inboundTask.senderSecretName)
            case .addContacts:
                let contacts = try BSONDecoder().decode([CryptoSession.SharedContactInfo].self, from: decodedMessage.metadata)
                try await session.addContacts(contacts)
            case .revokeMessage:
                do {
                    let decodedMetadata = try BSONDecoder().decode(RevokeMessageMetadata.self, from: decodedMessage.metadata)
                    let symmetricKey = try await session.getAppSymmetricKey()
                    let foundMessage = try await cache.fetchMessage(by: decodedMetadata.sharedId)
                    _ = try await cache.removeMessage(foundMessage)
                    await session.receiverDelegate?.deletedMessage(foundMessage)
                } catch {
                    await self.logger.log(level: .error, message: "Error Revoking Message: \(error)")
                }
            case .dccSymmetricKey:
                //Stash the key on the connection for this user to retrieve later
                let decodedKey = try BSONDecoder().decode(SymmetricKey.self, from: decodedMessage.metadata)
                await session.receiverDelegate?.passDCCKey(decodedKey)
            default:
                //This can happen on multidevice support when a sender is also sending a message to it's master/child device.
                let isMe = await inboundTask.senderSecretName == session.sessionContext?.sessionUser.secretName
                //Passthrough nothing special to do
                await session.receiverDelegate?.receivedLocalNudge(decodedMessage, sender: isMe ? decodedMessage.recipient.nicknameDescription : inboundTask.senderSecretName)
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
                              cache: SessionCache,
                              session: CryptoSession
    ) async throws -> SessionIdentity? {
        for identity in try await cache.fetchSessionIdentities() {
            let appSymmetricKey = try await session.getAppSymmetricKey()
            guard var props = await identity.props(symmetricKey: appSymmetricKey) else { throw JobProcessorErrors.missingIdentity }
            if props.secretName == outboundTask.recipientSecretName, props.deviceId == outboundTask.recipientDeviceId {
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
        sessionIdentity: SessionIdentity,
        session: CryptoSession,
        encryptedMessage: EncryptedMessage
    ) async throws -> Data {
        guard let sessionUser = await session.sessionContext?.sessionUser else {
            throw JobProcessorErrors.missingIdentity
        }
        
        let appSymmetricKey = try await session.getAppSymmetricKey()
        guard var props = await sessionIdentity.props(symmetricKey: appSymmetricKey) else { throw JobProcessorErrors.missingIdentity }
       
        let sendersPublicKeyRepresentable = await props.publicKeyRepesentable
        let symmetricKey = try await deriveSymmetricKey(
            for: sessionUser.secretName,
            my: sessionUser.deviceKeys.privateKey,
            their: try Curve25519PublicKey(rawRepresentation: sendersPublicKeyRepresentable)
        )
        
        let localPrivateKey = try Curve25519PrivateKey(rawRepresentation: sessionUser.deviceKeys.privateKey)
        
        return try await ratchetManager.recipientInitialization(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: appSymmetricKey,
            secretKey: symmetricKey,
            localPrivateKey: localPrivateKey,
            initialMessage: encryptedMessage
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
        let appSymmetricKey = try await session.getAppSymmetricKey()
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
                    session: session
                )
                
                var communication = try await communicationModel.makeDecryptedModel(of: Communication.self, symmetricKey: appSymmetricKey)
                communication.messageCount += 1
                
                _ = try await communicationModel.updateProps(
                    symmetricKey: appSymmetricKey,
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
                    symmetricKey: appSymmetricKey
                )
                try await cache.createCommunication(communicationModel)
                try await session.receiverDelegate?.updatedCommunication(communicationModel, members: [recipient, inboundTask.senderSecretName])
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
                if let members = try await communicationModel.props(symmetricKey: session.getAppSymmetricKey())?.members {
                    try await session.receiverDelegate?.updatedCommunication(communicationModel, members: members)
                }
            }
            
            try await cache.createMessage(messageModel, symmetricKey: appSymmetricKey)
            let props = await messageModel.props(symmetricKey: appSymmetricKey)
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
        case .personalMessage:
            let sender = inboundTask.senderSecretName
            guard let mySecretName = await session.sessionContext?.sessionUser.secretName else { return }
            
            let appSymmetricKey = try await session.getAppSymmetricKey()
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            do {
                communicationModel = try await findCommunicationType(
                    cache: cache,
                    communicationType: decodedMessage.recipient,
                    session: session
                )
                
                var communication = try await communicationModel.makeDecryptedModel(of: Communication.self, symmetricKey: appSymmetricKey)
                communication.messageCount += 1
                
                _ = try await communicationModel.updateProps(
                    symmetricKey: appSymmetricKey,
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
                    symmetricKey: appSymmetricKey)
                
                try await cache.createCommunication(communicationModel)
                try await session.receiverDelegate?.updatedCommunication(communicationModel, members: [mySecretName])
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
                try await session.receiverDelegate?.updatedCommunication(communicationModel, members: [mySecretName])
            }
            
            try await cache.createMessage(messageModel, symmetricKey: appSymmetricKey)
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
        case .channel(let channelName):
            
            let sender = inboundTask.senderSecretName
            
            let symmetricKey = try await session.getAppSymmetricKey()
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            
            //Channel Models need to be created before a message is sent or received
            communicationModel = try await findCommunicationType(
                cache: cache,
                communicationType: decodedMessage.recipient,
                session: session
            )
            
            guard var newProps = await communicationModel.props(symmetricKey: symmetricKey) else { fatalError() }
            newProps.messageCount += 1
            _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: newProps)
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
            try await cache.createMessage(messageModel, symmetricKey: appSymmetricKey)
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
            
        case .broadcast:
            //Broadcast messages are not persiseted yet
            break
        }
    }
    
    internal func createCommunicationModel(
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
    
    internal func findCommunicationType(
        cache: SessionCache,
        communicationType: MessageRecipient,
        session: CryptoSession
    ) async throws -> BaseCommunication {
        let communications = try await cache.fetchCommunications()
        let symmetricKey = try await session.getAppSymmetricKey()
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
    
    private func createInboundMessageModel(
        decodedMessage: CryptoMessage,
        inboundTask: InboundTaskMessage,
        sendersSecretName: String,
        senderDeviceId: UUID,
        session: CryptoSession,
        communication: BaseCommunication,
        sessionIdentity: SessionIdentity
    ) async throws -> PrivateMessage {
        let symmetricKey = try await session.getAppSymmetricKey()
        guard var props = await sessionIdentity.props(symmetricKey: symmetricKey) else {
            throw JobProcessorErrors.missingIdentity
        }
        guard let communicationProps = await communication.props(symmetricKey: symmetricKey) else {
            throw CryptoSession.SessionErrors.propsError
        }
        
        let newMessageCount = communicationProps.messageCount + 1
        let messageModel = try await PrivateMessage(
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
    
    private func verifyEncryptedMessage(
        session: CryptoSession,
        inboundTask: InboundTaskMessage
    ) async throws -> (EncryptedMessage, SessionIdentity) {
        var identities = try await session.getSessionIdentities(with: inboundTask.senderSecretName)
        if identities.isEmpty {
            identities = try await session.refreshSessionIdentities(for: inboundTask.senderSecretName, from: [])
        }
        let appSymmetricKey = try await session.getAppSymmetricKey()

        guard let sessionIdentity = await identities.asyncFirst(where: { identity in
            guard var props = await identity.props(symmetricKey: appSymmetricKey) else { return false }
            return props.deviceId == inboundTask.senderDeviceId
        }) else {
            //If we did not have an identity we need to create it
            throw CryptoSession.SessionErrors.missingSessionIdentity
        }
        
        // Unwrap properties and retrieve the public signing key
        guard var props = await sessionIdentity.props(symmetricKey: appSymmetricKey) else { throw JobProcessorErrors.missingIdentity }
        let sendersPublicSigningKey = try Curve25519SigningPublicKey(rawRepresentation: props.publicSigningRepresentable)
        
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
            //If this happens the public key is not the same as the one that signed it or the data has been tampered with
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


extension Array {
    
    /// Asynchronously finds the first element in the array that satisfies the given predicate.
    ///
    /// This method iterates through the elements of the array and evaluates the provided asynchronous
    /// predicate for each element. If the predicate returns `true` for an element, that element is
    /// returned. If no elements satisfy the predicate, `nil` is returned.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the array and returns
    ///   a Boolean value indicating whether the element satisfies a certain condition. The closure
    ///   is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: The first element that satisfies the predicate, or `nil` if no such element is found.
    ///
    /// - Complexity: O(n), where n is the number of elements in the array. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with arrays of any type, as long as the type conforms
    ///   to the requirements of the predicate closure.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let numbers = [1, 3, 5, 7, 8, 10]
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     if let firstEven = await numbers.asyncFirst(where: isEven) {
    ///         print("The first even number is \(firstEven).") // Output: The first even number is 8.
    ///     } else {
    ///         print("No even number found.")
    ///     }
    /// }
    /// ```
    public func asyncFirst(where predicate: @Sendable (Element) async -> Bool) async -> Element? {
        for element in self {
            if await predicate(element) {
                return element
            }
        }
        return nil
    }
    
    public func asyncMap<T>(transform: @Sendable (Element) async -> T) async -> [T] {
        var results = [T]()
        for element in self {
            let result = await transform(element)
            results.append(result)
        }
        return results
    }
    
    public func asyncCompactMap<T>(transform: @Sendable (Element) async -> T?) async -> [T] {
        var results = [T]()
        for element in self {
            if let result = await transform(element) {
                results.append(result)
            }
        }
        return results
    }
    
    // Asynchronously finds the index of the first element in the array that satisfies the given predicate.
    ///
    /// This method iterates through the elements of the array and evaluates the provided asynchronous
    /// predicate for each element. If the predicate returns `true` for an element, the index of that
    /// element is returned. If no elements satisfy the predicate, `nil` is returned.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the array and returns
    ///   a Boolean value indicating whether the element satisfies a certain condition. The closure
    ///   is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: The index of the first element that satisfies the predicate, or `nil` if no such
    ///   element is found.
    ///
    /// - Complexity: O(n), where n is the number of elements in the array. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with arrays of any type, as long as the type conforms
    ///   to the requirements of the predicate closure.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let numbers = [1, 3, 5, 7, 8, 10]
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     if let index = await numbers.firstAsyncIndex(where: isEven) {
    ///         print("The first even number is at index \(index).") // Output: The first even number is at index 4.
    ///     } else {
    ///         print("No even number found.")
    ///     }
    /// }
    /// ```
    public func firstAsyncIndex(where predicate: @Sendable (Element) async -> Bool) async -> Int? {
        for (index, element) in self.enumerated() {
            if await predicate(element) {
                return index
            }
        }
        return nil
    }
    
    /// Asynchronously filters the array based on the given predicate.
    ///
    /// This method iterates through the elements of the array and evaluates the provided asynchronous
    /// predicate for each element. If the predicate returns `true` for an element, that element is
    /// included in the resulting array. The method returns a new array containing all elements that
    /// satisfy the predicate.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the array and returns
    ///   a Boolean value indicating whether the element should be included in the resulting array.
    ///   The closure is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: An array containing the elements that satisfy the predicate.
    ///
    /// - Complexity: O(n), where n is the number of elements in the array. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with arrays of any type, as long as the type conforms
    ///   to the requirements of the predicate closure.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let numbers = [1, 2, 3, 4, 5]
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     let evenNumbers = await numbers.asyncFilter(where: isEven)
    ///     print("Even numbers: \(evenNumbers)") // Output: Even numbers: [2, 4]
    /// }
    /// ```
    public func asyncFilter(_ predicate: @Sendable (Element) async -> Bool) async -> [Element] {
        var result: [Element] = []
        for element in self {
            if await predicate(element) {
                result.append(element)
            }
        }
        return result
    }
    
    
    /// Asynchronously removes all elements that satisfy the given predicate from the current array.
    ///
    /// This method evaluates the provided asynchronous predicate for each element in the array. If the
    /// predicate returns `true` for an element, that element is removed from the array. The method
    /// updates the current array to contain only the elements that do not satisfy the predicate.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the array and returns
    ///   a Boolean value indicating whether the element should be removed from the array. The closure
    ///   is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: This method does not return a value. It modifies the current array in place to
    ///   exclude the elements that satisfy the predicate.
    ///
    /// - Complexity: O(n), where n is the number of elements in the array. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with arrays of any type, as long as the type conforms
    ///   to the requirements of the predicate closure.
    ///
    /// ## Example
    ///
    /// ```swift
    /// var numbers = [1, 2, 3, 4, 5]
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     await numbers.asyncRemoveAll(where: isEven)
    ///     print("Remaining numbers: \(numbers)") // Output: Remaining numbers: [1, 3, 5]
    /// }
    /// ```
    public mutating func asyncRemoveAll(where predicate: @Sendable (Element) async -> Bool) async {
        // Create a new array with elements that should remain
        let filteredArray = await asyncFilter { element in
            await !predicate(element)
        }
        // Update the current array
        self = filteredArray
    }
    
    /// Asynchronously checks if the array contains an element that satisfies the given predicate.
    ///
    /// This method iterates through the elements of the array and evaluates the provided asynchronous
    /// predicate for each element. If the predicate returns `true` for any element, the method returns
    /// `true`. If no elements satisfy the predicate, the method returns `false`.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the array and returns
    ///   a Boolean value indicating whether the element satisfies a certain condition. The closure
    ///   is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: A Boolean value indicating whether the array contains an element that satisfies the
    ///   predicate.
    ///
    /// - Complexity: O(n), where n is the number of elements in the array. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with arrays of any type, as long as the type conforms
    ///   to the requirements of the predicate closure.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let numbers = [1, 2, 3, 4, 5]
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     let containsEven = await numbers.asyncContains(where: isEven)
    ///     print("Contains even number: \(containsEven)") // Output: Contains even number: true
    /// }
    /// ```
    public func asyncContains(where predicate: @Sendable (Element) async -> Bool) async -> Bool {
        for element in self {
            if await predicate(element) {
                return true
            }
        }
        return false
    }
    
}

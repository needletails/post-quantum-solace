//
//  TaskProcessor.swift
//  crypto-session
//
//  Created by Cole M on 4/8/25.
//
import Foundation
import Crypto
import BSON
import NeedleTailLogger
import NeedleTailAsyncSequence
import NeedleTailCrypto
import DoubleRatchetKit
import SessionEvents
import SessionModels

actor TaskProcessor {
    
    private let cryptoExecutor = CryptoExecutor(
        queue: DispatchQueue(label: "crypto-executor-queue"),
        shouldExecuteAsTask: false)
    
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        self.cryptoExecutor.asUnownedSerialExecutor()
    }
    
    let crypto = NeedleTailCrypto()
    let logger: NeedleTailLogger
    let jobConsumer: NeedleTailAsyncConsumer<JobModel>
    let ratchetManager: RatchetStateManager<SHA256>
    var sequenceId = 0
    var isRunning = false
    
    init(logger: NeedleTailLogger = NeedleTailLogger()) {
        self.logger = logger
        self.ratchetManager = RatchetStateManager<SHA256>(executor: self.cryptoExecutor.asUnownedSerialExecutor())
        self.jobConsumer = NeedleTailAsyncConsumer<JobModel>(logger: logger, executor: self.cryptoExecutor)
    }
    
    //MARK: Outbound
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
            recipients = recipients.union(members)
            
        case .broadcast:
            break
        }
        
        func getIdentity(secretName: String, deviceId: String) async -> SessionIdentity? {
            return await identities.asyncFirst(where: { identity in
                if
                    let props = await identity.props(symmetricKey: symmetricKey) {
                    if props.deviceId == UUID(uuidString: deviceId) && props.secretName == secretName {
                        return true
                    } else {
                        return false
                    }
                } else {
                    return false
                }
            })
        }
        
        
        if let sessionDelegate = await session.sessionDelegate {
            if let (secretName, deviceId) = try await sessionDelegate.getUserInfo(message.transportInfo) {
                if !deviceId.isEmpty && !secretName.isEmpty {
                    // When secretName is not empty, attempt to fetch the offer identity.
                    guard let offerIdentity = await getIdentity(
                        secretName: secretName,
                        deviceId: deviceId
                    ) else {
                        logger.log(level: .error, message: "Missing Offer Identity: \(secretName)")
                        return
                    }
                    identities = [offerIdentity]
                } else if secretName.isEmpty && !deviceId.isEmpty {
                    guard let offerIdentity = await getIdentity(
                        secretName: type.nicknameDescription,
                        deviceId: deviceId
                    ) else {
                        logger.log(level: .error, message: "Missing Offer Identity: \(secretName)")
                        return
                    }
                    identities = [offerIdentity]
                }
                // When secretName is empty, do nothing.
            } else {
                await identities.asyncRemoveAll { await $0.props(symmetricKey: symmetricKey)?.isMasterDevice == false }
            }
        }
        
        try await createEncryptableTask(
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
        let identities = try await session.refreshIdentities(secretName: sender)
        logger.log(level: .info, message: "Gathered \(identities.count) Personal Session Identities")
        return identities
    }
    
    private func gatherPrivateMessageIdentities(
        session: CryptoSession,
        target: String,
        logger: NeedleTailLogger
    ) async throws -> [SessionIdentity] {
        //Get Identities only for me
        let identities = try await session.refreshIdentities(secretName: target)
        logger.log(level: .info, message: "Gathered \(identities.count) Private Message Session Identities")
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
        do {
            communicationModel = try await findCommunicationType(
                cache: cache,
                communicationType: type,
                session: session
            )
            
            guard var newProps = await communicationModel.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
            newProps.messageCount += 1
            do {
                _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: newProps)
            } catch {
                throw CryptoSession.SessionErrors.propsError
            }
        } catch {
            throw CryptoSession.SessionErrors.cannotFindCommunication
        }
        
        
        //1. Collect Members of channel
        guard let props = await communicationModel.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
        let members = props.members
        
        var identities = [SessionIdentity]()
        //3. Double Ratchet for all memebers and their devices
        for member in members {
            identities.append(contentsOf: try await session.refreshIdentities(secretName: member))
        }
        logger.log(level: .info, message: "Gathered \(identities.count) Channel Session Identities")
        return (identities, members)
    }
    
    private func createEncryptableTask(for
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
        var encryptableMessage: EncryptedMessage?
        
        if shouldPersist {
            //1. Pass messages to be cached and saved on the local database
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            
            do {
                communicationModel = try await findCommunicationType(
                    cache: cache,
                    communicationType: message.recipient,
                    session: session)
                
                guard var newProps = await communicationModel.props(symmetricKey: symmetricKey) else {
                    throw CryptoSession.SessionErrors.propsError
                }
                
                newProps.messageCount += 1
                _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: newProps)
                shouldUpdateCommunication = true
                
            } catch {
                communicationModel = try await createCommunicationModel(
                    recipients: recipients,
                    communicationType: message.recipient,
                    metadata: message.metadata,
                    symmetricKey: symmetricKey)
                
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: recipients)
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
            
            if let unwrappedEncryptableMessage = encryptableMessage {
                encryptableMessage = try await session.sessionDelegate?.updateEncryptableMessageMetadata(
                    unwrappedEncryptableMessage,
                    transportInfo: message.transportInfo,
                    identity: identity,
                    recipient: message.recipient)
            }
            
            //Only Persist local
            if shouldPersist {
                guard let encryptableMessage else { return }
                guard let messageProps = await encryptableMessage.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
                
                task = EncrytableTask(
                    task: .writeMessage(OutboundTaskMessage(
                        message: messageProps.message,
                        recipientIdentity: identity,
                        localId: encryptableMessage.id,
                        sharedId: encryptableMessage.sharedId)))
            } else {
                if await session.sessionDelegate?.shouldFinishCommunicationSynchronization(message.transportInfo) == true {
                    //This updates our communication Model for us locally on outbound writes
                    guard !message.text.isEmpty else { return }
                    logger.log(level: .debug, message: "Requester Synchronizing Communication Message")
                    let communicationModel = try await findCommunicationType(
                        cache: cache,
                        communicationType: message.recipient,
                        session: session
                    )
                    logger.log(level: .debug, message: "Found Communication Model For Synchronization: \(communicationModel)")
                    var props = await communicationModel.props(symmetricKey: symmetricKey)
                    props?.sharedId = UUID(uuidString: message.text)
                    _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
                    try await cache.updateCommunication(communicationModel)
                    logger.log(level: .debug, message: "Updated Communication Model For Synchronization with Shared Id: \(String(describing: props?.sharedId))")
                }
                task = EncrytableTask(
                    task: .writeMessage(OutboundTaskMessage(
                        message: message,
                        recipientIdentity: identity,
                        localId: UUID(),
                        sharedId: UUID().uuidString)))
            }
            try await feedTask(task, session: session)
        }
    }
    
    //MARK: Inbound
    func inboundTask(_ message: InboundTaskMessage, session: CryptoSession) async throws {
        try await feedTask(
            EncrytableTask(task: .streamMessage(message)),
            session: session)
        
    }
}

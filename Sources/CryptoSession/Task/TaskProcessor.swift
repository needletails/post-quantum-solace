//
//  TaskProcessor.swift
//  post-quantum-solace
//
//  Created by Cole M on 4/8/25.
//

import Foundation
import Crypto
import NeedleTailLogger
import NeedleTailAsyncSequence
import NeedleTailCrypto
import DoubleRatchetKit
import SessionEvents
import SessionModels
import DequeModule

/// `TaskProcessor` manages the asynchronous execution of encryption and decryption tasks
/// using Double Ratchet and other cryptographic mechanisms. It handles inbound and outbound
/// messaging for sessions, including persistence, identity resolution, and communication state.
actor TaskProcessor {

    // MARK: - Properties

    /// Executor for running cryptographic tasks on a serial queue.
    private let cryptoExecutor = CryptoExecutor(
        queue: DispatchQueue(label: "com.needletails.crypto-executor-queue"),
        shouldExecuteAsTask: false
    )
    
    let keyTransportExecutor = CryptoExecutor(
        queue: DispatchQueue(label: "com.needletails.key-transport-executor-queue"),
        shouldExecuteAsTask: false
    )
    var updateKeyTasks: Deque<Task<Void, Never>> = []
    var deleteKeyTasks: Deque<Task<Void, Never>> = []

    /// The serial executor exposed to allow `Sendable` access to async work.
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        self.cryptoExecutor.asUnownedSerialExecutor()
    }

    /// The currently active session.
    var session: CryptoSession?

    /// Handles cryptographic operations (e.g. encryption/decryption).
    let crypto = NeedleTailCrypto()

    /// Logger for debugging and telemetry.
    let logger: NeedleTailLogger

    /// Consumer that asynchronously receives and handles jobs.
    let jobConsumer: NeedleTailAsyncConsumer<JobModel>

    /// Manages the Double Ratchet state.
    let ratchetManager: RatchetStateManager<SHA256>

    /// Internal message sequence tracker.
    var sequenceId = 0

    /// Indicates if the processor is actively running.
    var isRunning = false

    /// Delegate responsible for transport-level session communication.
    var delegate: (any SessionTransport)?
    
    struct StashedTask: Hashable, Sendable {
        let id = UUID()
        let task: InboundTaskMessage
        
        static func == (lhs: TaskProcessor.StashedTask, rhs: TaskProcessor.StashedTask) -> Bool {
            lhs.id == rhs.id
        }
        
        func hash(into hasher: inout Hasher) {
            hasher.combine(id)
        }
    }

    // MARK: - Initialization

    /// Creates a new task processor with optional logger injection.
    /// - Parameter logger: Custom logger instance, defaults to a basic logger.
    init(logger: NeedleTailLogger = NeedleTailLogger()) {
        self.logger = logger
        self.ratchetManager = RatchetStateManager<SHA256>(executor: self.cryptoExecutor)
        self.jobConsumer = NeedleTailAsyncConsumer<JobModel>(logger: logger, executor: self.cryptoExecutor)
    }

    /// Sets the session transport delegate.
    /// - Parameter delegate: An object conforming to `SessionTransport`.
    func setDelegate(_ delegate: (any SessionTransport)?) {
        self.delegate = delegate
    }

    // MARK: - Outbound Messaging

    /// Handles outbound message encryption and task dispatch.
    ///
    /// This function performs the following steps:
    /// 1. Resolves the appropriate session identities.
    /// 2. Filters and prioritizes recipient identities based on the message type.
    /// 3. Constructs and persists encrypted tasks.
    ///
    /// - Parameters:
    ///   - message: The message to encrypt and send.
    ///   - cache: A reference to the session's cache for communications.
    ///   - symmetricKey: Key used for encrypting communication metadata.
    ///   - session: The active session context.
    ///   - sender: Sender's identifier (typically their secret name).
    ///   - type: The recipient category (e.g., personal, nickname, channel).
    ///   - shouldPersist: Whether the message should be stored locally.
    ///   - logger: Logger instance for debug logging.
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
            identities = try await gatherPersonalIdentities(session: session, sender: sender, logger: logger)
            recipients.insert(sender)
        case .nickname(let nickname):
            identities = try await gatherPrivateMessageIdentities(session: session, target: nickname, logger: logger)
            recipients.formUnion([sender, nickname])
        case .channel(_):
            let (channelIdentities, members) = try await gatherChannelIdentities(
                cache: cache,
                session: session,
                symmetricKey: symmetricKey,
                type: type,
                logger: logger
            )
            identities = channelIdentities
            recipients.formUnion(members)
        case .broadcast:
            break
        }

        // Utility for selecting matching identities
        func getIdentity(secretName: String, deviceId: String) async -> SessionIdentity? {
            return await identities.asyncFirst { identity in
                guard let props = await identity.props(symmetricKey: symmetricKey) else { return false }
                return props.secretName == secretName && props.deviceId == UUID(uuidString: deviceId)
            }
        }

        // Filter identities based on delegate-supplied info
        if let sessionDelegate = await session.sessionDelegate {
            if let (secretName, deviceId) = try await sessionDelegate.getUserInfo(message.transportInfo) {
                if !deviceId.isEmpty {
                    let resolvedIdentity = await getIdentity(secretName: secretName.isEmpty ? type.nicknameDescription : secretName, deviceId: deviceId)
                    if let offerIdentity = resolvedIdentity {
                        identities = [offerIdentity]
                    } else {
                        logger.log(level: .error, message: "Missing Offer Identity: \(secretName)")
                        return
                    }
                }
            } else {
                await identities.asyncRemoveAll {
                    (await $0.props(symmetricKey: symmetricKey)?.isMasterDevice == false)
                }
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
            logger: logger
        )
    }

    // MARK: - Identity Resolution

    /// Fetches personal identities for the sender.
    private func gatherPersonalIdentities(session: CryptoSession, sender: String, logger: NeedleTailLogger) async throws -> [SessionIdentity] {
        let identities = try await session.refreshIdentities(secretName: sender)
        logger.log(level: .info, message: "Gathered \(identities.count) Personal Session Identities")
        return identities
    }

    /// Fetches identities for private (1:1) messages.
    private func gatherPrivateMessageIdentities(session: CryptoSession, target: String, logger: NeedleTailLogger) async throws -> [SessionIdentity] {
        let identities = try await session.refreshIdentities(secretName: target)
        logger.log(level: .info, message: "Gathered \(identities.count) Private Message Session Identities")
        return identities
    }

    /// Fetches all identities for channel messages.
    private func gatherChannelIdentities(
        cache: SessionCache,
        session: CryptoSession,
        symmetricKey: SymmetricKey,
        type: MessageRecipient,
        logger: NeedleTailLogger
    ) async throws -> ([SessionIdentity], Set<String>) {
        let communicationModel = try await findCommunicationType(cache: cache, communicationType: type, session: session)
        guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
            throw CryptoSession.SessionErrors.propsError
        }

        props.messageCount += 1
        _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)

        let members = props.members
        var identities = [SessionIdentity]()
        for member in members {
            identities.append(contentsOf: try await session.refreshIdentities(secretName: member))
        }

        logger.log(level: .info, message: "Gathered \(identities.count) Channel Session Identities")
        return (identities, members)
    }

    // MARK: - Message Encryption

    /// Encrypts and schedules a task for each recipient identity.
    private func createEncryptableTask(
        for sessionIdentities: [SessionIdentity],
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
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false

            do {
                communicationModel = try await findCommunicationType(cache: cache, communicationType: message.recipient, session: session)
                guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
                    throw CryptoSession.SessionErrors.propsError
                }
                props.messageCount += 1
                _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
                shouldUpdateCommunication = true
            } catch {
                communicationModel = try await createCommunicationModel(
                    recipients: recipients,
                    communicationType: message.recipient,
                    metadata: message.metadata,
                    symmetricKey: symmetricKey
                )
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: recipients)
            }

            let savedMessage = try await createOutboundMessageModel(
                message: message,
                communication: communicationModel,
                session: session,
                symmetricKey: symmetricKey,
                members: recipients,
                sharedId: UUID().uuidString,
                shouldUpdateCommunication: shouldUpdateCommunication
            )

            await session.receiverDelegate?.createdMessage(savedMessage)
            encryptableMessage = savedMessage
        }

        for identity in sessionIdentities {
            if let unwrappedEncryptableMessage = encryptableMessage {
                encryptableMessage = try await session.sessionDelegate?.updateEncryptableMessageMetadata(
                    unwrappedEncryptableMessage,
                    transportInfo: message.transportInfo,
                    identity: identity,
                    recipient: message.recipient)
            }

            if shouldPersist {
                guard let encryptableMessage else { return }
                guard let messageProps = await encryptableMessage.props(symmetricKey: symmetricKey) else {
                    throw CryptoSession.SessionErrors.propsError
                }

                task = EncrytableTask(
                    task: .writeMessage(OutboundTaskMessage(
                        message: messageProps.message,
                        recipientIdentity: identity,
                        localId: encryptableMessage.id,
                        sharedId: encryptableMessage.sharedId
                    ))
                )
            } else {
                if await session.sessionDelegate?.shouldFinishCommunicationSynchronization(message.transportInfo) == true {
                    guard !message.text.isEmpty else { return }

                    logger.log(level: .debug, message: "Requester Synchronizing Communication Message")
                    let communicationModel = try await findCommunicationType(
                        cache: cache,
                        communicationType: message.recipient,
                        session: session
                    )

                    var props = await communicationModel.props(symmetricKey: symmetricKey)
                    props?.sharedId = UUID(uuidString: message.text)
                    _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
                    try await cache.updateCommunication(communicationModel)

                    logger.log(level: .debug, message: "Updated Communication Model with Shared ID: \(String(describing: props?.sharedId))")
                }

                task = EncrytableTask(
                    task: .writeMessage(OutboundTaskMessage(
                        message: message,
                        recipientIdentity: identity,
                        localId: UUID(),
                        sharedId: UUID().uuidString
                    ))
                )
            }

            try await feedTask(task, session: session)
        }
    }

    // MARK: - Inbound Messaging

    /// Handles an inbound encrypted message by enqueuing it for decryption.
    ///
    /// - Parameters:
    ///   - message: The message received from the transport layer.
    ///   - session: The current crypto session used to decrypt and dispatch.
    func inboundTask(_ message: InboundTaskMessage, session: CryptoSession) async throws {
        try await feedTask(
            EncrytableTask(task: .streamMessage(message)),
            session: session
        )
    }
}

//
//  TaskProcessor.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-04-08.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.

import DequeModule
import DoubleRatchetKit
import Foundation
import NeedleTailAsyncSequence
import SessionEvents
import SessionModels
import Crypto

/// `TaskProcessor` manages the asynchronous execution of encryption and decryption tasks
/// using Double Ratchet and other cryptographic mechanisms. It handles inbound and outbound
/// messaging for sessions, including persistence, identity resolution, and communication state.
///
/// This actor uses custom executors to ensure cryptographic operations are performed serially
/// on dedicated queues, preventing timing attacks and maintaining security properties.
///
/// ## Key Features
/// - **Actor Isolation**: Uses Swift's actor model for thread-safe access to mutable state
/// - **Custom Executors**: Dedicated serial queues for cryptographic and key transport operations
/// - **Double Ratchet**: Implements secure messaging with post-quantum cryptography
/// - **Message Persistence**: Optional local storage of encrypted messages
/// - **Identity Management**: Automatic resolution and refresh of session identities
/// - **Job Queue**: Asynchronous task processing with proper sequencing
///
/// ## Concurrency Model
/// - All actor methods run on the actor's serial executor by default
/// - Cryptographic operations use `cryptoExecutor` (serial queue)
/// - Key transport operations use `keyTransportExecutor` (separate serial queue)
/// - External code can access async capabilities via `unownedExecutor`
///
/// ## Usage
/// ```swift
/// let processor = TaskProcessor(logger: customLogger)
/// try await processor.outboundTask(message, cache: cache, symmetricKey: key, ...)
/// ```
///
/// ## Security Considerations
/// - Cryptographic operations are performed on dedicated serial queues to prevent timing attacks
/// - Sensitive data is never logged or exposed in error messages
/// - Keys are managed securely and never persisted in plain text
/// - Message ordering is preserved to maintain cryptographic properties
/// - Actor isolation prevents concurrent access to mutable state
public actor TaskProcessor {
    // MARK: - Properties

    /// Executor for running cryptographic tasks on a serial queue.
    /// Used for message encryption/decryption and ratchet operations.
    /// All cryptographic work is serialized to prevent timing attacks.
    private let cryptoExecutor = CryptoExecutor(
        queue: DispatchQueue(label: "com.needletails.crypto-executor-queue"),
        shouldExecuteAsTask: false
    )

    /// Executor for key transport operations on a separate serial queue.
    /// Used for key exchange, rotation, and deletion operations.
    /// Separated from message processing to prevent blocking.
    let keyTransportExecutor = CryptoExecutor(
        queue: DispatchQueue(label: "com.needletails.key-transport-executor-queue"),
        shouldExecuteAsTask: false
    )

    /// Queue of tasks for updating cryptographic keys.
    /// These tasks run on the key transport executor to avoid blocking message processing.
    var updateKeyTasks: Deque<Task<Void, Never>> = []

    /// Queue of tasks for deleting cryptographic keys.
    /// These tasks run on the key transport executor for proper cleanup.
    var deleteKeyTasks: Deque<Task<Void, Never>> = []

    /// The serial executor exposed to allow `Sendable` access to async work.
    /// External code can use this to schedule work on the cryptographic executor
    /// while maintaining actor isolation for the processor's state.
    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        cryptoExecutor.asUnownedSerialExecutor()
    }

    /// The currently active session.
    /// This is set by the session manager and contains the current cryptographic context.
    var session: PQSSession?

    /// Handles cryptographic operations (e.g. encryption/decryption).
    /// Provides a unified interface for all cryptographic primitives used by the processor.
    let crypto = NeedleTailCrypto()

    /// Logger for debugging, telemetry, and audit trails.
    /// All sensitive data is filtered before logging to prevent information leakage.
    var logger: NeedleTailLogger

    /// Consumer that asynchronously receives and handles jobs for processing.
    /// Manages the job queue with proper sequencing and error handling.
    let jobConsumer: NeedleTailAsyncConsumer<JobModel>

    /// Manages the Double Ratchet state for secure messaging.
    /// Handles key derivation, message encryption/decryption, and ratchet advancement.
    let ratchetManager: RatchetStateManager<SHA256>

    /// Internal message sequence tracker for job ordering.
    /// Ensures that jobs are processed in the correct order to maintain cryptographic properties.
    var sequenceId = 0

    /// Indicates if the processor is actively running jobs.
    /// Used to prevent multiple concurrent job processing loops.
    var isRunning = false

    /// Delegate responsible for transport-level session communication.
    /// Handles the actual sending and receiving of encrypted messages over the network.
    var delegate: (any SessionTransport)?
    
    var taskDelegate: TaskSequenceDelegate?

    /// Represents a stashed inbound task for later processing.
    ///
    /// This struct is used to temporarily store inbound messages that cannot be processed
    /// immediately, typically due to missing cryptographic context or identity information.
    /// The tasks are processed later when the required context becomes available.
    ///
    /// - Note: This struct is `Sendable` and `Hashable` for safe use in concurrent collections.
    /// - Warning: Stashed tasks should be processed promptly to avoid memory accumulation.
    public struct StashedTask: Hashable, Sendable {
        /// Unique identifier for the stashed task.
        /// Used for deduplication and task tracking.
        let id = UUID()

        /// The inbound task message to be processed.
        /// Contains the encrypted message and metadata needed for decryption.
        let task: InboundTaskMessage

        /// Equality comparison based on task ID.
        /// - Parameters:
        ///   - lhs: Left-hand side of the comparison
        ///   - rhs: Right-hand side of the comparison
        /// - Returns: `true` if the tasks have the same ID, `false` otherwise
        public static func == (lhs: TaskProcessor.StashedTask, rhs: TaskProcessor.StashedTask) -> Bool {
            lhs.id == rhs.id
        }

        /// Generates a hash value for the task.
        /// - Parameter hasher: The hasher to use for generating the hash value
        public func hash(into hasher: inout Hasher) {
            hasher.combine(id)
        }
    }

    // MARK: - Initialization

    /// Creates a new task processor with optional logger injection.
    ///
    /// The processor is initialized with custom executors and a job queue
    /// ready to handle message processing tasks. The ratchet manager and job consumer
    /// are configured to use the cryptographic executor for serialized operations.
    ///
    /// - Parameter logger: Custom logger instance, defaults to a basic logger.
    ///   The logger is used for debugging, telemetry, and audit trails.
    /// - Note: The processor is not ready for use until a session is set and the delegate is configured.
    public init(logger: NeedleTailLogger = NeedleTailLogger(), ratchetConfiguration: RatchetConfiguration? = nil) {
        self.logger = logger
        ratchetManager = RatchetStateManager<SHA256>(
            executor: cryptoExecutor,
            logger: logger,
            ratchetConfiguration: ratchetConfiguration)
        jobConsumer = NeedleTailAsyncConsumer<JobModel>(logger: logger, executor: cryptoExecutor)
    }

    /// Sets the session transport delegate.
    ///
    /// The transport delegate is responsible for handling the actual network communication
    /// of encrypted messages. This must be set before the processor can send or receive messages.
    ///
    /// - Parameter delegate: An object conforming to `SessionTransport` for handling transport-level communication.
    ///   Pass `nil` to remove the current delegate.
    public func setDelegate(_ delegate: (any SessionTransport)?) {
        self.delegate = delegate
    }
    
    func setTaskDelegate(_ delegate: TaskSequenceDelegate) {
        self.taskDelegate = delegate
    }
    
    public func setLogLevel(_ level: Level) async {
        logger.setLogLevel(level)
        await ratchetManager.setLogLevel(level)
    }


    // MARK: - Outbound Messaging

    /// Handles outbound message encryption and task dispatch.
    ///
    /// This function performs the complete outbound message processing pipeline:
    /// 1. Resolves the appropriate session identities for the recipients
    /// 2. Filters and prioritizes recipient identities based on the message type
    /// 3. Constructs and persists encrypted tasks for delivery
    /// 4. Schedules the tasks for processing by the job queue
    ///
    /// The function handles different message types (personal, nickname, channel, broadcast)
    /// and ensures that each recipient receives a properly encrypted message with the correct
    /// cryptographic context.
    ///
    /// ## Message Types
    /// - **Personal**: Messages sent to the sender's own devices
    /// - **Nickname**: Private messages between two users
    /// - **Channel**: Messages sent to a group of users
    /// - **Broadcast**: Messages sent to all known users (not fully implemented)
    ///
    /// ## Security Features
    /// - All messages are encrypted using Double Ratchet protocol
    /// - Identity resolution ensures messages only go to intended recipients
    /// - Optional persistence provides message history and delivery confirmation
    /// - Cryptographic operations are performed serially on dedicated queues
    ///
    /// - Parameters:
    ///   - message: The message to encrypt and send. Contains the plaintext content and metadata.
    ///   - cache: A reference to the session's cache for communications. Used for persistence and identity lookup.
    ///   - symmetricKey: Key used for encrypting communication metadata. Must be kept secure.
    ///   - session: The active session context. Contains user identity and cryptographic state.
    ///   - sender: Sender's identifier (typically their secret name). Used for identity resolution.
    ///   - type: The recipient category (e.g., personal, nickname, channel). Determines routing logic.
    ///   - shouldPersist: Whether the message should be stored locally. Enables message history and delivery tracking.
    ///   - logger: Logger instance for debug logging. Sensitive data is filtered before logging.
    /// - Throws: Errors related to identity resolution, encryption, persistence, or job scheduling.
    ///   Common errors include missing identities, encryption failures, and database errors.
    public func outboundTask(
        message: CryptoMessage,
        cache: SessionCache,
        symmetricKey: SymmetricKey,
        session: PQSSession,
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
            var sendOneTimeIdentities = false
            var createIdentity = true
            if let state = try? BinaryDecoder().decode(FriendshipMetadata.self, from: message.metadata) {
                if state.myState == .requested {
                    sendOneTimeIdentities = true
                }
                if state.myState == .pending && state.theirState == .pending {
                    createIdentity = false
                }
            }

            identities = try await gatherPrivateMessageIdentities(
                session: session,
                target: nickname,
                logger: logger,
                createIdentity: createIdentity,
                sendOneTimeIdentities: sendOneTimeIdentities
            )
            recipients.formUnion([sender, nickname])
        case .channel:
            do {
                
                let (channelIdentities, members) = try await gatherChannelIdentities(
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey,
                    type: type,
                    logger: logger
                )
                identities = channelIdentities
                recipients.formUnion(members)
                
            } catch let sessionError as PQSSession.SessionErrors where sessionError == .cannotFindCommunication {
                
                let info = try BinaryDecoder().decode(ChannelInfo.self, from: message.metadata)

                try await createChannelCommuncation(
                    sender: sender,
                    recipient: type,
                    channelName: info.name,
                    administrator: info.administrator,
                    members: info.members,
                    operators: info.operators,
                    symmetricKey: symmetricKey,
                    session: session,
                    cache: cache,
                    metadata: message.metadata)
                
                let (channelIdentities, gatheredMembers) = try await gatherChannelIdentities(
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey,
                    type: type,
                    logger: logger)
                
                identities = channelIdentities
                recipients.formUnion(gatheredMembers)
                
            } catch {
                throw error
            }
        case .broadcast:
            break
        }

        /// Utility for selecting matching identities by secret name and device ID.
        /// This function searches through the available identities to find one that matches
        /// the specified secret name and device ID combination.
        ///
        /// - Parameters:
        ///   - secretName: The secret name to match. Used for user identification.
        ///   - deviceId: The device UUID string to match. Used for device-specific routing.
        /// - Returns: The matching `SessionIdentity` if found, else `nil`.
        ///   Returns `nil` if no identity matches or if the device ID is invalid.
        func getIdentity(secretName: String, deviceId: String) async -> SessionIdentity? {
            await identities.asyncFirst { identity in
                guard let props = await identity.props(symmetricKey: symmetricKey) else { return false }
                return props.secretName == secretName && props.deviceId == UUID(uuidString: deviceId)
            }
        }

        // Filter identities based on delegate-supplied info
        if let sessionDelegate = await session.sessionDelegate {
            if let (secretName, deviceId) = await sessionDelegate.retrieveUserInfo(message.transportInfo) {
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
                    await ($0.props(symmetricKey: symmetricKey)?.isMasterDevice == false)
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
            logger: logger)
    }
    
    public func createChannelCommuncation(
        sender: String,
        recipient: MessageRecipient,
        channelName: String,
        administrator: String,
        members: Set<String>,
        operators: Set<String>,
        symmetricKey: SymmetricKey,
        session: PQSSession,
        cache: SessionCache,
        metadata: Data,
        shouldSynchronize: Bool = true
    ) async throws {
        var members = members
        var operators = operators
        members.insert(sender)
        operators.insert(sender)
        guard !members.isEmpty else {
            throw PQSSession.SessionErrors.missingMetadata
        }
        guard !operators.isEmpty else {
            throw PQSSession.SessionErrors.missingMetadata
        }

        guard operators.count >= 1 else {
            throw PQSSession.SessionErrors.invalidOperatorCount
        }
        guard members.count >= 3 else {
            throw PQSSession.SessionErrors.invalidMemberCount
        }

        let communicationModel = try await createCommunicationModel(
            administrator: administrator,
            operators: operators,
            recipients: members,
            communicationType: .channel(channelName),
            metadata: metadata,
            symmetricKey: symmetricKey)
        
        try await cache.createCommunication(communicationModel)
        await session.receiverDelegate?.updatedCommunication(
            communicationModel,
            members: members)
        await session.receiverDelegate?.createdChannel(communicationModel)
        
        if shouldSynchronize {
            let params = try await session.requireSessionParametersWithoutTransportDelegate()
            
            try await session.sendCommunicationSynchronization(
                recipient: recipient,
                metadata: metadata,
                sessionContext: params.sessionContext,
                sessionDelegate: params.sessionDelegate,
                cache: params.cache,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger)
        }
    }

    // MARK: - Identity Resolution

    /// Fetches personal identities for the sender.
    ///
    /// Retrieves all session identities associated with the sender's secret name.
    /// These identities represent the sender's devices and are used for personal messages
    /// (messages sent to the sender's own devices).
    ///
    /// - Parameters:
    ///   - session: The current session containing user context and identity management.
    ///   - sender: The sender's secret name used for identity lookup.
    ///   - logger: Logger for debug output and identity resolution tracking.
    /// - Returns: An array of `SessionIdentity` objects for the sender's devices.
    /// - Throws: Errors from identity refresh, typically network or cryptographic errors.
    private func gatherPersonalIdentities(session: PQSSession, sender: String, logger: NeedleTailLogger) async throws -> [SessionIdentity] {
        let identities = try await session.refreshIdentities(secretName: sender)
        logger.log(level: .info, message: "Gathered \(identities.count) Personal Session Identities")
        return identities
    }

    /// Fetches identities for private (1:1) messages.
    ///
    /// Retrieves all session identities associated with the target recipient's secret name.
    /// These identities represent the recipient's devices and are used for private messages
    /// between two users.
    ///
    /// - Parameters:
    ///   - session: The current session containing user context and identity management.
    ///   - target: The target recipient's secret name used for identity lookup.
    ///   - logger: Logger for debug output and identity resolution tracking.
    /// - Returns: An array of `SessionIdentity` objects for the target's devices.
    /// - Throws: Errors from identity refresh, typically network or cryptographic errors.
    private func gatherPrivateMessageIdentities(
        session: PQSSession,
        target: String,
        logger: NeedleTailLogger,
        createIdentity: Bool = true,
        sendOneTimeIdentities: Bool
    ) async throws -> [SessionIdentity] {
        let identities = try await session.refreshIdentities(
            secretName: target,
            createIdentity: createIdentity,
            sendOneTimeIdentities: sendOneTimeIdentities)
        logger.log(level: .info, message: "Gathered \(identities.count) Private Message Session Identities")
        return identities
    }

    /// Fetches all identities for channel messages.
    ///
    /// Retrieves session identities for all members of a channel. This function also
    /// updates the channel's message count and handles communication model creation
    /// if needed.
    ///
    /// The function processes channel members sequentially to maintain cryptographic
    /// ordering and prevent race conditions. Each member's identities are fetched
    /// individually to ensure proper error isolation.
    ///
    /// - Parameters:
    ///   - cache: The session cache containing communication models and metadata.
    ///   - session: The current session containing user context and identity management.
    ///   - symmetricKey: The symmetric key used for decrypting communication metadata.
    ///   - type: The message recipient type (should be a channel type).
    ///   - logger: Logger for debug output and identity resolution tracking.
    /// - Returns: A tuple containing all `SessionIdentity` objects for channel members
    ///   and the set of member names.
    /// - Throws: Errors from communication lookup, identity refresh, or metadata decryption.
    private func gatherChannelIdentities(
        cache: SessionCache,
        session: PQSSession,
        symmetricKey: SymmetricKey,
        type: MessageRecipient,
        logger: NeedleTailLogger
    ) async throws -> ([SessionIdentity], Set<String>) {
        let communicationModel = try await findCommunicationType(cache: cache, communicationType: type, session: session)
        guard let props = await communicationModel.props(symmetricKey: symmetricKey) else {
            throw PQSSession.SessionErrors.propsError
        }

        let members = props.members
        var identities = [SessionIdentity]()
        for member in members {
            try await identities.append(contentsOf: session.refreshIdentities(secretName: member, forceRefresh: true))
        }
        logger.log(level: .info, message: "Gathered \(identities.count) Channel Session Identities")
        return (identities, members)
    }

    // MARK: - Message Encryption

    /// Encrypts and schedules a task for each recipient identity.
    ///
    /// This function creates encrypted tasks for each recipient and schedules them for processing.
    /// It handles both persistent and non-persistent messages, updating communication models
    /// and creating message records as needed.
    ///
    /// For persistent messages, the function:
    /// - Creates or updates communication models
    /// - Saves encrypted message records
    /// - Updates message counts and metadata
    ///
    /// For non-persistent messages, the function:
    /// - Creates temporary tasks for immediate processing
    /// - Handles communication synchronization if needed
    ///
    /// ## Security Features
    /// - Each recipient gets a uniquely encrypted message
    /// - Message metadata is updated per recipient
    /// - Cryptographic operations are performed serially on dedicated queues
    /// - Sensitive data is never logged
    ///
    /// - Parameters:
    ///   - sessionIdentities: The recipient identities to encrypt for.
    ///   - message: The message to encrypt and send.
    ///   - cache: The session cache for persistence and metadata.
    ///   - session: The current session context.
    ///   - symmetricKey: The symmetric key for encryption and metadata.
    ///   - sender: The sender's identifier.
    ///   - recipients: The set of recipient names.
    ///   - shouldPersist: Whether to persist the message locally.
    ///   - logger: Logger for debug output.
    /// - Throws: Errors from encryption, persistence, or task scheduling.
    private func createEncryptableTask(
        for sessionIdentities: [SessionIdentity],
        message: CryptoMessage,
        cache: SessionCache,
        session: PQSSession,
        symmetricKey: SymmetricKey,
        sender _: String,
        recipients: Set<String>,
        shouldPersist: Bool,
        logger: NeedleTailLogger
    ) async throws {

        var task: EncryptableTask
        var encryptableMessage: EncryptedMessage?

        if shouldPersist {
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false

            do {
                communicationModel = try await findCommunicationType(
                    cache: cache,
                    communicationType: message.recipient,
                    session: session)
                
                guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
                    throw PQSSession.SessionErrors.propsError
                }
                props.messageCount += 1
                _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
                shouldUpdateCommunication = true
            } catch {
                communicationModel = try await createCommunicationModel(
                    recipients: recipients,
                    communicationType: message.recipient,
                    metadata: message.metadata,
                    symmetricKey: symmetricKey)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: recipients)
            }

            let savedMessage = try await createOutboundMessageModel(
                message: message,
                communication: communicationModel,
                session: session,
                symmetricKey: symmetricKey,
                members: recipients,
                sharedId: UUID().uuidString,
                shouldUpdateCommunication: shouldUpdateCommunication)
            await session.receiverDelegate?.createdMessage(savedMessage)
            encryptableMessage = savedMessage
        }
        
        for identity in sessionIdentities {
            do {
                if let unwrappedEncryptableMessage = encryptableMessage {
                    encryptableMessage = await session.sessionDelegate?.updateEncryptableMessageMetadata(
                        unwrappedEncryptableMessage,
                        transportInfo: message.transportInfo,
                        identity: identity,
                        recipient: message.recipient
                    )
                }

                if shouldPersist {
                    guard let encryptableMessage else { return }
                    guard let messageProps = await encryptableMessage.props(symmetricKey: symmetricKey) else {
                        throw PQSSession.SessionErrors.propsError
                    }
                    logger.log(level: .debug, message: "Obtained encryptable message props for recipient \(identity)")

                    task = EncryptableTask(
                        task: .writeMessage(OutboundTaskMessage(
                            message: messageProps.message,
                            recipientIdentity: identity,
                            localId: encryptableMessage.id,
                            sharedId: encryptableMessage.sharedId
                        )))
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

                    task = EncryptableTask(
                        task: .writeMessage(OutboundTaskMessage(
                            message: message,
                            recipientIdentity: identity,
                            localId: UUID(),
                            sharedId: UUID().uuidString
                        ))
                    )
                }
                try await feedTask(task, session: session)
            } catch {
                logger.log(level: .error, message: "Error handling recipient identity \(identity): \(error)")
            }
        }
    }

    // MARK: - Inbound Messaging

    /// Handles an inbound encrypted message by enqueuing it for decryption.
    ///
    /// This function receives an encrypted message from the transport layer and schedules
    /// it for decryption and processing by the job queue. The actual decryption and
    /// message handling is performed asynchronously by the job processor.
    ///
    /// ## Processing Pipeline
    /// 1. Message is received and wrapped in an `EncryptableTask`
    /// 2. Task is scheduled for processing by the job queue
    /// 3. Job processor decrypts the message using Double Ratchet
    /// 4. Message is validated and processed according to its type
    /// 5. Recipients are notified of the new message
    ///
    /// ## Security Features
    /// - Messages are processed in order to maintain cryptographic properties
    /// - Decryption is performed on dedicated cryptographic queues
    /// - Message validation prevents malicious content from being processed
    /// - Identity verification ensures messages come from known senders
    ///
    /// - Parameters:
    ///   - message: The message received from the transport layer.
    ///     Contains the encrypted payload and sender metadata.
    ///   - session: The current crypto session used to decrypt and dispatch.
    ///     Provides the cryptographic context needed for decryption.
    /// - Throws: Errors from task scheduling or job queue management.
    ///   Decryption errors are handled by the job processor.
    public func inboundTask(_ message: InboundTaskMessage, session: PQSSession) async throws {
        try await feedTask(
            EncryptableTask(task: .streamMessage(message)),
            session: session
        )
    }
}


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
import BinaryCodable
import AsyncAlgorithms

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
    let ratchetManager: DoubleRatchetStateManager<SHA256>

    /// Internal message sequence tracker for job ordering.
    /// Ensures that jobs are processed in the correct order to maintain cryptographic properties.
    var sequenceId = 0

    /// Indicates if the processor is actively running jobs.
    /// Used to prevent multiple concurrent job processing loops.
    var isRunning = false

    /// Delayed (not-yet-due) jobs that were skipped ahead of once in the current
    /// processing pass so ready work behind them is not head-of-line blocked.
    /// When a job id is already recorded here and is popped again while still
    /// not due, the queue has cycled back to it and the loop waits it out
    /// instead of busy-spinning. Cleared as jobs become due or the loop restarts.
    var deferredDelayedJobIds: Set<UUID> = []

    /// Delegate responsible for transport-level session communication.
    /// Handles the actual sending and receiving of encrypted messages over the network.
    var delegate: (any SessionTransport)?
    
    var taskDelegate: TaskSequenceDelegate?

    /// Last time we sent a peer `refreshOneTimeKeys` control message for a given peer secret name.
    /// Used to debounce control-plane churn during reconnect bursts.
    var lastPeerRefreshRequestAt: [String: Date] = [:]

    /// Minimum interval between peer refresh control messages for the same peer.
    /// Keeps recovery behavior while reducing startup storms that can race with live traffic.
    let peerRefreshRequestCooldown: TimeInterval = 15

    /// Recovery-critical control messages may need one retry even when a recent outbound
    /// reconciliation already set the peer cooldown. Keyed by outbound shared id.
    var outboundControlRepairBypassAtBySharedId: [String: Date] = [:]
    let outboundControlRepairBypassTTL: TimeInterval = 60 * 10

    struct RecentOutboundReplay: Sendable {
        let message: CryptoMessage
        let createdAt: Date
        var replayCount: Int
    }

    struct PendingOutboundTransport: Sendable {
        let message: SignedRatchetMessage
        let metadata: SignedRatchetMessageMetadata
        let needsRemoteDeletion: Bool
        let curveOneTimeKeyId: String?
        let mlKEMOneTimeKeyId: String
        let createdAt: Date
    }

    /// Recent non-persistent SDK control payloads, keyed by shared id.
    /// Persisted user messages are replayed from the app store; this covers the
    /// Session recovery controls that intentionally do not create UI rows.
    var recentOutboundReplayBySharedId: [String: RecentOutboundReplay] = [:]
    let recentOutboundReplayTTL: TimeInterval = 60 * 10
    let recentOutboundReplayLimit = 256
    let recentOutboundReplayMaxReplays = 5

    /// Signed ratchet frames whose encryption succeeded but whose transport send has not.
    /// Retrying these frames avoids advancing the outbound ratchet a second time for the same
    /// logical message, which is especially important for first messages in a session.
    var pendingOutboundTransportBySharedId: [String: PendingOutboundTransport] = [:]
    let pendingOutboundTransportTTL: TimeInterval = 60 * 10
    let pendingOutboundTransportLimit = 256
    
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
        ratchetManager = DoubleRatchetStateManager<SHA256>(
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
    /// - **Broadcast**: Fan-out to every contact plus existing ratchet peers (excluding self), after per-peer `refreshIdentities`; one ciphertext per device via `.nickname` transports.
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
        sharedIdOverride: String? = nil,
        shouldPersist: Bool,
        logger: NeedleTailLogger
    ) async throws {
        var identities = [SessionIdentity]()
        var recipients = Set<String>()
        // Friendship / OTK bootstrap must avoid ghost non-master rows in published
        // peer configs. Normal DMs, channels, and sibling sync must keep every
        // linked device — otherwise child devices can send but never receive.
        var restrictPeerFanoutToMasterDevices = false

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
            
            var forceIdentityRefresh = false
            if let state = try? BinaryDecoder().decode(FriendshipMetadata.self, from: message.metadata) {
                if state.myState == .requested {
                    // Bootstrap OTK when the master peer identity has no initialized ratchet
                    // yet. Callers that pre-bootstrap via `bootstrapPeerContactSession`
                    // must not burn another OTK on friendship.
                    sendOneTimeIdentities = try await session.peerNeedsOutboundBootstrap(nickname)
                }
                if state.myState == .pending && state.theirState == .pending {
                    createIdentity = false
                }
                // Friendship controls must not fan out to ghost device rows left after
                // peer reinstall / device rotation; force a prune against published devices.
                forceIdentityRefresh = true
                restrictPeerFanoutToMasterDevices = true
            }
            // OTK handshake fan-out has the same ghost-device risk as friendship.
            if sendOneTimeIdentities {
                forceIdentityRefresh = true
                restrictPeerFanoutToMasterDevices = true
            }

            identities = try await gatherPrivateMessageIdentities(
                session: session,
                target: nickname,
                logger: logger,
                createIdentity: createIdentity,
                sendOneTimeIdentities: sendOneTimeIdentities,
                forceRefresh: forceIdentityRefresh)

            // OTK handshake notify must encrypt to the bootstrap-target device
            // (online / OTK-capable), not every master-flagged row. Ghost devices
            // left in published configs after reinstall are often still marked master.
            if let transportInfo = message.transportInfo,
               let event = try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo),
               case .synchronizeOneTimeKeys = event,
               let targetDevice = try? await session.peerMasterDevice(for: nickname) {
                let beforeCount = identities.count
                await identities.asyncRemoveAll { identity in
                    guard let props = await identity.props(symmetricKey: symmetricKey) else { return true }
                    return props.deviceId != targetDevice.deviceId
                }
                if identities.isEmpty {
                    logger.log(
                        level: .warning,
                        message: "OTK handshake: no SessionIdentity for bootstrap target \(nickname) deviceId=\(targetDevice.deviceId); gathered=\(beforeCount)")
                } else {
                    logger.log(
                        level: .info,
                        message: "OTK handshake: scoped to bootstrap target \(nickname) deviceId=\(targetDevice.deviceId)")
                }
            }

            // Prune peer ghosts before appending sibling identities so linked-device
            // sync is not stripped by the master-only friendship/OTK filter.
            if restrictPeerFanoutToMasterDevices {
                let hadMaster = await identities.asyncContains {
                    await ($0.props(symmetricKey: symmetricKey)?.isMasterDevice == true)
                }
                if hadMaster {
                    await identities.asyncRemoveAll {
                        await ($0.props(symmetricKey: symmetricKey)?.isMasterDevice == false)
                    }
                }
                // If the published config has no master flag (or only ghosts are
                // flagged), keep the gathered identities rather than dropping all
                // recipients and silently no-op'ing OTK / friendship delivery.
            }
            
            let isPersistable = await session.sessionDelegate?.shouldPersist(transportInfo: message.transportInfo) != false
            if isPersistable && !sendOneTimeIdentities {
                // Sibling sync must not block or fail the peer DM fan-out. A missing
                // personal SessionIdentity (SESSIONIDENTITYNOTFOUND) is recovered
                // best-effort after the peer ciphertext jobs are already queued.
                do {
                    let personalIdentities = try await gatherPersonalIdentities(session: session, sender: sender, logger: logger)
                    identities.append(contentsOf: personalIdentities)
                } catch {
                    logger.log(
                        level: .warning,
                        message: "Sibling identity gather failed for \(sender); continuing peer fan-out without linked-device sync: \(error)")
                }
            }
            
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

                try await createChannelCommunication(
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
            identities = try await gatherBroadcastIdentities(
                session: session,
                cache: cache,
                symmetricKey: symmetricKey,
                sender: sender,
                logger: logger)
            for identity in identities {
                if let peer = await identity.props(symmetricKey: symmetricKey)?.secretName {
                    recipients.insert(peer)
                }
            }
            recipients.insert(sender)
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

        let targetedPersonalDeviceId: UUID? = {
            guard type == .personalMessage else { return nil }
            guard let transportInfo = message.transportInfo else { return nil }
            guard let event = try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo) else { return nil }
            switch event {
            case .linkedDeviceReprovisioning(let bundle):
                return bundle.targetDeviceId
            default:
                return nil
            }
        }()

        if let targetedPersonalDeviceId {
            await identities.asyncRemoveAll { identity in
                guard let props = await identity.props(symmetricKey: symmetricKey) else { return true }
                return props.secretName != sender || props.deviceId != targetedPersonalDeviceId
            }
        }

        // Filter identities based on delegate-supplied info
        if let sessionDelegate = await session.sessionDelegate {
            if let (secretName, deviceId) = await sessionDelegate.retrieveUserInfo(message.transportInfo),
               !deviceId.isEmpty {
                let lookupSecretName: String?
                if secretName.isEmpty {
                    switch type {
                    case let .nickname(name), let .channel(name):
                        lookupSecretName = name
                    case .personalMessage:
                        lookupSecretName = sender
                    case .broadcast:
                        lookupSecretName = nil
                    }
                } else {
                    lookupSecretName = secretName
                }
                if let lookupSecretName {
                    let resolvedIdentity = await getIdentity(secretName: lookupSecretName, deviceId: deviceId)
                    if let offerIdentity = resolvedIdentity {
                        identities = [offerIdentity]
                    } else {
                        logger.log(level: .error, message: "Missing Offer Identity: \(lookupSecretName)")
                        return
                    }
                }
            }
        }

        if case .broadcast = type {
            let identitiesByPeer = await BroadcastRecipientDiscovery.groupIdentitiesByPeerSecretName(
                identities,
                symmetricKey: symmetricKey)
            for peer in identitiesByPeer.keys.sorted() {
                guard let peerIdentities = identitiesByPeer[peer], !peerIdentities.isEmpty else { continue }
                var peerMessage = message
                peerMessage.recipient = .nickname(peer)
                try await createEncryptableTask(
                    for: peerIdentities,
                    message: peerMessage,
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey,
                    sender: sender,
                    recipients: Set([sender, peer]),
                    sharedIdOverride: sharedIdOverride,
                    shouldPersist: shouldPersist,
                    logger: logger)
            }
            return
        }

        try await createEncryptableTask(
            for: identities,
            message: message,
            cache: cache,
            session: session,
            symmetricKey: symmetricKey,
            sender: sender,
            recipients: recipients,
            sharedIdOverride: sharedIdOverride,
            shouldPersist: shouldPersist,
            logger: logger)
    }
    
    public func createChannelCommunication(
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

        guard operators.count >= PQSSessionConstants.minimumChannelOperators else {
            throw PQSSession.SessionErrors.invalidOperatorCount
        }
        guard members.count >= PQSSessionConstants.minimumChannelMembers else {
            throw PQSSession.SessionErrors.invalidMemberCount
        }

        if try await cache.fetchCommunications().async.first(where: {
            await $0.props(symmetricKey: symmetricKey)?.communicationType == .channel(channelName)
        }) == nil {
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
        }
        
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

    /// Expands an existing channel communication roster and optionally re-synchronizes encryption state.
    public func updateChannelMembership(
        channelName: String,
        administrator: String,
        members: Set<String>,
        operators: Set<String>,
        symmetricKey: SymmetricKey,
        session: PQSSession,
        cache: SessionCache,
        shouldSynchronize: Bool
    ) async throws {
        var members = members
        var operators = operators
        members.insert(administrator)
        operators.insert(administrator)

        let communicationModel = try await findCommunicationType(
            cache: cache,
            communicationType: .channel(channelName),
            session: session)

        guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
            throw PQSSession.SessionErrors.missingMetadata
        }

        let wireInfo = ChannelInfo(
            name: channelName,
            administrator: administrator,
            members: members,
            operators: operators)
        let metadata = try BinaryEncoder().encode(wireInfo)

        props.administrator = administrator
        props.members = members
        props.operators = operators
        props.metadata = metadata

        _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
        try await cache.updateCommunication(communicationModel)

        await session.receiverDelegate?.updatedCommunication(communicationModel, members: members)

        if shouldSynchronize {
            let params = try await session.requireSessionParametersWithoutTransportDelegate()
            try await session.sendCommunicationSynchronization(
                recipient: .channel(channelName),
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
        var identities = try await session.refreshIdentities(secretName: sender)
        if identities.isEmpty {
            identities = try await session.refreshIdentities(secretName: sender, forceRefresh: true)
        }
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
        sendOneTimeIdentities: Bool,
        forceRefresh: Bool = false
    ) async throws -> [SessionIdentity] {
        let identities = try await session.refreshIdentities(
            secretName: target,
            createIdentity: createIdentity,
            forceRefresh: forceRefresh,
            sendOneTimeIdentities: sendOneTimeIdentities)
        logger.log(level: .info, message: "Gathered \(identities.count) Private Message Session Identities")
        return identities
    }

    /// Peer devices for broadcast: union of contacts and existing session identities, then `refreshIdentities` per peer
    /// so missing or stale ratchet rows are filled before encrypting (same pattern as channel member gathering).
    private func gatherBroadcastIdentities(
        session: PQSSession,
        cache: SessionCache,
        symmetricKey: SymmetricKey,
        sender: String,
        logger: NeedleTailLogger
    ) async throws -> [SessionIdentity] {
        let stored = try await cache.fetchSessionIdentities()
        let contacts = try await cache.fetchContacts()
        let peerNames = await BroadcastRecipientDiscovery.collectPeerSecretNames(
            sender: sender,
            sessionIdentities: stored,
            contacts: contacts,
            symmetricKey: symmetricKey
        )

        logger.log(level: .info, message: "Broadcast: resolving identities for \(peerNames.count) peer(s)")

        for peer in peerNames.sorted() {
            do {
                _ = try await session.refreshIdentities(secretName: peer)
            } catch {
                // Do not log peer identifiers in production logs.
                logger.log(level: .error, message: "Broadcast: refreshIdentities failed for a peer: \(error)")
            }
        }

        let refreshed = try await cache.fetchSessionIdentities()
        var result: [SessionIdentity] = []
        result.reserveCapacity(refreshed.count)
        for identity in refreshed {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            guard props.secretName != sender else { continue }
            result.append(identity)
        }
        logger.log(level: .info, message: "Gathered \(result.count) broadcast session identities (peers only)")
        return result
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
        var identities = Set<SessionIdentity>()
        for member in members {
            try await identities.formUnion(session.refreshIdentities(secretName: member))
        }
        logger.log(level: .info, message: "Gathered \(identities.count) Channel Session Identities")
        return (Array(identities), members)
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
        sender: String,
        recipients: Set<String>,
        sharedIdOverride: String? = nil,
        shouldPersist: Bool,
        logger: NeedleTailLogger
    ) async throws {

        let hasRecipientIdentities = !sessionIdentities.isEmpty
        if !hasRecipientIdentities {
            logger.log(
                level: .warning,
                message: "No recipient session identities resolved for outbound message recipient \(message.recipient)")
            // Personal messages are encrypted only for the account's *other* devices.
            // A single-device account legitimately resolves zero identities here:
            // control events (non-persisted) are a no-op, and persisted notes-to-self
            // fall through below so they are stored locally and marked delivered.
            guard message.recipient == .personalMessage else {
                throw PQSSession.SessionErrors.missingSessionIdentity
            }
            guard shouldPersist else { return }
        }

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
                sharedId: sharedIdOverride ?? UUID().uuidString,
                shouldUpdateCommunication: shouldUpdateCommunication)
            await session.receiverDelegate?.createdMessage(savedMessage)
            encryptableMessage = savedMessage
        }

        if !hasRecipientIdentities {
            // Single-device personal message: nothing to encrypt or transmit. The
            // note already lives on the only device, so it is delivered by definition.
            if let savedMessage = encryptableMessage {
                try await session.updateMessageDeliveryState(
                    savedMessage,
                    deliveryState: .delivered,
                    messageRecipient: message.recipient)
            }
            return
        }

        // When persisting, fetch message props once and reuse for all identities to avoid per-identity
        // decrypt/props failures (e.g. PROPSERROR on second identity) which would skip recipients.
        var persistedMessageProps: EncryptedMessage.UnwrappedProps?
        if shouldPersist, let encryptableMessage {
            persistedMessageProps = await encryptableMessage.props(symmetricKey: symmetricKey)
            if persistedMessageProps == nil {
                logger.log(level: .error, message: "Obtained encryptable message props failed for initial message")
            }
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

                guard let identityProps = await identity.props(symmetricKey: symmetricKey) else {
                    logger.log(level: .warning, message: "Skipping outbound task for unreadable recipient identity \(identity.id)")
                    continue
                }

                // User-visible ciphertext to peers is urgent. Sibling sync and
                // non-persisted control/repair frames stay lower so they cannot
                // starve the conversation path (see production multi-device delay).
                let isSelfRecipient = identityProps.secretName == sender
                let taskPriority: Priority = {
                    if shouldPersist {
                        return isSelfRecipient ? .standard : .urgent
                    }
                    return .background
                }()

                if shouldPersist {
                    guard let encryptableMessage else { return }
                    guard let messageProps = persistedMessageProps else {
                        throw PQSSession.SessionErrors.propsError
                    }
                    logger.log(level: .debug, message: "Obtained encryptable message props for recipient \(identity)")

                    task = EncryptableTask(
                        task: .writeMessage(OutboundTaskMessage(
                            message: messageProps.message,
                            recipientIdentity: identity,
                            localId: encryptableMessage.id,
                            sharedId: encryptableMessage.sharedId
                        )),
                        priority: taskPriority)
                } else {
                    if await session.sessionDelegate?.shouldFinishCommunicationSynchronization(message.transportInfo) == true {
                        guard !message.text.isEmpty else { return }

                        logger.log(level: .debug, message: "Requester Synchronizing Communication Message")
                        let communicationModel = try await findCommunicationType(
                            cache: cache,
                            communicationType: message.recipient,
                            session: session)

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
                            sharedId: sharedIdOverride ?? UUID().uuidString,
                            isPersistedOutbound: false
                        )),
                        priority: taskPriority
                    )
                }
                try await feedTask(task, session: session)
            } catch {
                logger.log(level: .error, message: "Error handling recipient identity: \(error)")
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

extension SessionIdentity: @retroactive Equatable {}
extension SessionIdentity: @retroactive Hashable {
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: DoubleRatchetKit.SessionIdentity, rhs: DoubleRatchetKit.SessionIdentity) -> Bool {
        lhs.id == rhs.id
    }
}

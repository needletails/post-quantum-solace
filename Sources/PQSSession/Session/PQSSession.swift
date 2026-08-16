//
//  PQSSession.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-12.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//

import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
import NeedleTailLogger
import SessionEvents
import SessionModels

/// A secure, post-quantum cryptographic session manager for end-to-end encrypted messaging.
///
/// `PQSSession` is the central actor responsible for managing cryptographic sessions, key management,
/// and secure communication channels. It implements both classical (Curve25519) and post-quantum
/// (MLKEM1024) cryptography to ensure long-term security against quantum attacks.
///
/// ## Overview
///
/// The session manager provides:
/// - **Post-quantum secure key exchange** using MLKEM1024
/// - **Forward secrecy** through Double Ratchet protocol
/// - **Device management** with master/child device support
/// - **Automatic key rotation** and compromise recovery
/// - **End-to-end encryption** for all communications
///
/// ## Architecture
///
/// `PQSSession` follows a singleton pattern and uses Swift's actor model for thread-safe
/// concurrent access. It delegates specific responsibilities to protocol-conforming objects:
///
/// - `PQSNetworkHost` - Network communication and key distribution
/// - `PQSPersistenceHost` - Persistent storage and caching
/// - `MessageStoreObserver` - Event handling and UI updates
/// - `PQSHostDelegate` - Application-specific session logic
///
/// ## Usage Example
///
/// ```swift
/// let session = await PQSSession(configuration: SessionConfiguration(
///     transport: myTransport,
///     store: myStore,
///     observer: myReceiver
/// ))
///
/// try await session.createAccount(
///     secretName: "alice",
///     appPassword: "securePassword",
///     createInitialTransport: setupTransport
/// )
/// try await session.unlock(appPassword: "securePassword")
/// try await session.send(
///     recipient: .nickname("bob"),
///     text: "Hello, world!",
///     metadata: ["timestamp": Date()],
///     destructionTime: 3600
/// )
/// ```
///
/// ## Security Features
///
/// - **Post-quantum cryptography**: MLKEM1024 for key exchange
/// - **Forward secrecy**: Double Ratchet protocol with automatic key rotation
/// - **Compromise recovery**: Key rotation on potential compromise
/// - **Device verification**: Signed device configurations
/// - **One-time keys**: Pre-generated keys for immediate communication
/// - **Perfect forward secrecy**: Keys are rotated after each message
///
/// ## Thread Safety
///
/// This actor is designed for concurrent access and all public methods are thread-safe.
/// The singleton pattern ensures consistent state across your application.
///
/// ## Error Handling
///
/// All methods throw specific `PQSError` that conform to `LocalizedError`,
/// providing clear information about what went wrong and how to recover.
///
/// ### Error Information
///
/// Each error provides:
/// - `errorDescription` - Human-readable error message
/// - `failureReason` - Detailed explanation of what went wrong
/// - `recoverySuggestion` - Actionable steps to resolve the issue
///
/// ### Common Errors
///
/// - `PQSError.sessionNotInitialized` - Session not properly set up
/// - `PQSError.databaseNotInitialized` - Storage not configured
/// - `PQSError.transportNotInitialized` - Network layer not ready
/// - `PQSError.invalidSignature` - Cryptographic verification failed
/// - `PQSError.cannotFindOneTimeKey` - No available keys for recipient
/// - `PQSError.drainedKeys` - All local keys have been used
///
/// ### Example
///
/// ```swift
/// do {
///     try await session.send(...)
/// } catch let error as PQSError {
///     if let localizedError = error as? LocalizedError {
///         print("Error: \(localizedError.errorDescription ?? "")")
///         if let suggestion = localizedError.recoverySuggestion {
///             print("Suggestion: \(suggestion)")
///         }
///     }
/// }
/// ```
///
/// ## Performance Considerations
///
/// - Key generation is performed asynchronously
/// - One-time keys are pre-generated in batches (see `PQSSessionConstants.oneTimeKeyBatchSize`)
/// - Automatic key refresh when supply is low
/// - Efficient caching of session identities
///
/// - Important: Construct one `PQSSession` per local account. Hosts should use
///   ``init(configuration:ratchetConfiguration:)``.

/// Why `bootstrapPeerContactSession` is being invoked for a peer.
public enum PeerContactBootstrapPurpose: Sendable {
    /// Requester sending the first friendship packet to a peer.
    case newOutbound
    /// Acceptor replying to a peer-initiated request. Opens a fresh OTK lane so the
    /// accept packet encrypts on the same session the requester learns from OTK notify.
    case friendshipReply
}

public actor PQSSession: SessionCacheSynchronizer {
    /// Unique identifier for the session instance.
    /// This ID is generated once and remains constant for the lifetime of the session.
    nonisolated let id = UUID()

    /// Whether the session is viable for cryptographic operations and job-queue drain.
    /// Mutate only through ``setConnectivity(_:)`` (or `shutdown()`).
    public internal(set) var isViable = false

    /// Actor lifecycle. `shutdown()` enters `shuttingDown` before any suspension
    /// so scheduling cannot recreate workers during teardown.
    /// Internal so lifecycle extensions in this module can mutate it.
    var lifecyclePhase: SessionLifecyclePhase = .idle

    /// Coalesces concurrent false→true viability drains onto one in-flight resume.
    var jobQueueResumeCoalesced = false

    /// Per-instance session. Hosts should construct with ``init(configuration:ratchetConfiguration:)``.
    /// Tests and in-process broadcaster identities may use ``init(_:)``.
    public init(_ ratchetConfiguration: RatchetConfiguration? = nil) {
        self.ratchetConfiguration = ratchetConfiguration
        self.auditSink = FilePQSAuditSink()
        messagePipeline = MessagePipeline(logger: logger, ratchetConfiguration: ratchetConfiguration)
    }

    /// Host construction path. Wires transport, store, and receiver before any session work.
    public init(
        configuration: SessionConfiguration,
        ratchetConfiguration: RatchetConfiguration? = nil
    ) async {
        self.ratchetConfiguration = ratchetConfiguration
        self.auditSink = configuration.auditSink
        messagePipeline = MessagePipeline(logger: logger, ratchetConfiguration: ratchetConfiguration)
        await setTransportDelegate(conformer: configuration.transport)
        await setDatabaseDelegate(conformer: configuration.store)
        setReceiverDelegate(conformer: configuration.observer)
        if let delegate = configuration.hostDelegate {
            await setPQSSessionDelegate(conformer: delegate)
        }
    }

    // Internal (not private) so the PQSSession+* extension files in this
    // module can access them; they are not part of the public API.
    var _sessionContext: SessionContext?
    var _appPassword = ""
    private let ratchetConfiguration: RatchetConfiguration?
    nonisolated let auditSink: any PQSAuditSink
    private(set) var messagePipeline: MessagePipeline
    var transportDelegate: (any PQSNetworkHost)?
    var receiverDelegate: (any MessageStoreObserver)?
    var sessionDelegate: (any PQSHostDelegate)?
    var eventDelegate: (any ContactService)?
    var refreshOTKeysTask: Task<Bool, Never>?
    var refreshMLKEMOTKeysTask: Task<Bool, Never>?
    var otkBatchReplacementPairTask: Task<Bool, Never>?
    private var serverAcceptAckOverdueHandler: (@Sendable (String) async -> Void)?

    /// Bounded FIFO coordinator for session-scoped background / protocol work.
    private var sessionWorkCoordinator: SessionWorkCoordinator?

    var otkUploadCircuitOpen = false
    var otkUploadCircuitOpenedAt: Date?
    let otkCircuitCooldownSeconds: TimeInterval = 300

    /// Updates messaging/session connectivity. On false→true, coalesces one queue resume.
    /// Actor isolation serializes concurrent calls; the last awaited write wins.
    public func setConnectivity(_ value: Bool) async {
        let wasViable = isViable
        isViable = value
        guard value, !wasViable else { return }
        guard !jobQueueResumeCoalesced else { return }
        jobQueueResumeCoalesced = true
        _ = await scheduleBackgroundWork { [weak self] in
            guard let self else { return }
            await self.performCoalescedJobQueueResume()
        }
    }

    /// Receives a server acceptance acknowledgment for an outbound envelope.
    ///
    public func confirmServerAcceptedEnvelope(_ envelopeMessageId: String) async {
        await messagePipeline.confirmServerAcceptedEnvelope(envelopeMessageId, session: self)
    }

    /// Whether this envelope is still waiting for server `privateMessageAccepted`.
    public func isAwaitingServerAccept(_ envelopeMessageId: String) async -> Bool {
        await messagePipeline.isAwaitingServerAccept(envelopeMessageId)
    }

    /// Restart one envelope's accept deadline (owner deferred recycle during backlog).
    public func rearmServerAcceptDeadline(_ envelopeMessageId: String) async {
        await messagePipeline.rearmServerAcceptDeadline(
            envelopeMessageId: envelopeMessageId,
            session: self)
    }

    /// Restart accept deadlines after offline backlog drains (accepts often queue behind it).
    public func rearmAllServerAcceptDeadlines() async {
        await messagePipeline.rearmAllServerAcceptDeadlines(session: self)
    }

    /// Replays durable outbound envelopes which have not received server acceptance.
    ///
    public func resendUnackedOutboundEnvelopes(reason: String) async {
        await messagePipeline.resendUnackedOutboundEnvelopes(reason: reason, session: self)
    }

    /// Retries a chat envelope that exhausted server-accept reconnect attempts.
    @discardableResult
    public func retryFailedServerAcceptOutbound(localMessageId: UUID) async -> Bool {
        await messagePipeline.retryFailedServerAcceptOutbound(
            localMessageId: localMessageId,
            session: self)
    }

    /// Sets the owner callback for a concrete missing server-acceptance transition.
    public func setServerAcceptAckOverdueHandler(
        _ handler: (@Sendable (String) async -> Void)?
    ) {
        serverAcceptAckOverdueHandler = handler
    }

    public func notifyServerAcceptAckOverdue(envelopeMessageId: String) async {
        if let serverAcceptAckOverdueHandler {
            await serverAcceptAckOverdueHandler(envelopeMessageId)
        }
    }

    private func performCoalescedJobQueueResume() async {
        jobQueueResumeCoalesced = false
        guard isViable else { return }
        // Before unlock the cache is nil and this throws
        // databaseNotInitialized — nothing is parked yet, safe to ignore.
        try? await resumeJobQueue()
    }

    /// Transitions `idle` → `running` and starts the work coordinator.
    /// Called from `unlock` / `createAccount` after cache prerequisites, and
    /// lazily from scheduling APIs for bare test sessions.
    func beginSessionLifecycleIfNeeded() async {
        switch lifecyclePhase {
        case .idle:
            lifecyclePhase = .running
            let coordinator = SessionWorkCoordinator(
                maxWorkers: PQSSessionConstants.sessionWorkMaxWorkers,
                maxPending: PQSSessionConstants.sessionWorkMaxPending
            )
            sessionWorkCoordinator = coordinator
            await coordinator.start()
        case .running, .shuttingDown, .shutDown:
            break
        }
    }

    /// Replaces runtime-only components whose shutdown contract is terminal.
    ///
    /// `MessageRatchet.flushAndClose()` permanently closes its mutation
    /// gate, so a persisted session restart must use a new `MessagePipeline`.
    /// This transition is only called by explicit session creation/restoration;
    /// ordinary scheduling after shutdown remains rejected.
    func reviveAfterShutdownIfNeeded() async throws {
        guard lifecyclePhase == .shutDown else { return }

        // A prior best-effort shutdown may have failed to persist ratchet state.
        // Retry while the old processor is still retained. If persistence still
        // fails, propagate the error and keep the processor alive; replacing it
        // would discard unpersisted ratchet state and trip its deinit contract.
        let previous = messagePipeline
        try await previous.ratchetManager.flushAndClose()

        let replacement = MessagePipeline(
            logger: logger,
            ratchetConfiguration: ratchetConfiguration)
        await replacement.setDelegate(transportDelegate)
        messagePipeline = replacement
        sessionWorkCoordinator = nil
        // A false→true viability transition may occur while still shut down.
        // Its scheduled drain is correctly rejected; clear the coalescing token
        // so the revived runtime can own future viability wake-ups.
        jobQueueResumeCoalesced = false
        lifecyclePhase = .idle
    }

    /// Schedules non-blocking work as a child of the session work tree.
    /// Rejected after shutdown closes admission. Re-checks viability at execute time.
    @discardableResult
    func scheduleBackgroundWork(
        _ operation: @escaping @Sendable () async -> Void
    ) async -> SessionWorkAdmission {
        await beginSessionLifecycleIfNeeded()
        guard lifecyclePhase == .running, let coordinator = sessionWorkCoordinator else {
            return .rejected
        }
        return await coordinator.enqueue { [weak self] in
            guard let self else { return }
            guard !Task.isCancelled else { return }
            guard await self.isViable else { return }
            await operation()
        }
    }

    /// Schedules transport-protocol work that must survive viability flaps.
    ///
    /// `inboundCiphertextAccepted` tells the transport to delete a consumed
    /// offline spool copy. Never dropped while the session is running: a full
    /// queue backpressures the producer. Shutdown closes admission.
    @discardableResult
    func scheduleTransportProtocolWork(
        _ operation: @escaping @Sendable () async -> Void
    ) async -> SessionWorkAdmission {
        await beginSessionLifecycleIfNeeded()
        guard lifecyclePhase == .running, let coordinator = sessionWorkCoordinator else {
            return .rejected
        }
        return await coordinator.enqueue {
            guard !Task.isCancelled else { return }
            await operation()
        }
    }

    func sessionWorkMetrics() async -> SessionWorkMetrics {
        if let coordinator = sessionWorkCoordinator {
            return await coordinator.currentMetrics()
        }
        return SessionWorkMetrics()
    }

    func cancelSessionWorkTree() async {
        let coordinator = sessionWorkCoordinator
        sessionWorkCoordinator = nil
        await coordinator?.shutdown()
    }

    /// Opens the OTK upload circuit and runs signing-key mismatch recovery inline
    /// (already on the refresh singleflight path — not a fire-and-forget Task).
    func openOTKUploadCircuitAndScheduleRecovery() async {
        otkUploadCircuitOpen = true
        otkUploadCircuitOpenedAt = Date()
        do {
            try await recoverFromSigningKeyMismatch()
        } catch {
            logger.log(
                level: .warning,
                message: "Signing-key mismatch recovery failed after opening OTK circuit: \(error)")
        }
    }

    // MARK: - Session Reestablishment Coalescing State
    //
    // These dictionaries throttle outbound emissions and coalesce inbound control events
    // (`peerRefresh`, `linkedDeviceRepair`, `linkedDeviceCompromiseObserved`) so that an
    // offline mailbox replaying many copies of the same control event collapses to a
    // single application-visible reaction. State is intentionally in-memory: receiver-side
    // deduplication on cold start still collapses each backlog burst to one delegate fire
    // because all backlogged emissions share the same sender-issued `intentId`/`epoch`.
    //
    // See `PQSSession+ControlEventCoalescing.swift` for the helpers operating on this state.
    var senderControlEpisodes: [ControlEventEpisodeKey: ControlEventEpisode] = [:]
    var senderControlEpochCounters: [SessionReestablishmentKind: UInt64] = [:]
    var processedControlEvents: [ProcessedControlEventKey: ProcessedControlEventState] = [:]
    var lastForcedIdentityRefresh: [String: Date] = [:]

    /// Optional delegate for device linking operations
    public nonisolated(unsafe) weak var linkDelegate: DeviceLinkingDelegate?
    
    /// The session cache instance for data storage and retrieval
    var cache: SessionCache?
    
    let crypto = NeedleTailCrypto()
    var logger = NeedleTailLogger("[PQSSession]")
    var sessionIdentities = Set<String>()
    /// Peers whose OTK notify finished and outbound jobs drained this session.
    /// Prevents skipping bootstrap when DB rows show initialized outbound state but
    /// the peer never received the handshake (intermittent friendship decrypt failures).
    var deliveredOneTimeNotifyPeers = Set<String>()
    /// Peers whose inbound `friendshipStateRequest` was decrypted and applied this session.
    /// Accept bootstrap requires this flag or an established inbound ratchet in the cache.
    var peerInboundFriendshipConfirmedPeers = Set<String>()
    var lastPeerOneTimeRefreshRequestAt: [String: Date] = [:]
    let peerOneTimeRefreshRequestCooldown: TimeInterval = 15
    struct PeerReplenishWaiterKey: Hashable, Sendable {
        let secretName: String
        let deviceId: UUID
    }

    /// Tokenized replenish waiters keyed by `(secretName, deviceId)`.
    /// Timeout resumes only its token; publish ack wakes every waiter for that secret.
    var peerOneTimeReplenishWaiters: [PeerReplenishWaiterKey: [UUID: CheckedContinuation<Void, Never>]] = [:]
    var peerOneTimeReplenishAcknowledgedPeers = Set<String>()
    let peerOneTimeReplenishWaitTimeout: TimeInterval = 4
    var addingContactData: Data?
    /// Last successful automatic key-rotation attempt by inbound peer key.
    /// Key format: "<secretName>|<deviceUUID>".
    var lastAutomaticRotationAtByPeer: [String: Date] = [:]
    
    /// Global timestamp for the last successful automatic key-rotation attempt.
    /// Helps cap account-wide churn when many peers fail at once.
    var lastAutomaticRotationAt: Date?
    
    /// Cooldown window for automatic rotation attempts per peer.
    let automaticRotationPeerCooldown: TimeInterval = 60
    
    /// Cooldown window for automatic rotation attempts globally.
    let automaticRotationGlobalCooldown: TimeInterval = 20

    enum ReconciliationFlow: String, Sendable {
        case inbound
        case outbound
    }

    /// Per-peer timestamp for the last key-reconciliation recovery (archive + identity reset).
    var lastReconciliationAtByPeer: [String: Date] = [:]
    let reconciliationPeerCooldown: TimeInterval = 15

#if DEBUG
    /// Test-only hook: when set, replaces decrypted payload bytes before CryptoMessage decode.
    /// Used to simulate sessionDecryptionError without fighting AEAD.
    var _testDecryptedPayloadTransform: (@Sendable (Data) -> Data)?

    func setTestDecryptedPayloadTransform(_ transform: (@Sendable (Data) -> Data)?) {
        _testDecryptedPayloadTransform = transform
    }
#endif

    func canAttemptReconciliation(
        sender: String,
        deviceId: UUID,
        flow: ReconciliationFlow = .inbound,
        now: Date = Date()
    ) -> Bool {
        let key = reconciliationPeerKey(sender: sender, deviceId: deviceId, flow: flow)
        if let last = lastReconciliationAtByPeer[key],
           now.timeIntervalSince(last) < reconciliationPeerCooldown { return false }
        return true
    }

    func markReconciliationAttempt(
        sender: String,
        deviceId: UUID,
        flow: ReconciliationFlow = .inbound,
        now: Date = Date()
    ) {
        let key = reconciliationPeerKey(sender: sender, deviceId: deviceId, flow: flow)
        pruneRecoveryTimestamps(&lastReconciliationAtByPeer, ttl: reconciliationPeerCooldown, now: now)
        lastReconciliationAtByPeer[key] = now
    }

    func clearOutboundReconciliationCooldown(secretName: String, deviceId: UUID) {
        let key = reconciliationPeerKey(sender: secretName, deviceId: deviceId, flow: .outbound)
        lastReconciliationAtByPeer.removeValue(forKey: key)
    }

    private func reconciliationPeerKey(sender: String, deviceId: UUID, flow: ReconciliationFlow) -> String {
        "\(automaticRotationPeerKey(sender: sender, deviceId: deviceId))|\(flow.rawValue)"
    }

    /// SessionID of the initiating session created for an orphan-resend wave.
    /// Reused across MessageRecords for that peer device. Cleared on wipe /
    /// non-`orphanResend` reset — not when the local replay queue drains, and
    /// not on generic inbound activate/promote (control frames falsely settled).
    var orphanResendInitiatingSessionByPeer: [String: UUID] = [:]

    /// Last orphan-resend recovery session id for a peer device. Survives mark clear
    /// so a post-MessageRecord ledger match cannot remint the same recovery lane.
    /// Cleared with peer wipe / non-`orphanResend` reset.
    var orphanResendRecoverySessionByPeer: [String: UUID] = [:]

    func markOrphanResendInitiatingSession(
        secretName: String,
        deviceId: UUID,
        sessionId: UUID
    ) {
        let key = automaticRotationPeerKey(sender: secretName, deviceId: deviceId)
        orphanResendInitiatingSessionByPeer[key] = sessionId
        orphanResendRecoverySessionByPeer[key] = sessionId
        // Orphan replays must be allowed to encrypt on the new initiating row even
        // if a prior outbound repair attempt armed the peer cooldown.
        clearOutboundReconciliationCooldown(secretName: secretName, deviceId: deviceId)
    }

    func orphanResendInitiatingSessionId(secretName: String, deviceId: UUID) -> UUID? {
        orphanResendInitiatingSessionByPeer[
            automaticRotationPeerKey(sender: secretName, deviceId: deviceId)
        ]
    }

    func orphanResendRecoverySessionId(secretName: String, deviceId: UUID) -> UUID? {
        orphanResendRecoverySessionByPeer[
            automaticRotationPeerKey(sender: secretName, deviceId: deviceId)
        ]
    }

    func clearOrphanResendInitiatingSession(secretName: String, deviceId: UUID) {
        orphanResendInitiatingSessionByPeer.removeValue(
            forKey: automaticRotationPeerKey(sender: secretName, deviceId: deviceId))
    }

    /// Clears the sticky mark and recovery-session history (wipe / non-orphan reset).
    func clearOrphanResendRecoveryState(secretName: String, deviceId: UUID) {
        let key = automaticRotationPeerKey(sender: secretName, deviceId: deviceId)
        orphanResendInitiatingSessionByPeer.removeValue(forKey: key)
        orphanResendRecoverySessionByPeer.removeValue(forKey: key)
    }

    func isOrphanResendInitiatingSession(
        secretName: String,
        deviceId: UUID,
        sessionId: UUID
    ) -> Bool {
        orphanResendInitiatingSessionId(secretName: secretName, deviceId: deviceId) == sessionId
    }

    func isOrphanResendRecoverySession(
        secretName: String,
        deviceId: UUID,
        sessionId: UUID
    ) -> Bool {
        orphanResendRecoverySessionId(secretName: secretName, deviceId: deviceId) == sessionId
    }

    /// Unified inbound-failure policy table.
    /// Keys are either:
    /// - "<sender>|<deviceUUID>|<messageId>" for explicit whole-tuple quarantine
    /// - "<sender>|<deviceUUID>|<messageId>|<failureClass>" for failure-class suppression
    var inboundFailurePolicyUntil: [String: Date] = [:]
    
    /// Suppression duration for replayed/failed inbound frames.
    let inboundFailurePolicyTTL: TimeInterval = 60 * 10
    
    /// Last resend/refresh control request timestamp per request key.
    /// Key format: "<secretName>|<deviceUUID>|<failedSharedMessageId>".
    var lastResendRequestAtByPeer: [String: Date] = [:]

    /// Last time we *serviced* (replayed a frame for) an inbound resend request, keyed by the
    /// requesting device and the failed shared message id. Bounds responder-side amplification:
    /// a peer stuck in a decrypt-failure loop cannot force us to re-ratchet and re-consume
    /// one-time keys for the same message on every repeated request.
    /// Key format: "<requestingDeviceUUID>|<sharedId>".
    var lastServicedResendAtByRequest: [String: Date] = [:]

    /// Responder-side memory of `(requestingDeviceId, sharedId)` tuples that have no
    /// local replay source. Repeat requests for these ids short-circuit the DB lookup
    /// and are answered with a `messageResendUnavailable` notice without re-auditing.
    /// Key format: "<requestingDeviceUUID>|<sharedId>".
    var unavailableResendIds: [String: Date] = [:]

    /// Distinct undecryptable inbound `sharedId`s per peer device. Used to escalate
    /// from per-message resend to automatic session reset when the lane is dead
    /// even though each frame has a unique id.
    /// Key format: `"secretName|deviceUUID"`.
    var undecryptableLaneFailureIdsByPeer: [String: (ids: Set<String>, firstAt: Date)] = [:]

    /// Requester-side count of resend-request submissions per failed message, used to
    /// make the deferred-resend loop terminal even when the responder's unavailable
    /// notice is lost. Key format matches ``peerResendRequestKey(sender:deviceId:failedMessageId:)``.
    var resendRequestAttemptsByKey: [String: (attempts: Int, lastAt: Date)] = [:]

    /// Terminal inbound outcomes: tuples whose content was already declared
    /// unrecoverable to the host. Redelivered copies of these frames are
    /// swallowed on decrypt failure instead of reopening a NACK round and
    /// re-notifying the host. A frame for a marked tuple that *does* decrypt
    /// (late orphan replay) still recovers normally — this ledger is only
    /// consulted on failure. Key format: "<sender>|<deviceUUID>|<sharedId>".
    var terminalInboundOutcomeAt: [String: Date] = [:]

    struct PendingResendAfterReestablishment: Sendable, Equatable {
        let senderName: String
        let senderDeviceId: UUID
        let failedSharedMessageId: String
        let failureClass: String
        let createdAt: Date
    }

    /// Failed inbound messages whose replay should be requested only after the
    /// peer/device has completed the reestablishment round.
    var pendingResendAfterReestablishment: [String: PendingResendAfterReestablishment] = [:]

    /// Open single-flight reestablishment episodes keyed by `"secretName|deviceUUID"`.
    /// While an episode is open, additional decrypt failures for that peer device
    /// coalesce into deferred resend instead of starting another identity reset.
    var openReestablishmentEpisodes: [String: Date] = [:]

    /// Episodes (same keys) opened for failure classes whose spooled offline
    /// ciphertext can never decrypt regardless of how the lane heals —
    /// `missingOneTimeKey` means the referenced one-time key is consumed, so
    /// every frame of that dead session epoch is permanently undecryptable.
    /// Transport hold-and-replay is pointless for these: held copies would be
    /// redelivered on every backlog wave forever. Each frame should instead be
    /// attempted once and purged through the bounded durable-resend claim.
    var deadSessionCiphertextEpisodes: Set<String> = []

    /// Expected response intent for each concrete peer-device recovery lane.
    /// A response cannot close another device's or an older recovery episode.
    var expectedPeerRefreshIntentByPeer: [String: UUID] = [:]

    /// Local account signing-key pin is out of sync with the server-trusted configuration.
    /// Same-account peerRefresh must not emit until the user acknowledges the change
    /// (or a verified reprovisioning path updates the pin). Cleared only by that event.
    public internal(set) var accountIdentityRequiresAcknowledgement: Bool = false

    /// SharedIds for which ``inboundMessagePendingRecovery`` already notified the host.
    /// Prevents placeholder spam across coalesce / redelivery of the same logical id.
    var pendingRecoveryNotifiedKeys: Set<String> = []

    /// Outbound device-send ledger: which local SessionIdentity encrypted each
    /// `(sharedId, recipientDeviceId)`. Hot path is in-memory; mirrored to the store.
    var outboundDeviceSendRecordsByKey: [String: OutboundDeviceSendRecord] = [:]
    /// In-memory accepted-envelope ledger (durable mirror via store when available).
    var acceptedEnvelopeKeys: Set<String> = []
    var acceptedEnvelopeKeyOrder: [String] = []
    /// Default retention: 14d spool + 7d safety margin.
    let acceptedEnvelopeRetention: TimeInterval = 60 * 60 * 24 * 21

    /// Last server-verified device id set per peer secret name. Populated by successful
    /// `findConfiguration` during identity refresh / chat fan-out; used to avoid blocking
    /// network configuration fetch on warm sends when local lanes already match.
    var lastVerifiedDeviceIdsBySecretName: [String: Set<UUID>] = [:]

    /// Accounts the transport definitively reported deleted (HTTP 404 / `userNotFound`).
    /// Excluded from identity refresh / fan-out so ghost channel roster members stop
    /// receiving encrypted traffic on stale device lanes. Cleared by any successful
    /// live configuration fetch (background probe or forced refresh).
    var knownDeletedAccountSecretNames: Set<String> = []

    /// Rate limit for the fire-and-forget deleted-account probes on warm-lane sends.
    var lastDeletedAccountProbeAtBySecretName: [String: Date] = [:]
    let deletedAccountProbeInterval: TimeInterval = 300

    /// Maximum lifetime of a single-flight reestablishment episode before a new
    /// leader is allowed. Bounds stuck recovery without timer-based retry loops.
    let reestablishmentEpisodeTTL: TimeInterval = 90
    
    /// Cooldown for peer resend/refresh requests triggered by inbound failures.
    let peerResendRequestCooldown: TimeInterval = 15

    /// Cooldown for *servicing* a repeated inbound resend request for the same failed message
    /// from the same requesting device. Matches ``peerResendRequestCooldown`` so a legitimate
    /// re-request (which the requester itself rate-limits to this interval) is honored, while
    /// bursts/loops of identical requests are coalesced to a single replay.
    let peerResendServiceCooldown: TimeInterval = 15

    // MARK: - Inactive session support (backward compatible)

    /// Determines how ratchet invalidation is handled.
    ///
    /// - `archive`: Best-effort create a bounded inactive snapshot before clearing state.
    /// - `drop`: Clear state and delete any inactive snapshots (compromise / hard reset).
    enum RatchetInvalidationPolicy: Sendable {
        case archive
        case drop
    }

    enum InactiveSessionSnapshotScope: Sendable {
        case peer(secretName: String)
        case allPeersExcludingLocalUser
    }

    /// Strategy used by the one-time pre-key refresh tasks
    /// (``refreshOneTimeKeysTask(policy:)`` and
    /// ``refreshMLKEMOneTimeKeysTask(policy:)``).
    public enum OneTimeKeyRefreshPolicy: Sendable {
        /// Let the SDK decide based on remaining server-side OTK count and
        /// configured low-water marks.
        case automatic
        /// Top up the local pool back to ``PQSSessionConstants/oneTimeKeyBatchSize``
        /// even if the server still reports a healthy count.
        case replenishBatch
        /// Generate a brand-new batch and replace the *current device's* OTKs
        /// on the server, deleting the previous batch first. Used during
        /// device-key rotation flows.
        case replaceCurrentDeviceBatch
        /// Replace the batch *advertised on the server* with fresh keys while
        /// retaining existing local private keys, so in-flight messages that
        /// were encrypted against the previous batch can still be decrypted.
        /// The retained private pool is capped at
        /// ``PQSSessionConstants/retainedOneTimePrivateKeyCap``; the oldest
        /// keys are evicted first. Used by `missingOneTimeKey` recovery.
        case replacePublishedBatch
    }
    
    enum KeyLoadingState: Sendable {
        case initial, rotating, complete
    }
    
    var keyLoadingState: KeyLoadingState = .initial
    func setKeyLoadingState(_ newState: KeyLoadingState) {
        keyLoadingState = newState
    }

    var pendingLinkedDeviceRepair = false
    func setPendingLinkedDeviceRepair(_ isPending: Bool) {
        pendingLinkedDeviceRepair = isPending
    }
    func hasPendingLinkedDeviceRepair() -> Bool {
        pendingLinkedDeviceRepair
    }
    
    //MARK: Media Encryption
    var currentMessageIndex = 0
    
    /// Asynchronously retrieves the current session context
    ///
    /// The session context contains all the information needed to restore and maintain
    /// a session, including user information, cryptographic keys, and session state.
    ///
    /// - Returns: The current session context, or `nil` if no session has been created
    public var sessionContext: SessionContext? {
        get async {
            _sessionContext
        }
    }

    /// Sets the session context
    ///
    /// - Parameter context: The session context to set
    public func setSessionContext(_ context: SessionContext) async {
        _sessionContext = context
    }

    /// Asynchronously retrieves the application password
    ///
    /// The application password is used to derive encryption keys for session data.
    ///
    /// - Returns: The current application password
    public var appPassword: String {
        get async {
            _appPassword
        }
    }

    // Sets the application password
    func setAppPassword(_ password: String) async {
        _appPassword = password
    }
    

    /// Fingerprint of the inbound frame that last spent a transport-confirmed NACK
    /// for `(sender|device|sharedId)`. Same fingerprint → await sender; different → rearm.
    var lastNackFrameFingerprintByKey: [String: Data] = [:]


    /// Sets the logger log level for both the session and task processor
    ///
    /// - Parameter level: The log level to set (e.g., `.debug`, `.info`, `.error`)
    public func setLogLevel(_ level: Level) async {
        logger.setLogLevel(level)
        await messagePipeline.setLogLevel(level)
    }

    /// Sets the data to be used when adding a new contact
    ///
    /// - Parameter data: Optional data to associate with contact addition
    public func setAddingContact(_ data: Data?) async {
        addingContactData = data
    }
    
    /// Removes a session identity for the specified secret name
    ///
    /// This method removes the session identity from the internal tracking set,
    /// effectively disconnecting from that user's devices.
    ///
    /// - Parameter secretName: The secret name of the user whose identity should be removed
    public func removeIdentity(with secretName: String) {
        clearPeerTransientState(secretName: secretName)
    }

    /// Invalidates only the memoized identity selection for a peer.
    ///
    /// Device-local reset, promote, and demote operations must use this instead of
    /// `removeIdentity(with:)`: clearing account-wide friendship and orphan-recovery
    /// state for one device interrupts recovery already in flight on sibling devices.
    internal func invalidateSessionIdentityCache(secretName: String) {
        sessionIdentities.remove(secretName)
    }

    internal func clearPeerTransientState(secretName: String) {
        invalidateSessionIdentityCache(secretName: secretName)
        deliveredOneTimeNotifyPeers.remove(secretName)
        peerInboundFriendshipConfirmedPeers.remove(secretName)
        lastPeerOneTimeRefreshRequestAt.removeValue(forKey: secretName)
        peerOneTimeReplenishAcknowledgedPeers.remove(secretName)
        resumePeerOneTimeReplenishWaiters(secretName: secretName)
        let orphanPrefix = "\(secretName)|"
        orphanResendInitiatingSessionByPeer = orphanResendInitiatingSessionByPeer.filter {
            !$0.key.hasPrefix(orphanPrefix)
        }
        orphanResendRecoverySessionByPeer = orphanResendRecoverySessionByPeer.filter {
            !$0.key.hasPrefix(orphanPrefix)
        }
    }

    // MARK: - Inactive snapshot helpers

    private func isInactiveSessionIdentity(deviceName: String) -> Bool {
        deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
    }

    /// Interprets `sessionContextId` as an archive timestamp (seconds since epoch) for inactive snapshots.
    ///
    /// Active identities use random `sessionContextId`s; we only call this for inactive identities.
    private func archivedAtSeconds(fromSessionContextId sessionContextId: Int) -> TimeInterval {
        TimeInterval(sessionContextId)
    }

    /// Deletes expired/excess inactive session snapshots for a given peer device.
    func cleanupInactiveSessionSnapshots(
        cache: SessionCache,
        symmetricKey: SymmetricKey,
        secretName: String,
        deviceId: UUID
    ) async {
        do {
            let all = try await cache.fetchSessionIdentities()
            let now = Date().timeIntervalSince1970

            var inactive: [(identity: SessionIdentity, archivedAt: TimeInterval, hasState: Bool)] = []
            for identity in all {
                guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
                guard props.secretName == secretName, props.deviceId == deviceId else { continue }
                guard isInactiveSessionIdentity(deviceName: props.deviceName) else { continue }
                inactive.append((
                    identity,
                    archivedAtSeconds(fromSessionContextId: props.sessionContextId),
                    props.hasRatchetState))
            }

            // Age bound
            for item in inactive where (now - item.archivedAt) > PQSSessionConstants.inactiveSessionMaxAgeSeconds {
                try await cache.deleteSessionIdentity(item.identity.id)
            }

            // Re-fetch and enforce count bound (newest-first by archivedAt)
            let remaining = try await cache.fetchSessionIdentities()
            var remainingInactive: [(identity: SessionIdentity, archivedAt: TimeInterval, hasState: Bool)] = []
            for identity in remaining {
                guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
                guard props.secretName == secretName, props.deviceId == deviceId else { continue }
                guard isInactiveSessionIdentity(deviceName: props.deviceName) else { continue }
                remainingInactive.append((
                    identity,
                    archivedAtSeconds(fromSessionContextId: props.sessionContextId),
                    props.hasRatchetState))
            }

            // Stateful snapshots can decrypt delayed mailbox frames; state-less
            // placeholders cannot. Preserve stateful rows before applying recency.
            remainingInactive.sort {
                if $0.hasState != $1.hasState {
                    return $0.hasState && !$1.hasState
                }
                return $0.archivedAt > $1.archivedAt
            }
            if remainingInactive.count > PQSSessionConstants.inactiveSessionMaxCountPerDevice {
                for item in remainingInactive.dropFirst(PQSSessionConstants.inactiveSessionMaxCountPerDevice) {
                    try await cache.deleteSessionIdentity(item.identity.id)
                }
            }
        } catch {
            logger.log(level: .warning, message: "Failed inactive session snapshot cleanup for \(secretName): \(error)")
        }
    }
    
    
    /// Prunes stale inactive snapshots after the host confirms that its offline
    /// mailbox boundary has been fully processed. Never call this at startup:
    /// delayed ciphertext may still require an archived session to decrypt.
    func cleanupAllInactiveSessionSnapshots() async {
        guard let cache else { return }
        do {
            let symmetricKey = try await getDatabaseSymmetricKey()
            let all = try await cache.fetchSessionIdentities()

            var seen = Set<String>()
            for identity in all {
                guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
                guard isInactiveSessionIdentity(deviceName: props.deviceName) else { continue }
                let key = "\(props.secretName)|\(props.deviceId)"
                guard seen.insert(key).inserted else { continue }
                await cleanupInactiveSessionSnapshots(
                    cache: cache,
                    symmetricKey: symmetricKey,
                    secretName: props.secretName,
                    deviceId: props.deviceId)
            }
        } catch {
            logger.log(level: .warning, message: "Startup inactive session cleanup failed: \(error)")
        }
    }

    /// Host event fired only after an ordered offline replay boundary has settled.
    public func offlineReplayDidSettle() async {
        await pruneAcceptedEnvelopes()
        await cleanupAllInactiveSessionSnapshots()
    }

    /// Keeps a record of inactive session identities for one peer.
    func createInactiveSessionSnapshot(
        for secretName: String,
        policy: RatchetInvalidationPolicy
    ) async throws {
        try await createInactiveSessionSnapshots(
            scope: .peer(secretName: secretName),
            policy: policy
        )
    }

    /// Keeps a record of inactive session identities for all peers except the local user.
    func createInactiveSessionSnapshotsForAllPeers(
        policy: RatchetInvalidationPolicy
    ) async throws {
        try await createInactiveSessionSnapshots(
            scope: .allPeersExcludingLocalUser,
            policy: policy
        )
    }

    /// Keeps a record of inactive session identities for authorized past messages.
    private func createInactiveSessionSnapshots(
        scope: InactiveSessionSnapshotScope,
        policy: RatchetInvalidationPolicy
    ) async throws {
        let symmetricKey = try await getDatabaseSymmetricKey()
        let mySecretName = await sessionContext?.sessionUser.secretName
        guard let cache else { return }
        for identity in try await cache.fetchSessionIdentities() {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            switch scope {
            case .peer(let secretName):
                guard props.secretName == secretName else { continue }
            case .allPeersExcludingLocalUser:
                // Global archival exists for compromise recovery, but our own identities are not
                // used for peer-to-peer ratchet reestablishment.
                if let mySecretName, props.secretName == mySecretName { continue }
            }
            // Never invalidate archived/inactive snapshots.
            if isInactiveSessionIdentity(deviceName: props.deviceName) { continue }
            guard props.hasRatchetState else { continue }
            guard var archiveProps = await identity.props(symmetricKey: symmetricKey) else {
                throw RatchetError.missingProps
            }
            switch policy {
            case .archive:
                // Creation: one new snapshot per matching active identity (no cap at create time).
                // Retention: cleanupInactiveSessionSnapshots (called below) enforces count and age bounds
                // (inactiveSessionMaxCountPerDevice, inactiveSessionMaxAgeSeconds) so we keep the newest N per device.
                archiveProps.sessionContextId = Int(Date().timeIntervalSince1970)
                archiveProps.deviceName = PQSSessionConstants.inactiveSessionDeviceNamePrefix + archiveProps.deviceName
                let archived = try SessionIdentity(
                    id: UUID(),
                    props: archiveProps,
                    symmetricKey: symmetricKey)
                try await cache.createSessionIdentity(archived)
                logger.log(level: .debug, message: "Archived ratchet state for \(archiveProps.secretName) (\(archiveProps.deviceId))")
                
            case .drop:
                for archived in try await cache.fetchSessionIdentities() {
                    guard let aProps = await archived.props(symmetricKey: symmetricKey) else { continue }
                    guard aProps.secretName == archiveProps.secretName, aProps.deviceId == archiveProps.deviceId else { continue }
                    guard isInactiveSessionIdentity(deviceName: aProps.deviceName) else { continue }
                    try await cache.deleteSessionIdentity(archived.id)
                }
            }
            
            // Opportunistic cleanup: bound inactive snapshots per device.
            await cleanupInactiveSessionSnapshots(
                cache: cache,
                symmetricKey: symmetricKey,
                secretName: archiveProps.secretName,
                deviceId: archiveProps.deviceId)
        }
    }

    // Synchronizes the local configuration with the provided data
    func synchronizeLocalConfiguration(_ data: Data) async throws {
        let symmetricKey = try await getAppSymmetricKey()
        guard let decryptedData = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else { return }
        let context = try BinaryDecoder().decode(SessionContext.self, from: decryptedData)
        await setSessionContext(context)
    }

    /// Sets the transport delegate conforming to `PQSNetworkHost`.
    /// - Parameter conformer: The conforming object to set as the transport delegate.
    func setTransportDelegate(conformer: (any PQSNetworkHost)?) async {
        transportDelegate = conformer
        await messagePipeline.setDelegate(conformer)
    }

    /// Sets the database delegate conforming to `PQSPersistenceHost`.
    /// - Parameter conformer: The conforming object to set as the identity store.
    func setDatabaseDelegate(conformer: (any PQSPersistenceHost)?) async {
        if let conformer {
            cache = SessionCache(store: conformer)
            await cache?.setSynchronizer(self)
        }
    }

    /// Attaches a persistence host so unlock and password checks can read salt and session context.
    ///
    /// Hosts that construct with ``init(configuration:ratchetConfiguration:)`` already have a store.
    /// Call this when a bare ``PQSSession`` must verify or unlock against an existing local store
    /// before full transport/observer wiring.
    public func attachPersistenceHost(_ store: any PQSPersistenceHost) async {
        await setDatabaseDelegate(conformer: store)
    }

    /// Ensures the host-facing delegates are wired on a live session without
    /// disturbing `sessionContext` or ratchet state.
    ///
    /// ``init(configuration:ratchetConfiguration:)`` wires hosts at construction,
    /// but a session can legitimately hold an unlocked `sessionContext` while its
    /// hosts are absent: a bare ``PQSSession`` that unlocked after
    /// ``attachPersistenceHost(_:)``, or a session revived by
    /// ``unlock(appPassword:)`` after ``shutdown()`` cleared its delegates.
    /// Hosts call this from their session-start event so a context-bearing actor
    /// can never enter service throwing `transportNotInitialized` /
    /// `receiverDelegateNotSet`.
    ///
    /// Transport, observer, and host delegate are always (re)bound. The
    /// persistence host is installed only when no `SessionCache` exists yet, so a
    /// live session keeps its warm cache. Idempotent.
    public func configureHosts(
        transport: any PQSNetworkHost,
        store: any PQSPersistenceHost,
        observer: any MessageStoreObserver,
        delegate: (any PQSHostDelegate)? = nil
    ) async {
        if _sessionContext != nil, transportDelegate == nil || receiverDelegate == nil {
            logger.log(
                level: .info,
                message: "Wiring missing host delegates on live session (transport: \(transportDelegate == nil ? "absent" : "present"), receiver: \(receiverDelegate == nil ? "absent" : "present"))")
        }
        await setTransportDelegate(conformer: transport)
        if cache == nil {
            await setDatabaseDelegate(conformer: store)
        }
        setReceiverDelegate(conformer: observer)
        if let delegate {
            await setPQSSessionDelegate(conformer: delegate)
        }
    }

    /// Sets (or clears) the application-facing event receiver.
    ///
    /// The receiver hears about lifecycle changes — created/updated/deleted
    /// messages, new contacts, new channels — and is what your UI layer
    /// usually conforms to. Pass `nil` to detach the current receiver
    /// (e.g. on logout). Hosts should construct with ``init(configuration:ratchetConfiguration:)``.
    ///
    /// - Parameter conformer: A ``MessageStoreObserver`` conformer or `nil`.
    func setReceiverDelegate(conformer: (any MessageStoreObserver)?) {
        receiverDelegate = conformer
    }

    /// Sets the policy delegate for sender resolution, persistence, and
    /// compromise notifications.
    ///
    /// Unlike ``setReceiverDelegate(conformer:)`` this method only updates
    /// the delegate when a non-`nil` value is passed; pass an explicit
    /// implementation to swap policies without nulling out the current one.
    ///
    /// - Parameter conformer: A ``PQSHostDelegate`` conformer.
    func setPQSSessionDelegate(conformer: (any PQSHostDelegate)?) async {
        if let conformer {
            sessionDelegate = conformer
        }
    }

    /// Overrides the default ``ContactService`` implementation with a custom
    /// conformer.
    ///
    /// `ContactService` is an *override surface* — the SDK ships a complete
    /// default in a protocol extension. Only call this when you need to
    /// replace the default contact, friendship, or message-state
    /// side effects. As with ``setPQSSessionDelegate(conformer:)``, this
    /// method only updates the delegate when a non-`nil` value is passed.
    ///
    /// - Parameter conformer: A ``ContactService`` conformer.
    func setSessionEventDelegate(conformer: (any ContactService)?) async {
        if let conformer {
            eventDelegate = conformer
        }
    }

}

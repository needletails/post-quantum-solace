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
/// - `SessionTransport` - Network communication and key distribution
/// - `PQSSessionStore` - Persistent storage and caching
/// - `EventReceiver` - Event handling and UI updates
/// - `PQSSessionDelegate` - Application-specific session logic
///
/// ## Usage Example
///
/// ```swift
/// // Initialize the session
/// let session = PQSSession.shared
///
/// // Set up delegates
/// await session.setTransportDelegate(conformer: myTransport)
/// await session.setDatabaseDelegate(conformer: myStore)
/// session.setReceiverDelegate(conformer: myReceiver)
///
/// // Create a new session
/// try await session.createSession(
///     secretName: "alice",
///     appPassword: "securePassword",
///     createInitialTransport: setupTransport
/// )
///
/// // Start the session
/// try await session.startSession(appPassword: "securePassword")
///
/// // Send a message
/// try await session.writeTextMessage(
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
/// All methods throw specific `SessionErrors` that conform to `LocalizedError`,
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
/// - `SessionErrors.sessionNotInitialized` - Session not properly set up
/// - `SessionErrors.databaseNotInitialized` - Storage not configured
/// - `SessionErrors.transportNotInitialized` - Network layer not ready
/// - `SessionErrors.invalidSignature` - Cryptographic verification failed
/// - `SessionErrors.cannotFindOneTimeKey` - No available keys for recipient
/// - `SessionErrors.drainedKeys` - All local keys have been used
///
/// ### Example
///
/// ```swift
/// do {
///     try await session.writeTextMessage(...)
/// } catch let error as SessionErrors {
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
/// - Important: This actor is designed as a singleton. Always use `PQSSession.shared`
///   rather than creating new instances.
public actor PQSSession: NetworkDelegate, SessionCacheSynchronizer {
    /// Unique identifier for the session instance.
    /// This ID is generated once and remains constant for the lifetime of the session.
    nonisolated let id = UUID()

    /// Indicates whether the session is viable for cryptographic operations.
    ///
    /// This property is set to `true` when the session is properly initialized
    /// with all required delegates and cryptographic keys. It becomes `false`
    /// when the session is shut down or encounters critical errors.
    ///
    /// - Important: Always check this property before performing cryptographic operations.
    public nonisolated(unsafe) var isViable: Bool = false

    /// The shared singleton instance of `PQSSession`.
    ///
    /// Use this instance throughout your application to ensure consistent
    /// session state and avoid conflicts between multiple session managers.
    ///
    /// - Important: Never create new instances of `PQSSession`. Always use this shared instance.
    public static let shared = PQSSession()

    /// Public initializer to enforce singleton usage.
    ///
    /// This initializer is provided to support the singleton pattern.
    /// In practice, you should always use `PQSSession.shared` instead.
    public init(_ ratchetConfiguration: RatchetConfiguration? = nil) {
        taskProcessor = TaskProcessor(logger: logger, ratchetConfiguration: ratchetConfiguration)
    }

    private(set) var _sessionContext: SessionContext?
    private var _appPassword = ""
    private(set) var taskProcessor: TaskProcessor
    private(set) var transportDelegate: (any SessionTransport)?
    private(set) var receiverDelegate: (any EventReceiver)?
    private(set) var sessionDelegate: (any PQSSessionDelegate)?
    private(set) var eventDelegate: (any SessionEvents)?
    private var refreshOTKeysTask: Task<Bool, Never>?
    private var refreshMLKEMOTKeysTask: Task<Bool, Never>?

    var otkUploadCircuitOpen = false
    var otkUploadCircuitOpenedAt: Date?
    private let otkCircuitCooldownSeconds: TimeInterval = 300

    private func openOTKUploadCircuitAndScheduleRecovery() {
        otkUploadCircuitOpen = true
        otkUploadCircuitOpenedAt = Date()
        Task { [weak self] in
            guard let self else { return }
            try? await self.recoverFromSigningKeyMismatch()
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
    public var cache: SessionCache?
    
    let crypto = NeedleTailCrypto()
    var logger = NeedleTailLogger("[PQSSession]")
    var sessionIdentities = Set<String>()
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

    private func reconciliationPeerKey(sender: String, deviceId: UUID, flow: ReconciliationFlow) -> String {
        "\(automaticRotationPeerKey(sender: sender, deviceId: deviceId))|\(flow.rawValue)"
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
    
    /// Cooldown for peer resend/refresh requests triggered by inbound failures.
    let peerResendRequestCooldown: TimeInterval = 15

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
    
    /// Builds a stable key for peer-scoped automatic rotation throttling.
    func automaticRotationPeerKey(sender: String, deviceId: UUID) -> String {
        "\(sender)|\(deviceId.uuidString)"
    }
    
    enum InboundFailureDisposition: Sendable, Equatable {
        case dropAndIgnore
        case reconcileThenRequestResend
        case rotateAndRequestResend
        case rotate
    }

    enum InboundFailureKind: Sendable, Equatable {
        case securityViolation
        case sessionRepairNeeded
        case payloadRepairNeeded
        case dropOrQuarantine
    }

    enum PeerIdentityRefreshImpact: Sendable, Equatable {
        case noSessionImpact
        case resendRecommended
        case freshSessionRecommended
    }

    struct PeerIdentityRefreshAssessment: Sendable {
        let identities: [SessionIdentity]
        let impact: PeerIdentityRefreshImpact
    }
    
    struct InboundFailureClassification: Sendable {
        let failureClass: String
        let disposition: InboundFailureDisposition
        let kind: InboundFailureKind

        init(
            failureClass: String,
            disposition: InboundFailureDisposition,
            kind: InboundFailureKind? = nil
        ) {
            self.failureClass = failureClass
            self.disposition = disposition
            self.kind = kind ?? {
                switch disposition {
                case .dropAndIgnore:
                    return .dropOrQuarantine
                case .reconcileThenRequestResend:
                    return .sessionRepairNeeded
                case .rotateAndRequestResend, .rotate:
                    return .securityViolation
                }
            }()
        }
    }
    
    /// Builds a stable key for inbound failure policy.
    func inboundFailureKey(sender: String, deviceId: UUID, messageId: String, failureClass: String? = nil) -> String {
        guard let failureClass else {
            return "\(sender)|\(deviceId.uuidString)|\(messageId)"
        }
        return "\(sender)|\(deviceId.uuidString)|\(messageId)|\(failureClass)"
    }
    
    /// Builds a stable key for whole-message inbound failure quarantine.
    func inboundFailureQuarantineKey(sender: String, deviceId: UUID, messageId: String) -> String {
        "\(sender)|\(deviceId.uuidString)|\(messageId)"
    }

    /// Builds a stable key for resend requests scoped to a failed message for a peer/device.
    func peerResendRequestKey(sender: String, deviceId: UUID, failedMessageId: String) -> String {
        "\(sender)|\(deviceId.uuidString)|\(failedMessageId)"
    }
    
    /// Drops expired entries from inbound-failure policy state.
    func cleanupInboundFailurePolicy(now: Date = Date()) {
        inboundFailurePolicyUntil = inboundFailurePolicyUntil.filter { _, expiry in
            expiry > now
        }
    }
    
    /// Returns `true` when this inbound tuple has been recently quarantined.
    func isInboundFailureQuarantined(sender: String, deviceId: UUID, messageId: String, now: Date = Date()) -> Bool {
        cleanupInboundFailurePolicy(now: now)
        let key = inboundFailureQuarantineKey(sender: sender, deviceId: deviceId, messageId: messageId)
        guard let expiry = inboundFailurePolicyUntil[key] else {
            return false
        }
        return expiry > now
    }
    
    /// Quarantines a failed inbound tuple to suppress replay-induced loops.
    func quarantineInboundFailure(sender: String, deviceId: UUID, messageId: String, now: Date = Date()) {
        cleanupInboundFailurePolicy(now: now)
        let key = inboundFailureQuarantineKey(sender: sender, deviceId: deviceId, messageId: messageId)
        inboundFailurePolicyUntil[key] = now.addingTimeInterval(inboundFailurePolicyTTL)
    }
    
    /// Returns whether a specific inbound failure class should be suppressed for this tuple.
    func shouldSuppressInboundFailure(_ inbound: InboundTaskMessage, failureClass: String, now: Date = Date()) -> Bool {
        cleanupInboundFailurePolicy(now: now)
        let key = inboundFailureKey(
            sender: inbound.senderSecretName,
            deviceId: inbound.senderDeviceId,
            messageId: inbound.sharedMessageId,
            failureClass: failureClass
        )
        guard let expiry = inboundFailurePolicyUntil[key] else {
            return false
        }
        if hasPendingResendAfterReestablishment(
            sender: inbound.senderSecretName,
            deviceId: inbound.senderDeviceId,
            failedMessageId: inbound.sharedMessageId,
            now: now
        ) {
            return false
        }
        return expiry > now
    }
    
    /// Records failure-class suppression for a final inbound failure.
    /// Intentionally does not quarantine the whole message tuple: resend recovery reuses the same
    /// `sharedMessageId`, so tuple-wide quarantine would drop the replay before decryption.
    func markInboundFailure(_ inbound: InboundTaskMessage, failureClass: String, now: Date = Date()) {
        markInboundFailure(
            sender: inbound.senderSecretName,
            deviceId: inbound.senderDeviceId,
            messageId: inbound.sharedMessageId,
            failureClass: failureClass,
            now: now)
    }

    /// Records failure-class suppression once the associated recovery side effect is accepted.
    func markInboundFailure(
        sender: String,
        deviceId: UUID,
        messageId: String,
        failureClass: String,
        now: Date = Date()
    ) {
        cleanupInboundFailurePolicy(now: now)
        let key = inboundFailureKey(
            sender: sender,
            deviceId: deviceId,
            messageId: messageId,
            failureClass: failureClass
        )
        inboundFailurePolicyUntil[key] = now.addingTimeInterval(inboundFailurePolicyTTL)
    }

    func takeInboundFailureClasses(
        sender: String,
        deviceId: UUID,
        messageId: String,
        now: Date = Date()
    ) -> [String] {
        cleanupInboundFailurePolicy(now: now)
        let prefix = "\(sender)|\(deviceId.uuidString)|\(messageId)|"
        let matches = inboundFailurePolicyUntil.keys.filter { $0.hasPrefix(prefix) }
        for key in matches {
            inboundFailurePolicyUntil.removeValue(forKey: key)
        }
        return matches.map { String($0.dropFirst(prefix.count)) }
    }
    
    /// Returns whether automatic key rotation is currently allowed for this peer.
    func canAttemptAutomaticRotation(sender: String, deviceId: UUID, now: Date = Date()) -> Bool {
        let peerKey = automaticRotationPeerKey(sender: sender, deviceId: deviceId)
        if let lastGlobal = lastAutomaticRotationAt, now.timeIntervalSince(lastGlobal) < automaticRotationGlobalCooldown {
            return false
        }
        if let lastPeer = lastAutomaticRotationAtByPeer[peerKey], now.timeIntervalSince(lastPeer) < automaticRotationPeerCooldown {
            return false
        }
        return true
    }
    
    /// Records a successful automatic rotation attempt for cooldown gating.
    func markAutomaticRotationAttempt(sender: String, deviceId: UUID, now: Date = Date()) {
        let peerKey = automaticRotationPeerKey(sender: sender, deviceId: deviceId)
        lastAutomaticRotationAt = now
        pruneRecoveryTimestamps(&lastAutomaticRotationAtByPeer, ttl: automaticRotationPeerCooldown, now: now)
        lastAutomaticRotationAtByPeer[peerKey] = now
    }

    /// Bounds an in-memory recovery bookkeeping map: drops entries whose cooldown/TTL
    /// has already lapsed (they can no longer influence gating decisions) and evicts
    /// oldest entries beyond `PQSSessionConstants.recoveryTrackingMaxEntries`.
    private func pruneRecoveryTimestamps(
        _ map: inout [String: Date],
        ttl: TimeInterval,
        now: Date
    ) {
        map = map.filter { now.timeIntervalSince($0.value) < ttl }
        let cap = PQSSessionConstants.recoveryTrackingMaxEntries
        guard map.count >= cap else { return }
        let overflowKeys = map
            .sorted { $0.value < $1.value }
            .prefix(map.count - cap + 1)
            .map(\.key)
        for key in overflowKeys {
            map.removeValue(forKey: key)
        }
    }
    
    /// Returns whether a resend/refresh control request can be sent for this failed message.
    func canSendPeerResendRequest(sender: String, deviceId: UUID, failedMessageId: String, now: Date = Date()) -> Bool {
        let requestKey = peerResendRequestKey(sender: sender, deviceId: deviceId, failedMessageId: failedMessageId)
        if let lastSentAt = lastResendRequestAtByPeer[requestKey],
           now.timeIntervalSince(lastSentAt) < peerResendRequestCooldown {
            return false
        }
        return true
    }
    
    /// Marks a resend/refresh control request as sent for this failed message.
    func markPeerResendRequestSent(sender: String, deviceId: UUID, failedMessageId: String, now: Date = Date()) {
        let requestKey = peerResendRequestKey(sender: sender, deviceId: deviceId, failedMessageId: failedMessageId)
        pruneRecoveryTimestamps(&lastResendRequestAtByPeer, ttl: peerResendRequestCooldown, now: now)
        lastResendRequestAtByPeer[requestKey] = now
    }

    func deferPeerResendUntilReestablished(
        sender: String,
        deviceId: UUID,
        failedMessageId: String,
        failureClass: String,
        now: Date = Date(),
        notifyDelegate: Bool = true
    ) {
        cleanupPendingResendAfterReestablishment(now: now)
        let requestKey = peerResendRequestKey(sender: sender, deviceId: deviceId, failedMessageId: failedMessageId)
        pendingResendAfterReestablishment[requestKey] = PendingResendAfterReestablishment(
            senderName: sender,
            senderDeviceId: deviceId,
            failedSharedMessageId: failedMessageId,
            failureClass: failureClass,
            createdAt: now)
        guard notifyDelegate else { return }
        let delegate = sessionDelegate
        Task {
            await delegate?.inboundRecoveryDeferred(
                senderSecretName: sender,
                senderDeviceId: deviceId,
                failedSharedMessageId: failedMessageId,
                failureClass: failureClass)
        }
    }

    func hasPendingResendAfterReestablishment(
        sender: String,
        deviceId: UUID,
        now: Date = Date()
    ) -> Bool {
        cleanupPendingResendAfterReestablishment(now: now)
        return pendingResendAfterReestablishment.values.contains { pending in
            pending.senderName == sender && pending.senderDeviceId == deviceId
        }
    }

    func hasPendingResendAfterReestablishment(
        sender: String,
        deviceId: UUID,
        failedMessageId: String,
        now: Date = Date()
    ) -> Bool {
        cleanupPendingResendAfterReestablishment(now: now)
        let requestKey = peerResendRequestKey(sender: sender, deviceId: deviceId, failedMessageId: failedMessageId)
        return pendingResendAfterReestablishment[requestKey] != nil
    }

    func takePendingResendsAfterReestablishment(
        sender: String,
        deviceId: UUID,
        satisfiedSharedMessageId: String? = nil,
        now: Date = Date()
    ) -> [PendingResendAfterReestablishment] {
        cleanupPendingResendAfterReestablishment(now: now)
        let matches = pendingResendAfterReestablishment.filter { _, pending in
            pending.senderName == sender && pending.senderDeviceId == deviceId
        }
        for (key, _) in matches {
            pendingResendAfterReestablishment.removeValue(forKey: key)
        }
        return matches.values.filter { pending in
            pending.failedSharedMessageId != satisfiedSharedMessageId
        }
    }

    private func cleanupPendingResendAfterReestablishment(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-inboundFailurePolicyTTL)
        pendingResendAfterReestablishment = pendingResendAfterReestablishment.filter { _, pending in
            pending.createdAt > cutoff
        }
        let cap = PQSSessionConstants.recoveryTrackingMaxEntries
        guard pendingResendAfterReestablishment.count >= cap else { return }
        let overflowKeys = pendingResendAfterReestablishment
            .sorted { $0.value.createdAt < $1.value.createdAt }
            .prefix(pendingResendAfterReestablishment.count - cap + 1)
            .map(\.key)
        for key in overflowKeys {
            pendingResendAfterReestablishment.removeValue(forKey: key)
        }
    }

    /// Sets the logger log level for both the session and task processor
    ///
    /// - Parameter level: The log level to set (e.g., `.debug`, `.info`, `.error`)
    public func setLogLevel(_ level: Level) async {
        logger.setLogLevel(level)
        await taskProcessor.setLogLevel(level)
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
        sessionIdentities.remove(secretName)
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

            var inactive: [(identity: SessionIdentity, archivedAt: TimeInterval)] = []
            for identity in all {
                guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
                guard props.secretName == secretName, props.deviceId == deviceId else { continue }
                guard isInactiveSessionIdentity(deviceName: props.deviceName) else { continue }
                inactive.append((identity, archivedAtSeconds(fromSessionContextId: props.sessionContextId)))
            }

            // Age bound
            for item in inactive where (now - item.archivedAt) > PQSSessionConstants.inactiveSessionMaxAgeSeconds {
                try await cache.deleteSessionIdentity(item.identity.id)
            }

            // Re-fetch and enforce count bound (newest-first by archivedAt)
            let remaining = try await cache.fetchSessionIdentities()
            var remainingInactive: [(identity: SessionIdentity, archivedAt: TimeInterval)] = []
            for identity in remaining {
                guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
                guard props.secretName == secretName, props.deviceId == deviceId else { continue }
                guard isInactiveSessionIdentity(deviceName: props.deviceName) else { continue }
                remainingInactive.append((identity, archivedAtSeconds(fromSessionContextId: props.sessionContextId)))
            }

            remainingInactive.sort { $0.archivedAt > $1.archivedAt }
            if remainingInactive.count > PQSSessionConstants.inactiveSessionMaxCountPerDevice {
                for item in remainingInactive.dropFirst(PQSSessionConstants.inactiveSessionMaxCountPerDevice) {
                    try await cache.deleteSessionIdentity(item.identity.id)
                }
            }
        } catch {
            logger.log(level: .warning, message: "Failed inactive session snapshot cleanup for \(secretName): \(error)")
        }
    }
    
    
    /// Prunes all stale inactive session snapshots across every `(secretName, deviceId)` pair.
    /// Called at session startup to clean up archives that expired while the app was offline.
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
            guard props.state != nil else { continue }
            guard let props = await identity.props(symmetricKey: symmetricKey) else {
                throw RatchetError.missingProps
            }
            switch policy {
            case .archive:
                // Creation: one new snapshot per matching active identity (no cap at create time).
                // Retention: cleanupInactiveSessionSnapshots (called below) enforces count and age bounds
                // (inactiveSessionMaxCountPerDevice, inactiveSessionMaxAgeSeconds) so we keep the newest N per device.
                let archived = try SessionIdentity(
                    id: UUID(),
                    props: .init(
                        secretName: props.secretName,
                        deviceId: props.deviceId,
                        sessionContextId: Int(Date().timeIntervalSince1970),
                        longTermPublicKey: props.longTermPublicKey,
                        signingPublicKey: props.signingPublicKey,
                        mlKEMPublicKey: props.mlKEMPublicKey,
                        oneTimePublicKey: props.oneTimePublicKey,
                        state: props.state,
                        deviceName: PQSSessionConstants.inactiveSessionDeviceNamePrefix + props.deviceName,
                        isMasterDevice: props.isMasterDevice
                    ),
                    symmetricKey: symmetricKey)
                try await cache.createSessionIdentity(archived)
                logger.log(level: .debug, message: "Archived ratchet state for \(props.secretName) (\(props.deviceId))")
                
            case .drop:
                for archived in try await cache.fetchSessionIdentities() {
                    guard let aProps = await archived.props(symmetricKey: symmetricKey) else { continue }
                    guard aProps.secretName == props.secretName, aProps.deviceId == props.deviceId else { continue }
                    guard isInactiveSessionIdentity(deviceName: aProps.deviceName) else { continue }
                    try await cache.deleteSessionIdentity(archived.id)
                }
            }
            
            // Opportunistic cleanup: bound inactive snapshots per device.
            await cleanupInactiveSessionSnapshots(
                cache: cache,
                symmetricKey: symmetricKey,
                secretName: props.secretName,
                deviceId: props.deviceId)
        }
    }

    // Synchronizes the local configuration with the provided data
    func synchronizeLocalConfiguration(_ data: Data) async throws {
        let symmetricKey = try await getAppSymmetricKey()
        guard let decryptedData = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else { return }
        let context = try BinaryDecoder().decode(SessionContext.self, from: decryptedData)
        await setSessionContext(context)
    }

    /// Sets the transport delegate conforming to `SessionTransport`.
    /// - Parameter conformer: The conforming object to set as the transport delegate.
    public func setTransportDelegate(conformer: (any SessionTransport)?) async {
        transportDelegate = conformer
        await taskProcessor.setDelegate(conformer)
    }

    /// Sets the database delegate conforming to `IdentityStore`.
    /// - Parameter conformer: The conforming object to set as the identity store.
    public func setDatabaseDelegate(conformer: (any PQSSessionStore)?) async {
        if let conformer {
            cache = SessionCache(store: conformer)
            await cache?.setSynchronizer(self)
        }
    }

    /// Sets (or clears) the application-facing event receiver.
    ///
    /// The receiver hears about lifecycle changes — created/updated/deleted
    /// messages, new contacts, new channels — and is what your UI layer
    /// usually conforms to. Pass `nil` to detach the current receiver
    /// (e.g. on logout). Prefer ``configure(with:)`` for the initial wiring.
    ///
    /// - Parameter conformer: An ``EventReceiver`` conformer or `nil`.
    public func setReceiverDelegate(conformer: (any EventReceiver)?) {
        receiverDelegate = conformer
    }

    /// Sets the policy delegate for sender resolution, persistence, and
    /// compromise notifications.
    ///
    /// Unlike ``setReceiverDelegate(conformer:)`` this method only updates
    /// the delegate when a non-`nil` value is passed; pass an explicit
    /// implementation to swap policies without nulling out the current one.
    ///
    /// - Parameter conformer: A ``PQSSessionDelegate`` conformer.
    public func setPQSSessionDelegate(conformer: (any PQSSessionDelegate)?) async {
        if let conformer {
            sessionDelegate = conformer
        }
    }

    /// Overrides the default ``SessionEvents`` implementation with a custom
    /// conformer.
    ///
    /// `SessionEvents` is an *override surface* — the SDK ships a complete
    /// default in a protocol extension. Only call this when you need to
    /// replace the default contact, friendship, or message-state
    /// side effects. As with ``setPQSSessionDelegate(conformer:)``, this
    /// method only updates the delegate when a non-`nil` value is passed.
    ///
    /// - Parameter conformer: A ``SessionEvents`` conformer.
    public func setSessionEventDelegate(conformer: (any SessionEvents)?) async {
        if let conformer {
            eventDelegate = conformer
        }
    }

    /// Configures the session with all required delegates in a single call.
    ///
    /// This convenience method allows you to set up all session delegates at once,
    /// ensuring proper initialization order and reducing boilerplate code.
    ///
    /// - Parameter configuration: The session configuration containing all delegates.
    ///   Must include at minimum: transport, store, and receiver.
    /// - Throws: An error if configuration fails (currently no errors are thrown,
    ///   but this is reserved for future validation).
    ///
    /// ## Usage Example
    /// ```swift
    /// try await session.configure(with: SessionConfiguration(
    ///     transport: myTransport,
    ///     store: myStore,
    ///     receiver: myReceiver,
    ///     delegate: myDelegate,
    ///     eventDelegate: myEventDelegate
    /// ))
    /// ```
    public func configure(with configuration: SessionConfiguration) async throws {
        await setTransportDelegate(conformer: configuration.transport)
        await setDatabaseDelegate(conformer: configuration.store)
        setReceiverDelegate(conformer: configuration.receiver)
        if let delegate = configuration.delegate {
            await setPQSSessionDelegate(conformer: delegate)
        }
        if let eventDelegate = configuration.eventDelegate {
            await setSessionEventDelegate(conformer: eventDelegate)
        }
    }

    /// Enum representing various session-related errors
    public enum SessionErrors: String, Error, LocalizedError {
        case saltError = "Salt error occurred."
        case databaseNotInitialized = "Database is not initialized."
        case sessionNotInitialized = "Session is not initialized."
        case transportNotInitialized = "Transport is not initialized."
        case sessionEncryptionError = "Session encryption error."
        case sessionDecryptionError = "Session decryption error."
        case connectionIsNonViable = "Connection is non-viable."
        case invalidPassword = "Invalid password."
        case invalidSecretName = "Invalid secret name."
        case invalidDeviceIdentity = "Invalid device identity."
        case missingSessionIdentity = "Missing session identity."
        case invalidSignature = "Invalid signature."
        case missingSignature = "Missing signature."
        case configurationError = "Configuration error."
        case cannotFindCommunication = "Cannot find communication."
        case cannotFindContact = "Cannot find contact."
        case propsError = "Properties error."
        case appPasswordError = "Application password error."
        case registrationError = "Registration error."
        case userExists = "User already exists."
        case cannotFindUserConfiguration = "Cannot find user configuration."
        case cannotFindOneTimeKey = "Cannot find a one-time key for the user."
        case oneTimeKeyUploadFailed = "Failed to upload one-time key for the user."
        case oneTimeKeyDeletionFailed = "Failed to delete one-time key for the user."
        case unknownError = "An unknown error occurred."
        case missingAuthInfo = "Missing authentication information in the payload."
        case userNotFound = "Could not find the user requested."
        case accessDenied = "Denied access to the requested resource."
        case userIsBlocked = "The user is blocked; cannot request friendship changes."
        case missingMessage = "The message cannot be processed because it is missing."
        case missingMetadata = "The metadata is missing."
        case invalidDocument = "The document is invalid."
        case receiverDelegateNotSet = "The receiver delegate is not set."
        case invalidKeyId = "The Key ID is invalid."
        case drainedKeys = "The Local Keys are drained."
        case longTermKeyRotationFailed = "Failed to rotate the long-term key."
        case signingKeyOutOfSync = "Local signing key is out of sync with server-trusted account state."
        case peerSigningKeyOutOfSync = "Peer account signing key is out of sync with the locally pinned contact identity."
        case compromiseRotationRequiresMasterDevice = "Compromise key rotation is restricted to the master device."
        case invalidOperatorCount = "The number of operators must be greater than 0."
        case invalidMemberCount = "The number of members must be at least 2."
        case signingKeyMismatchWithServer = "Local signing key does not match server's stored device signing key."
        case deviceIdentityCorrupted = "This device's identity is unrecoverable; re-link from your master device."
        
        public var errorDescription: String? {
            rawValue
        }
        
        public var failureReason: String? {
            switch self {
            case .databaseNotInitialized:
                return "The database delegate has not been configured"
            case .sessionNotInitialized:
                return "The session has not been created or started"
            case .transportNotInitialized:
                return "The transport delegate has not been configured"
            case .sessionDecryptionError:
                return "Failed to decrypt the session data"
            case .sessionEncryptionError:
                return "Failed to encrypt the session data"
            case .cannotFindOneTimeKey:
                return "No available one-time keys for the recipient"
            case .drainedKeys:
                return "All local one-time keys have been used"
            case .invalidKeyId:
                return "The provided key identifier is invalid or expired"
            case .invalidSignature:
                return "The cryptographic signature verification failed"
            case .missingSignature:
                return "The expected signature was not found"
            case .peerSigningKeyOutOfSync:
                return "The peer's account signing key no longer matches the locally pinned contact identity"
            case .invalidPassword:
                return "The provided password is incorrect or invalid"
            case .saltError:
                return "Failed to retrieve or generate the device salt"
            default:
                return nil
            }
        }
        
        public var recoverySuggestion: String? {
            switch self {
            case .databaseNotInitialized:
                return "Configure the database delegate using configure(with:) or setDatabaseDelegate(conformer:)"
            case .sessionNotInitialized:
                return "Call createSession() and startSession(appPassword:) before performing operations"
            case .transportNotInitialized:
                return "Configure the transport delegate using configure(with:) or setTransportDelegate(conformer:)"
            case .cannotFindOneTimeKey, .drainedKeys:
                return "Wait for the system to automatically generate new one-time keys, or manually trigger key refresh"
            case .invalidKeyId:
                return "Verify the key identifier and ensure keys are properly synchronized"
            case .sessionDecryptionError, .sessionEncryptionError:
                return "Verify the session is properly initialized and keys are valid"
            case .receiverDelegateNotSet:
                return "Configure the receiver delegate using setReceiverDelegate(conformer:)"
            case .invalidPassword:
                return "Verify the password is correct and try again"
            case .saltError:
                return "Ensure the device salt is properly initialized"
            case .signingKeyOutOfSync:
                return "Re-link this device from a trusted device or reset account keys"
            case .peerSigningKeyOutOfSync:
                return "Pause communication with this peer until the user verifies and accepts the new safety number"
            case .compromiseRotationRequiresMasterDevice:
                return "Initiate compromise rotation from the master device, then re-link secondary devices if needed"
            case .deviceIdentityCorrupted:
                return "This device's local identity no longer matches the server. Re-link this device from your master device."
            default:
                return nil
            }
        }
    }

    /// A bundle of cryptographic material produced for a single device.
    ///
    /// Returned by ``createDeviceCryptographicBundle(isMaster:)`` during
    /// account creation and device-link bootstrap. Bundles the freshly
    /// generated long-term ``DeviceKeys``, the resulting
    /// ``UserDeviceConfiguration`` (signed and ready to be added to a
    /// ``UserConfiguration``), and the in-memory ``UserConfiguration``
    /// snapshot the SDK uses to publish the new device.
    public struct CryptographicBundle: Sendable {
        /// Long-term curve / signing / ML-KEM material for this device.
        public let deviceKeys: DeviceKeys
        /// Per-device configuration to be added to the account-level
        /// ``UserConfiguration``.
        public let deviceConfiguration: UserDeviceConfiguration
        /// The (possibly newly minted) account-level ``UserConfiguration``
        /// containing this device.
        public let userConfiguration: UserConfiguration
    }

    /// A typed `(publicKey, privateKey)` pair tagged with a stable UUID.
    ///
    /// The SDK uses `KeyPair` for one-time prekey generation and for the
    /// long-term signing / agreement keys so every key has a unique
    /// identifier independent of its serialized representation.
    public struct KeyPair<Public, Private> {
        /// Stable identifier for the pair.
        public let id: UUID
        /// Public half of the pair.
        public let publicKey: Public
        /// Private half of the pair. Treat as secret.
        public let privateKey: Private

        public init(id: UUID, publicKey: Public, privateKey: Private) {
            self.id = id
            self.publicKey = publicKey
            self.privateKey = privateKey
        }
    }

    struct PrivateKeys: Sendable {
        let curve: Curve25519.KeyAgreement.PrivateKey
        let signing: Curve25519.Signing.PrivateKey
        let mlKem: MLKEM1024.PrivateKey
    }

    func createLongTermKeys() throws -> PrivateKeys {
        let curve = crypto.generateCurve25519PrivateKey()
        let signing = crypto.generateCurve25519SigningPrivateKey()
        let mlKem = try crypto.generateMLKem1024PrivateKey()
        return PrivateKeys(
            curve: curve,
            signing: signing,
            mlKem: mlKem
        )
    }

    /// Creates a cryptographic bundle for a device, including keys and configurations.
    ///
    /// This asynchronous function generates a set of cryptographic keys for a device,
    /// either as a master device or a child device. It creates long-term and one-time
    /// keys, signs the device configuration, and prepares the data for publishing to
    /// the server. The generated keys can be presented as a QR code for easy scanning
    /// by other devices.
    ///
    /// - Parameter isMaster: A boolean indicating whether the device being created is
    ///                       a master device or a child device.
    ///
    /// - Throws:
    ///   - `CryptoErrors`: If there is an error generating keys or creating configurations.
    ///
    /// - Returns: A `CryptographicBundle` containing the generated device keys, device
    ///            configuration, and user configuration.
    public func createDeviceCryptographicBundle(isMaster: Bool) async throws -> CryptographicBundle {
        let longTerm = try createLongTermKeys()

        // Generate one-time key pairs
        let curveOneTimeKeyPairs: [KeyPair] = try (0 ..< PQSSessionConstants.oneTimeKeyBatchSize).map { _ in
            let id = UUID()
            let privateKey = crypto.generateCurve25519PrivateKey()
            let privateKeyRep = try CurvePrivateKey(id: id, privateKey.rawRepresentation)
            let publicKey = try CurvePublicKey(id: id, privateKey.publicKey.rawRepresentation)
            return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }

        let mlKEMOneTimeKeyPairs: [KeyPair] = try (0 ..< PQSSessionConstants.oneTimeKeyBatchSize).map { _ in
            let id = UUID()
            let privateKey = try crypto.generateMLKem1024PrivateKey()
            let privateKeyRep = try MLKEMPrivateKey(id: id, privateKey.encode())
            let publicKey = try MLKEMPublicKey(id: id, privateKey.publicKey.rawRepresentation)
            return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }

        let mlKEMId = UUID()
        let mlKEMPrivateKey = try MLKEMPrivateKey(id: mlKEMId, longTerm.mlKem.encode())
        let mlKEMPublicKey = try MLKEMPublicKey(id: mlKEMId, longTerm.mlKem.publicKey.rawRepresentation)

        // Create a unique device ID
        let deviceId = UUID()

        // Generate HMAC data for the device
        let hmacData = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }

        // Create device keys object
        let deviceKeys = DeviceKeys(
            deviceId: deviceId,
            signingPrivateKey: longTerm.signing.rawRepresentation,
            longTermPrivateKey: longTerm.curve.rawRepresentation,
            oneTimePrivateKeys: curveOneTimeKeyPairs.map(\.privateKey),
            mlKEMOneTimePrivateKeys: mlKEMOneTimeKeyPairs.map(\.privateKey),
            finalMLKEMPrivateKey: mlKEMPrivateKey,
            rotateKeysDate: Calendar.current.date(byAdding: .weekOfYear, value: 1, to: Date())
        )

        // Create a user device configuration
        let device = UserDeviceConfiguration(
            deviceId: deviceKeys.deviceId,
            signingPublicKey: longTerm.signing.publicKey.rawRepresentation,
            longTermPublicKey: longTerm.curve.publicKey.rawRepresentation,
            finalMLKEMPublicKey: mlKEMPublicKey,
            deviceName: getDeviceName(),
            hmacData: hmacData,
            isMasterDevice: isMaster,
            lastSeenAt: Date()
        )

        // Sign the device configuration
        let signedDeviceConfiguration = try UserConfiguration.SignedDeviceConfiguration(
            device: device,
            signingKey: longTerm.signing
        )

        // Create signed public one-time keys for each one-time key pair
        let signedOneTimePublicKeys: [UserConfiguration.SignedOneTimePublicKey] = try curveOneTimeKeyPairs.map { keyPair in
            try UserConfiguration.SignedOneTimePublicKey(
                key: keyPair.publicKey,
                deviceId: deviceId,
                signingKey: longTerm.signing
            )
        }

        let signedPublicMLKEMOneTimeKeys: [UserConfiguration.SignedMLKEMOneTimeKey] = try mlKEMOneTimeKeyPairs.map { keyPair in
            try UserConfiguration.SignedMLKEMOneTimeKey(
                key: keyPair.publicKey,
                deviceId: deviceId,
                signingKey: longTerm.signing
            )
        }

        let signedDeviceKeyBundle = try UserConfiguration.SignedDeviceKeyBundle(
            bundle: .init(
                deviceId: deviceId,
                longTermPublicKey: longTerm.curve.publicKey.rawRepresentation,
                finalMLKEMPublicKey: mlKEMPublicKey
            ),
            signingKey: longTerm.signing
        )

        // Create the user configuration with the signed device and keys
        let userConfiguration = UserConfiguration(
            signingPublicKey: longTerm.signing.publicKey.rawRepresentation,
            signedDevices: [signedDeviceConfiguration],
            signedOneTimePublicKeys: signedOneTimePublicKeys,
            signedMLKEMOneTimePublicKeys: signedPublicMLKEMOneTimeKeys,
            signedDeviceKeyBundles: [signedDeviceKeyBundle]
        )

        // Return the complete cryptographic bundle
        return CryptographicBundle(
            deviceKeys: deviceKeys,
            deviceConfiguration: device,
            userConfiguration: userConfiguration
        )
    }

    /// Generates a symmetric key for database encryption.
    ///
    /// This private function creates a symmetric key of 256 bits for encrypting
    /// database models. The key is returned as a `Data` object.
    ///
    /// - Returns: A `Data` object representing the generated database encryption key.
    private func generateDatabaseEncryptionKey() -> Data {
        let databaseSymmetricKey = SymmetricKey(size: .bits256)
        return databaseSymmetricKey.withUnsafeBytes { Data($0) }
    }

    /// Creates a new session with the provided secret name and application password.
    ///
    /// This method generates cryptographic keys, retrieves necessary salts, and attempts to create a session
    /// for the user. It handles both the registration of a new device and the retrieval of existing user
    /// configurations. If the connection is not viable, an error is thrown.
    ///
    /// - Parameters:
    ///   - secretName: The name of the secret associated with the session.
    ///   - appPassword: The application password used for encryption and session management.
    /// - Returns: A `PQSSession` object representing the created session.
    /// - Throws: An error of type `SessionErrors` if the session creation fails due to various reasons.
    public func createSession(
        secretName: String,
        appPassword: String,
        createInitialTransport: @Sendable @escaping () async throws -> Void
    ) async throws -> PQSSession {
        await setAppPassword(appPassword)
        // Match the canonical normalization used by the transport layer and
        // by `createContact` so the local user's identity stays consistent
        // with how it'll be referenced by every other code path.
        let secretName = secretName.pqsCanonicalSecretName
        // Ensure identity store is initialized
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }

        let bundle = try await createDeviceCryptographicBundle(isMaster: true)
        let sessionUser = SessionUser(
            secretName: secretName,
            deviceId: bundle.deviceKeys.deviceId,
            deviceKeys: bundle.deviceKeys)

        var sessionContext = SessionContext(
            sessionUser: sessionUser,
            databaseEncryptionKey: generateDatabaseEncryptionKey(),
            sessionContextId: .random(in: 1 ..< .max),
            activeUserConfiguration: bundle.userConfiguration,
            registrationState: .unregistered
        )
        await setSessionContext(sessionContext)

        guard let passwordData = appPassword.data(using: .utf8) else {
            throw SessionErrors.appPasswordError
        }

        // Retrieve salt and derive symmetric key
        let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)

        let appSymmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )

        let databaseEncryptionKey = try await getDatabaseSymmetricKey()

        try await createInitialTransport()

        // Check if the connection is viable
        guard isViable else {
            throw SessionErrors.connectionIsNonViable
        }

        // Attempt to find user configuration and handle registration
        do {
            // We are registering a new device to the main device if this succeeds
            if try await transportDelegate?.findConfiguration(for: secretName) != nil {
                throw SessionErrors.userExists
            }

            // SHOULD NEVER HAPPEN
            throw SessionErrors.unknownError
        } catch let sessionError as SessionErrors {
            switch sessionError {
            case .userExists:
                throw sessionError

            case .userNotFound:
                // UserConfiguration does not contain Private keys/info... so it should be safe to store publicly.
                try await transportDelegate?.publishUserConfiguration(
                    bundle.userConfiguration,
                    recipient: secretName,
                    recipient: bundle.deviceKeys.deviceId
                )

                sessionContext.registrationState = .registered
                await setSessionContext(sessionContext)

                let encodedData = try BinaryEncoder().encode(sessionContext)
                guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: appSymmetricKey) else {
                    throw SessionErrors.sessionEncryptionError
                }

                // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
                try await cache.createLocalSessionContext(encryptedConfig)

                // Create Communication Model for personal messages
                self.logger.log(level: .debug, message: "Creating Communication Model")

                let communicationModel = try await taskProcessor.createCommunicationModel(
                    recipients: [secretName],
                    communicationType: .personalMessage,
                    symmetricKey: databaseEncryptionKey
                )

                guard var props = await communicationModel.props(symmetricKey: databaseEncryptionKey) else {
                    throw PQSSession.SessionErrors.propsError
                }
                // Used to communicated between personal messages in this case
                props.sharedId = UUID()

                _ = try await communicationModel.updateProps(symmetricKey: databaseEncryptionKey, props: props)

                try await cache.createCommunication(communicationModel)
                await receiverDelegate?.updatedCommunication(communicationModel, members: [secretName])
                self.logger.log(level: .debug, message: "Created Communication Model")

            default:
                throw sessionError
            }
        } catch {
            logger.log(level: .error, message: "Error Creating Session, \(error)")
            throw error
        }
        return self
    }

    /// This call must be followed by start session.
    /// Links a device to the current session by generating cryptographic credentials.
    ///
    /// This asynchronous function links a new device to the current session by
    /// generating cryptographic credentials based on the provided device configuration
    /// and password. It creates a session identity, derives a symmetric key, and
    /// sets up the session context. It also creates a communication model for personal
    /// messages. This call must be followed by a call to `startSession`.
    ///
    /// - Parameters:
    ///   - bundle: A `CryptographicBundle` containing the device configuration and keys.
    ///   - password: A string representing the password used for cryptographic operations.
    ///
    /// - Throws:
    ///   - `SessionErrors.databaseNotInitialized`: If the cache is not initialized.
    ///   - `SessionErrors.appPasswordError`: If there is an error retrieving the password data.
    ///   - `SessionErrors.sessionEncryptionError`: If the session context cannot be encrypted successfully.
    ///   - `SessionErrors.registrationError`: If the device linking process fails.
    ///   - `PQSSession.SessionErrors.propsError`: If there is an error retrieving or updating properties in the communication model.
    ///
    /// - Returns: A `PQSSession` object representing the newly created session.
    public func linkDevice(
        bundle: CryptographicBundle,
        password: String
    ) async throws -> PQSSession {
        // Set the application password
        await setAppPassword(password)

        let linkConfig = try UserDeviceConfiguration(
            deviceId: bundle.deviceConfiguration.deviceId,
            signingPublicKey: Data(),
            longTermPublicKey: Data(),
            finalMLKEMPublicKey: .init(Data(count: 1568)),
            deviceName: bundle.deviceConfiguration.deviceName,
            hmacData: bundle.deviceConfiguration.hmacData,
            isMasterDevice: bundle.deviceConfiguration.isMasterDevice,
            lastSeenAt: Date()
        )

        // Encode the device configuration to prepare for QR code generation
        let data = try BinaryEncoder().encode(linkConfig)

        // Generate cryptographic credentials for device linking
        if let credentials = await linkDelegate?.generateDeviceCryptographic(data, password: password) {
            guard let cache else {
                throw SessionErrors.databaseNotInitialized
            }

            // Set the application password from the generated credentials
            await setAppPassword(credentials.password)

            // Create a Session Identity
            let sessionUser = SessionUser(
                secretName: credentials.secretName,
                deviceId: bundle.deviceKeys.deviceId,
                deviceKeys: bundle.deviceKeys)

            // Generate a symmetric key for encrypting local database models
            let databaseEncryptionKey = generateDatabaseEncryptionKey()

            let userConfiguration: UserConfiguration
            if var linkedConfiguration = credentials.userConfiguration {
                let verifiedDevices = try linkedConfiguration.getVerifiedDevices()
                guard let localDevice = verifiedDevices.first(where: { $0.deviceId == bundle.deviceKeys.deviceId }) else {
                    throw SessionErrors.invalidDeviceIdentity
                }
                let localSigningKey = try Curve25519.Signing.PrivateKey(
                    rawRepresentation: bundle.deviceKeys.signingPrivateKey)
                guard localDevice.signingPublicKey == localSigningKey.publicKey.rawRepresentation else {
                    throw SessionErrors.deviceIdentityCorrupted
                }

                let localCurveKeys = bundle.userConfiguration.signedOneTimePublicKeys.filter {
                    $0.deviceId == bundle.deviceKeys.deviceId
                }
                var curveKeysById = Dictionary(uniqueKeysWithValues: linkedConfiguration.signedOneTimePublicKeys.map {
                    ($0.id, $0)
                })
                for key in localCurveKeys {
                    curveKeysById[key.id] = key
                }
                linkedConfiguration.signedOneTimePublicKeys = Array(curveKeysById.values)

                let localMLKEMKeys = bundle.userConfiguration.signedMLKEMOneTimePublicKeys.filter {
                    $0.deviceId == bundle.deviceKeys.deviceId
                }
                var mlkemKeysById = Dictionary(uniqueKeysWithValues: linkedConfiguration.signedMLKEMOneTimePublicKeys.map {
                    ($0.id, $0)
                })
                for key in localMLKEMKeys {
                    mlkemKeysById[key.id] = key
                }
                linkedConfiguration.signedMLKEMOneTimePublicKeys = Array(mlkemKeysById.values)

                if let localBundle = bundle.userConfiguration.signedDeviceKeyBundles.last(where: {
                    $0.id == bundle.deviceKeys.deviceId
                }), !linkedConfiguration.signedDeviceKeyBundles.contains(where: {
                    $0.id == bundle.deviceKeys.deviceId
                }) {
                    linkedConfiguration.signedDeviceKeyBundles.append(localBundle)
                }
                try validateLinkedDeviceConfiguration(
                    linkedConfiguration,
                    localDeviceId: bundle.deviceKeys.deviceId
                )
                userConfiguration = linkedConfiguration
            } else {
                // Legacy link delegates only return bare devices. Keep this as a compatibility
                // fallback, but modern device linking should supply `userConfiguration`.
                userConfiguration = try await createNewUser(
                    configuration: bundle.userConfiguration,
                    signingPrivateKeyData: bundle.deviceKeys.signingPrivateKey,
                    devices: credentials.devices,
                    keys: bundle.userConfiguration.getVerifiedCurveKeys(deviceId: bundle.deviceKeys.deviceId),
                    mlKEMKeys: bundle.userConfiguration.getVerifiedMLKEMKeys(deviceId: bundle.deviceKeys.deviceId))
            }

            // Create a new session context with the session user and user configuration
            var sessionContext = SessionContext(
                sessionUser: sessionUser,
                databaseEncryptionKey: databaseEncryptionKey,
                sessionContextId: .random(in: 1 ..< .max),
                activeUserConfiguration: userConfiguration,
                registrationState: .unregistered)

            // Set the session context
            await setSessionContext(sessionContext)

            // Convert the password to data for deriving the symmetric key
            guard let passwordData = credentials.password.data(using: .utf8) else {
                throw SessionErrors.appPasswordError
            }

            // Retrieve salt and derive the symmetric key
            let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)
            let symmetricKey = await crypto.deriveStrictSymmetricKey(
                data: passwordData,
                salt: saltData)

            // Update the registration state to registered
            sessionContext.registrationState = .registered
            await setSessionContext(sessionContext)

            // Encode the updated session context for encryption
            let encodedData = try BinaryEncoder().encode(sessionContext)

            // Encrypt the session context using the derived symmetric key
            guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: symmetricKey) else {
                throw SessionErrors.sessionEncryptionError
            }

            // Create a local session context with the encrypted data
            try await cache.createLocalSessionContext(encryptedConfig)

            // Create a communication model for personal messages
            logger.log(level: .debug, message: "Creating Communication Model")
            let databaseSymmetricKey = try await getDatabaseSymmetricKey()
            let communicationModel = try await taskProcessor.createCommunicationModel(
                recipients: [credentials.secretName],
                communicationType: .personalMessage,
                symmetricKey: databaseSymmetricKey)

            // Update properties of the communication model
            guard var props = await communicationModel.props(symmetricKey: databaseSymmetricKey) else {
                throw PQSSession.SessionErrors.propsError
            }

            props.sharedId = UUID()

            // Update the communication model with the new properties
            _ = try await communicationModel.updateProps(symmetricKey: databaseSymmetricKey, props: props)

            // Create the communication in the cache
            try await cache.createCommunication(communicationModel)

            // Notify the receiver delegate about the updated communication model
            await receiverDelegate?.updatedCommunication(communicationModel, members: [credentials.secretName])
            logger.log(level: .debug, message: "Created Communication Model")

            // Start the session and return the PQSSession
            return try await startSession(appPassword: credentials.password)
        } else {
            throw SessionErrors.registrationError
        }
    }

    /// The local user's stable `SecurityIdentity`, suitable for computing safety
    /// numbers against a remote contact (`SecurityIdentity.safetyNumber(local:remote:)`).
    ///
    /// Returns `nil` if the session is not yet initialized.
    public func localSecurityIdentity() async -> SecurityIdentity? {
        guard let context = await sessionContext else { return nil }
        return SecurityIdentity(
            secretName: context.sessionUser.secretName,
            configuration: context.activeUserConfiguration
        )
    }

    private func validateLinkedDeviceConfiguration(
        _ configuration: UserConfiguration,
        localDeviceId: UUID
    ) throws {
        let verified = try configuration.getVerifiedDevices()
        guard verified.count == configuration.signedDevices.count,
              verified.contains(where: { $0.deviceId == localDeviceId })
        else {
            throw SessionErrors.invalidSignature
        }

        for signedBundle in configuration.signedDeviceKeyBundles {
            guard let device = verified.first(where: { $0.deviceId == signedBundle.id }) else {
                throw SessionErrors.invalidDeviceIdentity
            }
            let deviceSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: device.signingPublicKey)
            guard let bundle = try signedBundle.verified(using: deviceSigningKey),
                  bundle.deviceId == device.deviceId
            else {
                throw SessionErrors.invalidSignature
            }
        }
    }

    func userConfigurationPreservingLocalCurrentDeviceOneTimeKeys(
        _ incomingConfiguration: UserConfiguration,
        currentContext: SessionContext
    ) -> UserConfiguration {
        let deviceId = currentContext.sessionUser.deviceId
        guard let verifiedDevice = try? incomingConfiguration.getVerifiedDevices().first(where: {
            $0.deviceId == deviceId
        }),
              let deviceSigningKey = try? Curve25519.Signing.PublicKey(
                rawRepresentation: verifiedDevice.signingPublicKey
              )
        else {
            return incomingConfiguration
        }

        let localCurveKeys = currentContext.activeUserConfiguration.signedOneTimePublicKeys
            .filter { $0.deviceId == deviceId }
            .filter { (try? $0.verified(using: deviceSigningKey)) != nil }
        let localMLKEMKeys = currentContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys
            .filter { $0.deviceId == deviceId }
            .filter { (try? $0.verified(using: deviceSigningKey)) != nil }

        guard !localCurveKeys.isEmpty || !localMLKEMKeys.isEmpty else {
            return incomingConfiguration
        }

        var mergedConfiguration = incomingConfiguration
        if !localCurveKeys.isEmpty {
            mergedConfiguration.signedOneTimePublicKeys.removeAll { $0.deviceId == deviceId }
            mergedConfiguration.signedOneTimePublicKeys.append(contentsOf: localCurveKeys)
        }
        if !localMLKEMKeys.isEmpty {
            mergedConfiguration.signedMLKEMOneTimePublicKeys.removeAll { $0.deviceId == deviceId }
            mergedConfiguration.signedMLKEMOneTimePublicKeys.append(contentsOf: localMLKEMKeys)
        }

        return mergedConfiguration
    }

    /// Adopts a `UserConfiguration` that has already been verified against its own
    /// `signingPublicKey` (e.g. one returned from the server's `findConfiguration`
    /// endpoint, where every signed entry was produced by the master's account-level
    /// signing key).
    ///
    /// Use this from refresh / sync paths where the configuration originates from a
    /// trusted, already-verified source. Unlike `updateUserConfiguration(_:)`, this
    /// does NOT re-sign anything with the local device's per-device signing key, so it
    /// is safe on linked (child) devices whose per-device signing key intentionally
    /// differs from the account-level `signingPublicKey`.
    ///
    /// ## Trust model (TOFU)
    /// The account-level `signingPublicKey` is pinned on first set. A subsequent
    /// adoption whose `signingPublicKey` differs from the locally pinned value is
    /// rejected with `SessionErrors.signingKeyOutOfSync`. Legitimate rotations must
    /// arrive over a verified rotation channel (e.g. a master-signed reprovisioning
    /// bundle via `installLinkedDeviceReprovisioningBundle`, or this device performing
    /// its own `rotateKeysOnPotentialCompromise`), not a server refresh.
    ///
    /// - Parameter configuration: The fully-signed `UserConfiguration` to adopt.
    /// - Throws: `SessionErrors.invalidSignature` if `configuration` is not
    ///           internally consistent; `SessionErrors.signingKeyOutOfSync` if the
    ///           account signing key differs from the pinned value; plus the usual
    ///           session/cache errors.
    public func adoptVerifiedUserConfiguration(_ configuration: UserConfiguration) async throws {
        // 1. Internal consistency: every signed device must verify under the
        //    configuration's own signingPublicKey. `getVerifiedDevices` silently filters
        //    bad entries via compactMap, so cross-check the count.
        let verified = try configuration.getVerifiedDevices()
        guard verified.count == configuration.signedDevices.count else {
            throw SessionErrors.invalidSignature
        }
        for signedBundle in configuration.signedDeviceKeyBundles {
            guard let device = verified.first(where: { $0.deviceId == signedBundle.id }) else {
                throw SessionErrors.invalidDeviceIdentity
            }
            let deviceSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: device.signingPublicKey)
            guard let bundle = try signedBundle.verified(using: deviceSigningKey),
                  bundle.deviceId == device.deviceId
            else {
                throw SessionErrors.invalidSignature
            }
        }

        guard let cache else { return }
        let data = try await cache.fetchLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }

        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)

        // 2. TOFU pin on the account-level signing key. A change here is a security
        //    event (potential server-side identity swap) and must NOT be silently
        //    accepted. Legitimate rotations install via the reprovisioning bundle
        //    or `rotateKeysOnPotentialCompromise`, both of which update the local
        //    pin first, so a subsequent refresh sees a matching key.
        let pinnedKey = sessionContext.activeUserConfiguration.signingPublicKey
        if !pinnedKey.isEmpty, pinnedKey != configuration.signingPublicKey {
            logger.log(
                level: .error,
                message: "[adoptVerifiedUserConfiguration] account signing key changed without an authenticated rotation; refusing to adopt. pinnedPrefix=\(pinnedKey.prefix(8).map { String(format: "%02x", $0) }.joined()) incomingPrefix=\(configuration.signingPublicKey.prefix(8).map { String(format: "%02x", $0) }.joined())"
            )
            throw SessionErrors.signingKeyOutOfSync
        }

        sessionContext.activeUserConfiguration = userConfigurationPreservingLocalCurrentDeviceOneTimeKeys(
            configuration,
            currentContext: sessionContext
        )
        await setSessionContext(sessionContext)

        let encodedData = try BinaryEncoder().encode(sessionContext)
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encryptedConfig)
    }

    /// Explicitly clears the locally pinned account-level signing key and adopts
    /// `proposedConfiguration`'s signing key in its place. This is the **only**
    /// path allowed to overwrite the TOFU pin via a server-supplied configuration
    /// and is intended exclusively for an authenticated, user-initiated trust
    /// re-establishment after a legitimate rotation that bypassed the normal
    /// channels (lost master, restore-from-backup, server reset during private
    /// beta, etc.).
    ///
    /// > Important: Callers MUST gate this behind a strong, explicit user
    /// > confirmation (e.g. an in-app passcode, OS biometrics, or a typed
    /// > destructive phrase). Anyone who can call this can replace the trust
    /// > anchor for the local account; treat it like "remove all locks and
    /// > re-key the front door".
    ///
    /// On success, the new configuration's `signingPublicKey` becomes the new
    /// pin. Subsequent `adoptVerifiedUserConfiguration(_:)` calls (e.g. the
    /// background refresh path) will accept matching configurations and reject
    /// any further drift, restoring the normal TOFU invariant.
    ///
    /// The transition is logged at `.error` so it is grep-able in support
    /// triage even if the device's logs are filtered to errors only.
    ///
    /// - Parameter proposedConfiguration: A `UserConfiguration` whose internal
    ///   signatures verify against its own `signingPublicKey`. Typically
    ///   obtained by re-fetching `findConfiguration(for:)` from the transport.
    /// - Throws:
    ///   - `SessionErrors.invalidSignature` if the proposed configuration is
    ///     not internally consistent (signed devices don't all verify under
    ///     the configuration's own signing key).
    ///   - `SessionErrors.sessionDecryptionError` / `sessionEncryptionError`
    ///     for the usual cache/crypto failure modes.
    public func acknowledgeAccountIdentityChange(_ proposedConfiguration: UserConfiguration) async throws {
        // Internal consistency: never overwrite the pin with a malformed config.
        let verified = try proposedConfiguration.getVerifiedDevices()
        guard verified.count == proposedConfiguration.signedDevices.count else {
            throw SessionErrors.invalidSignature
        }

        guard let cache else { return }
        let data = try await cache.fetchLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }

        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)

        let oldKey = sessionContext.activeUserConfiguration.signingPublicKey
        let newKey = proposedConfiguration.signingPublicKey

        // Idempotent no-op: nothing to acknowledge.
        guard oldKey != newKey else {
            sessionContext.activeUserConfiguration = userConfigurationPreservingLocalCurrentDeviceOneTimeKeys(
                proposedConfiguration,
                currentContext: sessionContext
            )
            await setSessionContext(sessionContext)
            let encodedData = try BinaryEncoder().encode(sessionContext)
            guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
                throw PQSSession.SessionErrors.sessionEncryptionError
            }
            try await cache.updateLocalSessionContext(encryptedConfig)
            return
        }

        logger.log(
            level: .error,
            message: "[acknowledgeAccountIdentityChange] user-acknowledged account signing key change. oldPrefix=\(oldKey.prefix(8).map { String(format: "%02x", $0) }.joined()) newPrefix=\(newKey.prefix(8).map { String(format: "%02x", $0) }.joined()) deviceCount=\(verified.count)"
        )

        sessionContext.activeUserConfiguration = userConfigurationPreservingLocalCurrentDeviceOneTimeKeys(
            proposedConfiguration,
            currentContext: sessionContext
        )
        await setSessionContext(sessionContext)

        let encodedData = try BinaryEncoder().encode(sessionContext)
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encryptedConfig)
    }

    /// Updates the user's configuration with new device configurations.
    ///
    /// This asynchronous function updates the user's configuration by incorporating
    /// new device configurations. It retrieves the current session context from the
    /// cache, decrypts it, creates a new user configuration with the updated devices,
    /// and then re-encrypts the session context before saving it back to the cache.
    ///
    /// > Important: This is a **master-only** operation. It re-signs the resulting
    /// > `UserConfiguration` with the local device's signing key. On a linked (child)
    /// > device the per-device signing key intentionally differs from the account-level
    /// > `signingPublicKey`, so the resulting configuration would fail signature
    /// > verification. Calling this on a child throws `SessionErrors.signingKeyOutOfSync`.
    /// > Children should use `adoptVerifiedUserConfiguration(_:)` instead, which adopts
    /// > a server-signed configuration verbatim.
    ///
    /// - Parameter devices: An array of `UserDeviceConfiguration` objects representing
    ///                     the new devices to be associated with the user's configuration.
    ///
    /// - Throws:
    ///   - `SessionErrors.signingKeyOutOfSync`: If invoked on a linked (child) device.
    ///   - `SessionErrors.sessionDecryptionError`: If the session context cannot be
    ///     decrypted successfully.
    ///   - `PQSSession.SessionErrors.sessionEncryptionError`: If the updated session
    ///     context cannot be encrypted successfully.
    public func updateUserConfiguration(_ devices: [UserDeviceConfiguration]) async throws {
        // Retrieve the current session context from the cache
        guard let data = try await cache?.fetchLocalSessionContext() else { return }

        // Decrypt the session context data using the app's symmetric key
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }

        // Decode the session context from the decrypted data
        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)

        // Master-only invariant: the local device must own the account signing key.
        // On a linked child this comparison fails because the per-device signing key
        // intentionally differs from the account-level `signingPublicKey`.
        let localSigningPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey
        )
        let localSigningPublicKey = localSigningPrivateKey.publicKey.rawRepresentation
        guard localSigningPublicKey == sessionContext.activeUserConfiguration.signingPublicKey else {
            logger.log(
                level: .error,
                message: "[updateUserConfiguration] refusing to re-sign configuration on a non-master device. This path requires the account signing key; child devices must call adoptVerifiedUserConfiguration."
            )
            throw SessionErrors.signingKeyOutOfSync
        }

        // Create a new user configuration with the updated devices
        let userConfiguration = try await createNewUser(
            configuration: sessionContext.activeUserConfiguration,
            signingPrivateKeyData: sessionContext.sessionUser.deviceKeys.signingPrivateKey,
            devices: devices,
            keys: sessionContext.activeUserConfiguration.getVerifiedCurveKeys(deviceId: sessionContext.sessionUser.deviceId),
            mlKEMKeys: sessionContext.activeUserConfiguration.getVerifiedMLKEMKeys(deviceId: sessionContext.sessionUser.deviceId)
        )

        // Update the last user configuration in the session context
        sessionContext.activeUserConfiguration = userConfiguration

        // Save the updated session context back to the cache
        await setSessionContext(sessionContext)

        // Encode the updated session context to prepare for encryption
        let encodedData = try BinaryEncoder().encode(sessionContext)

        // Encrypt the updated session context using the app's symmetric key
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }

        // Update the local session context in the cache with the encrypted data
        try await cache?.updateLocalSessionContext(encryptedConfig)
    }

    /// Updates the user's public one-time keys in the session context.
    ///
    /// This asynchronous function updates the user's public one-time keys in the
    /// existing session context. It retrieves the current session context from the
    /// cache, decrypts it, updates the public one-time keys, and then re-encrypts
    /// the session context before saving it back to the cache.
    ///
    /// - Parameter keys: An array of `UserConfiguration.SignedoneTimePublicKey` objects
    ///                   representing the new public one-time keys to be associated
    ///                   with the user's configuration.
    ///
    /// - Throws:
    ///   - `SessionErrors.sessionDecryptionError`: If the session context cannot be
    ///     decrypted successfully.
    ///   - `PQSSession.SessionErrors.sessionEncryptionError`: If the updated session
    ///     context cannot be encrypted successfully.
    public func updateUseroneTimePublicKeys(_ keys: [UserConfiguration.SignedOneTimePublicKey]) async throws {
        // Retrieve the current session context from the cache
        guard let data = try await cache?.fetchLocalSessionContext() else { return }

        // Decrypt the session context data using the app's symmetric key
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }

        // Decode the session context from the decrypted data
        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)

        // Create a new UserConfiguration with the updated public one-time keys
        let userConfiguration = UserConfiguration(
            signingPublicKey: sessionContext.activeUserConfiguration.signingPublicKey,
            signedDevices: sessionContext.activeUserConfiguration.signedDevices,
            signedOneTimePublicKeys: keys,
            signedMLKEMOneTimePublicKeys: sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys,
            signedDeviceKeyBundles: sessionContext.activeUserConfiguration.signedDeviceKeyBundles
        )

        // Update the last user configuration in the session context
        sessionContext.activeUserConfiguration = userConfiguration

        // Save the updated session context back to the cache
        await setSessionContext(sessionContext)

        // Encode the updated session context to prepare for encryption
        let encodedData = try BinaryEncoder().encode(sessionContext)

        // Encrypt the updated session context using the app's symmetric key
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }

        // Update the local session context in the cache with the encrypted data
        try await cache?.updateLocalSessionContext(encryptedConfig)
    }

    /// Creates a new user configuration by signing device configurations and public keys.
    ///
    /// This asynchronous function takes a user configuration, a private signing key,
    /// a list of device configurations, and a list of public keys. It reconstructs the
    /// signing key, verifies the public signing key against the provided configuration,
    /// and signs each device configuration and public key with the private signing key.
    /// If any verification fails, an error is thrown.
    ///
    /// - Parameters:
    ///   - configuration: The initial user configuration containing the public signing key
    ///                    and a list of signed devices.
    ///   - signingPrivateKeyData: The raw data representation of the private signing key
    ///                            used for signing the device configurations and keys.
    ///   - devices: An array of `UserDeviceConfiguration` objects representing the devices
    ///              to be associated with the new user.
    ///   - keys: An array of `CurvePublicKey` objects representing the
    ///           public keys to be signed for the devices.
    ///
    /// - Throws:
    ///   - `PQSSession.SessionErrors.invalidSignature`: If the public signing key does
    ///     not match the reconstructed private signing key or if any device's signature
    ///     verification fails.
    ///
    /// - Returns: A new `UserConfiguration` object containing the public signing key,
    ///            signed device configurations, and signed public one-time keys.
    public func createNewUser(
        configuration: UserConfiguration,
        signingPrivateKeyData: Data,
        devices: [UserDeviceConfiguration],
        keys: [CurvePublicKey],
        mlKEMKeys: [MLKEMPublicKey]
    ) async throws -> UserConfiguration {
        // 1) Reconstruct your Curve25519 signing key
        let signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: signingPrivateKeyData
        )
        let signingPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: configuration.signingPublicKey)

        // Verify that the public signing key matches the reconstructed private signing key
        guard signingPublicKey.rawRepresentation == signingPrivateKey.publicKey.rawRepresentation else {
            throw PQSSession.SessionErrors.invalidSignature
        }

        // 2) Verify each signed device using the public signing key
        for device in configuration.signedDevices {
            if try (device.verified(using: signingPublicKey) != nil) == false {
                throw PQSSession.SessionErrors.invalidSignature
            }
        }

        // 3) For each device, build its SignedDeviceConfiguration
        let signedDevices: [UserConfiguration.SignedDeviceConfiguration] = try devices.map { device in
            try UserConfiguration.SignedDeviceConfiguration(
                device: device,
                signingKey: signingPrivateKey
            )
        }

        let activeDeviceIds = Set(devices.map(\.deviceId))
        let localDevice = devices.first {
            $0.signingPublicKey == signingPrivateKey.publicKey.rawRepresentation
        }
        let retainedSignedKeys = configuration.signedOneTimePublicKeys.filter { signedKey in
            activeDeviceIds.contains(signedKey.deviceId) && signedKey.deviceId != localDevice?.deviceId
        }
        let retainedSignedMLKEMKeys = configuration.signedMLKEMOneTimePublicKeys.filter { signedKey in
            activeDeviceIds.contains(signedKey.deviceId) && signedKey.deviceId != localDevice?.deviceId
        }

        let signedKeys: [UserConfiguration.SignedOneTimePublicKey]
        let signedMLKEMKeys: [UserConfiguration.SignedMLKEMOneTimeKey]
        if let localDevice {
            signedKeys = try retainedSignedKeys + keys.map { key in
                try UserConfiguration.SignedOneTimePublicKey(
                    key: key,
                    deviceId: localDevice.deviceId,
                    signingKey: signingPrivateKey
                )
            }
            signedMLKEMKeys = try retainedSignedMLKEMKeys + mlKEMKeys.map { key in
                try UserConfiguration.SignedMLKEMOneTimeKey(
                    key: key,
                    deviceId: localDevice.deviceId,
                    signingKey: signingPrivateKey
                )
            }
        } else {
            signedKeys = retainedSignedKeys
            signedMLKEMKeys = retainedSignedMLKEMKeys
        }

        var signedDeviceKeyBundles = configuration.signedDeviceKeyBundles.filter { signedBundle in
            devices.contains(where: { $0.deviceId == signedBundle.id })
        }
        if let localDevice {
            let localBundle = try UserConfiguration.SignedDeviceKeyBundle(
                bundle: .init(
                    deviceId: localDevice.deviceId,
                    longTermPublicKey: localDevice.longTermPublicKey,
                    finalMLKEMPublicKey: localDevice.finalMLKEMPublicKey
                ),
                signingKey: signingPrivateKey
            )
            signedDeviceKeyBundles.removeAll { $0.id == localDevice.deviceId }
            signedDeviceKeyBundles.append(localBundle)
        }

        // 4) Return the new account-signed membership plus device-owned key bundles.
        return UserConfiguration(
            signingPublicKey: signingPublicKey.rawRepresentation,
            signedDevices: signedDevices,
            signedOneTimePublicKeys: signedKeys,
            signedMLKEMOneTimePublicKeys: signedMLKEMKeys,
            signedDeviceKeyBundles: signedDeviceKeyBundles
        )
    }

    /// Starts a session using the provided application password.
    ///
    /// This method retrieves the local device salt, derives a symmetric key from the application password,
    /// and attempts to decrypt the local device configuration. If successful, it updates the last user
    /// configuration and returns a shared `PQSSession`.
    ///
    /// - Parameters:
    ///   - appPassword: The application password used for encryption and session management.
    /// - Returns: A `PQSSession` object representing the started session.
    /// - Throws: An error of type `SessionErrors` if the session start fails due to various reasons.
    public func startSession(appPassword: String) async throws -> PQSSession {
        await setAppPassword(appPassword)
        // Ensure the identity store is initialized
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }

        // Retrieve the local device configuration
        let data = try await cache.fetchLocalSessionContext()

        // Convert the application password to Data
        guard let passwordData = appPassword.data(using: .utf8) else {
            throw SessionErrors.saltError
        }

        // Retrieve salt and derive symmetric key
        let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)

        // Derive the symmetric key from the password and salt - This is the AppSymmetricKey
        let symmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )

        do {
            // Decrypt the configuration data
            guard let configurationData = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else {
                throw SessionErrors.sessionDecryptionError
            }

            // Decode the session context from the decrypted data
            let sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)

            // Diagnostic-only per-device identity check. Logs (does not throw) when the
            // local `signingPrivateKey` does not match this device's `signingPublicKey` entry in
            // the cached `activeUserConfiguration.signedDevices`. The original write-master-key-
            // onto-child overwrite bug is prevented at the source by:
            //   1. `LinkedDeviceReprovisioningBundle` carrying no private signing material,
            //   2. `installLinkedDeviceReprovisioningBundle` rejecting bundles that re-attest us
            //      with a foreign per-device key,
            //   3. `DeviceKeys.signingPrivateKey` being `private(set)` so future code cannot
            //      silently overwrite it.
            // The startup check is kept as a non-fatal observer because legitimate transient
            // states (right after a fresh link, before the first `refreshIdentities`) can also
            // produce divergence and should not block the user from completing a re-link.
            checkPerDeviceSigningKeyConsistency(sessionContext: sessionContext)

            await setSessionContext(sessionContext)

            // Prune archived session identities that expired while offline.
            await cleanupAllInactiveSessionSnapshots()

            return self
        } catch {
            throw error
        }
    }

    /// Diagnostic-only per-device identity health check.
    ///
    /// Inspects the persisted `activeUserConfiguration` and the local `signingPrivateKey` and
    /// emits a warning log on every form of inconsistency we know how to spot. Never throws.
    /// The historical write-master-key-onto-child corruption is prevented at the source by the
    /// invariants documented in `startSession`; this runtime check exists only so we can see in
    /// the logs if a device ever drifts back into a divergent state.
    private func checkPerDeviceSigningKeyConsistency(sessionContext: SessionContext) {
        let accountKey: Curve25519.Signing.PublicKey
        do {
            accountKey = try Curve25519.Signing.PublicKey(
                rawRepresentation: sessionContext.activeUserConfiguration.signingPublicKey
            )
        } catch {
            logger.log(level: .warning, message: "Cached account signing public key is malformed; identity inspection skipped")
            return
        }

        let myDeviceId = sessionContext.sessionUser.deviceId
        guard let signedSelf = sessionContext.activeUserConfiguration.signedDevices.first(where: { $0.id == myDeviceId }) else {
            logger.log(level: .warning, message: "This device is missing from the cached signedDevices list; identity inspection skipped")
            return
        }

        let verifiedSelf: UserDeviceConfiguration?
        do {
            verifiedSelf = try signedSelf.verified(using: accountKey)
        } catch {
            verifiedSelf = nil
        }
        guard let verifiedSelf else {
            logger.log(level: .warning, message: "This device's signed entry fails verification under cached account key; identity inspection skipped")
            return
        }

        let localPublicKey: Data
        do {
            localPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey
            ).publicKey.rawRepresentation
        } catch {
            logger.log(level: .warning, message: "Local signing private key is unreadable; identity inspection skipped")
            return
        }

        if verifiedSelf.signingPublicKey != localPublicKey {
            logger.log(
                level: .warning,
                message: "Per-device signing key divergence detected: local key does not match this device's entry in signedDevices. This is non-fatal; investigate if peer signature verification fails downstream."
            )
        }
    }

    private func removeExpiredOTKeys() {
        refreshOTKeysTask = nil
    }

    private func removeExpiredMLKEMOTKeys() {
        refreshMLKEMOTKeysTask = nil
    }

    /// Manually triggers a refresh of Curve25519 one-time keys
    ///
    /// By default this matches automatic refresh: after syncing with the server, new keys are
    /// generated and uploaded only when the remaining count is at or below
    /// `PQSSessionConstants.oneTimeKeyLowWatermark`. Use `policy` to request an explicit top-up
    /// or to fully replace this device's current batch.
    ///
    /// - Note: The refresh task runs asynchronously. When a replenish runs, it creates up to
    ///   enough keys to reach `PQSSessionConstants.oneTimeKeyBatchSize`.
    /// - Parameter policy: Controls whether the task only refreshes when low, forces a top-up,
    ///   or replaces the current device's one-time-key batch entirely.
    @discardableResult
    public func refreshOneTimeKeysTask(policy: OneTimeKeyRefreshPolicy = .automatic) async -> Bool {
        if otkUploadCircuitOpen {
            if let openedAt = otkUploadCircuitOpenedAt,
               Date().timeIntervalSince(openedAt) < otkCircuitCooldownSeconds {
                let remaining = Int(otkCircuitCooldownSeconds - Date().timeIntervalSince(openedAt))
                logger.log(level: .info, message: "OTK upload circuit breaker open; skipping curve refresh (\(remaining)s until probe)")
                return false
            }
            logger.log(level: .info, message: "OTK circuit breaker cooldown elapsed; allowing probe attempt for curve keys")
        }

        // Coalesce concurrent refresh requests to avoid cancel/restart storms that
        // surface as URLSession cancellation errors (-999) under load.
        if policy != .automatic, let existingTask = refreshOTKeysTask {
            _ = await existingTask.value
        } else if let existingTask = refreshOTKeysTask {
            return await existingTask.value
        }

        refreshOTKeysTask = Task(executorPreference: taskProcessor.keyTransportExecutor) { [weak self] in
            guard let self else { return false }
            let retryDelays: [UInt64] = [1_000_000_000, 3_000_000_000]
            for attempt in 0...retryDelays.count {
                do {
                    try await refreshOneTimeKeys(refreshType: .curve, policy: policy)
                    await removeExpiredOTKeys()
                    return true
                } catch let sessionError as SessionErrors where sessionError == .signingKeyMismatchWithServer {
                    await self.logger.log(level: .error, message: "Signing key mismatch detected during curve OTK upload; opening circuit breaker and initiating recovery")
                    await self.openOTKUploadCircuitAndScheduleRecovery()
                    return false
                } catch let sessionError as SessionErrors where sessionError == .oneTimeKeyUploadFailed {
                    if attempt < retryDelays.count {
                        await logger.log(level: .warning, message: "Curve OTK upload failed (attempt \(attempt + 1)/\(retryDelays.count + 1)), retrying after backoff")
                        try? await Task.sleep(nanoseconds: retryDelays[attempt])
                    } else {
                        await logger.log(level: .error, message: "Curve OTK upload failed after \(attempt + 1) attempts")
                        await removeExpiredOTKeys()
                        return false
                    }
                } catch {
                    await logger.log(level: .error, message: "Error refreshing one-time keys: \(error)")
                    await logger.log(level: .warning, message: "Curve one-time-key refresh failed; local/server state may remain out of sync")
                    await removeExpiredOTKeys()
                    return false
                }
            }
            return false
        }

        return await refreshOTKeysTask?.value ?? false
    }

    /// Manually triggers a refresh of MLKEM one-time keys
    ///
    /// Default behavior matches automatic refresh (see `refreshOneTimeKeysTask`). Use `policy`
    /// for reconciliation paths that must top up even when above the low watermark or for
    /// compromise-recovery paths that must replace the current device batch.
    ///
    /// - Parameter policy: Controls whether the task only refreshes when low, forces a top-up,
    ///   or replaces the current device's one-time-key batch entirely.
    @discardableResult
    public func refreshMLKEMOneTimeKeysTask(policy: OneTimeKeyRefreshPolicy = .automatic) async -> Bool {
        if otkUploadCircuitOpen {
            if let openedAt = otkUploadCircuitOpenedAt,
               Date().timeIntervalSince(openedAt) < otkCircuitCooldownSeconds {
                let remaining = Int(otkCircuitCooldownSeconds - Date().timeIntervalSince(openedAt))
                logger.log(level: .info, message: "OTK upload circuit breaker open; skipping MLKEM refresh (\(remaining)s until probe)")
                return false
            }
            logger.log(level: .info, message: "OTK circuit breaker cooldown elapsed; allowing probe attempt for MLKEM keys")
        }

        // Coalesce concurrent refresh requests to avoid cancel/restart storms that
        // surface as URLSession cancellation errors (-999) under load.
        if policy != .automatic, let existingTask = refreshMLKEMOTKeysTask {
            _ = await existingTask.value
        } else if let existingTask = refreshMLKEMOTKeysTask {
            return await existingTask.value
        }

        refreshMLKEMOTKeysTask = Task(executorPreference: taskProcessor.keyTransportExecutor) { [weak self] in
            guard let self else { return false }
            let retryDelays: [UInt64] = [1_000_000_000, 3_000_000_000]
            for attempt in 0...retryDelays.count {
                do {
                    try await refreshOneTimeKeys(refreshType: .mlKEM, policy: policy)
                    await removeExpiredMLKEMOTKeys()
                    return true
                } catch let sessionError as SessionErrors where sessionError == .signingKeyMismatchWithServer {
                    await self.logger.log(level: .error, message: "Signing key mismatch detected during MLKEM OTK upload; opening circuit breaker and initiating recovery")
                    await self.openOTKUploadCircuitAndScheduleRecovery()
                    return false
                } catch let sessionError as SessionErrors where sessionError == .oneTimeKeyUploadFailed {
                    if attempt < retryDelays.count {
                        await logger.log(level: .warning, message: "MLKEM OTK upload failed (attempt \(attempt + 1)/\(retryDelays.count + 1)), retrying after backoff")
                        try? await Task.sleep(nanoseconds: retryDelays[attempt])
                    } else {
                        await logger.log(level: .error, message: "MLKEM OTK upload failed after \(attempt + 1) attempts")
                        await removeExpiredMLKEMOTKeys()
                        return false
                    }
                } catch {
                    await logger.log(level: .error, message: "Error refreshing one-time keys: \(error)")
                    await logger.log(level: .warning, message: "MLKEM one-time-key refresh failed; local/server state may remain out of sync")
                    await removeExpiredMLKEMOTKeys()
                    return false
                }
            }
            return false
        }
        return await refreshMLKEMOTKeysTask?.value ?? false
    }

    /// - Parameter policy: Controls whether the device only tops up when low, always tops up to the
    ///   configured batch size, or replaces the current device's entire one-time-key batch.
    func refreshOneTimeKeys(refreshType: KeysType, policy: OneTimeKeyRefreshPolicy = .automatic) async throws {
        guard await sessionContext != nil else { return }
        guard let cache else { return }
        if policy == .replaceCurrentDeviceBatch {
            try await replaceCurrentDeviceOneTimeKeys(cache: cache, refreshType: refreshType)
            return
        }
        var keys = [UUID]()

        if let sessionContext = await sessionContext,
           let fetched = try await transportDelegate?.fetchOneTimeKeyIdentities(
            for: sessionContext.sessionUser.secretName,
            deviceId: sessionContext.sessionUser.deviceId.uuidString,
            type: refreshType
           ) {
            keys = fetched
        }

        if keys.isEmpty {
            logger.log(level: .warning, message: "No remote one-time key identities found for \(refreshType); regenerating local batch")
        }

        let publicKeysCount = try await synchronizeLocalKeys(cache: cache, keys: keys, type: refreshType)
        let shouldReplenish: Bool
        switch policy {
        case .automatic:
            shouldReplenish = publicKeysCount <= PQSSessionConstants.oneTimeKeyLowWatermark
        case .replenishBatch:
            shouldReplenish = true
        case .replaceCurrentDeviceBatch:
            shouldReplenish = false
        }
        if shouldReplenish {
            // 1. Delete all local keys that are not on the server
            let config = try await cache.fetchLocalSessionContext()

            // Decrypt the session context data using the app's symmetric key
            guard let configurationData = try await crypto.decrypt(data: config, symmetricKey: getAppSymmetricKey()) else {
                throw SessionErrors.sessionDecryptionError
            }

            // Decode the session context from the decrypted data
            var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)
            let keyPairsToCreate = max(0, PQSSessionConstants.oneTimeKeyBatchSize - publicKeysCount)

            logger.log(level: .info, message: "Creating Key Pairs, count: \(keyPairsToCreate)")
            switch refreshType {
            case .curve:
                // Create needed key pairs
                let privateOneTimeKeyPairs: [KeyPair] = try (0 ..< keyPairsToCreate).map { _ in
                    let id = UUID()
                    let privateKey = crypto.generateCurve25519PrivateKey()
                    let privateKeyRep = try CurvePrivateKey(id: id, privateKey.rawRepresentation)
                    let publicKey = try CurvePublicKey(id: id, privateKey.publicKey.rawRepresentation)
                    return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
                }

                sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.append(contentsOf: privateOneTimeKeyPairs.map(\.privateKey))
                let signedOneTimePublicKeys: [UserConfiguration.SignedOneTimePublicKey] = try privateOneTimeKeyPairs.map { keyPair in
                    try UserConfiguration.SignedOneTimePublicKey(
                        key: keyPair.publicKey,
                        deviceId: sessionContext.sessionUser.deviceId,
                        signingKey: Curve25519.Signing.PrivateKey(rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey))
                }

                try await transportDelegate?.updateOneTimeKeys(
                    for: sessionContext.sessionUser.secretName,
                    deviceId: sessionContext.sessionUser.deviceId.uuidString,
                    keys: signedOneTimePublicKeys
                )

                sessionContext.activeUserConfiguration.signedOneTimePublicKeys.append(contentsOf: signedOneTimePublicKeys)

            case .mlKEM:
                // Create needed key pairs
                let mlKEMOneTimeKeyPairs: [KeyPair] = try (0 ..< keyPairsToCreate).map { _ in
                    let id = UUID()
                    let privateKey = try crypto.generateMLKem1024PrivateKey()
                    let privateKeyRep = try MLKEMPrivateKey(id: id, privateKey.encode())
                    let publicKey = try MLKEMPublicKey(id: id, privateKey.publicKey.rawRepresentation)
                    return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
                }

                sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.append(contentsOf: mlKEMOneTimeKeyPairs.map(\.privateKey))
                let signedMLKEMOneTimeKeys: [UserConfiguration.SignedMLKEMOneTimeKey] = try mlKEMOneTimeKeyPairs.map { keyPair in
                    try UserConfiguration.SignedMLKEMOneTimeKey(
                        key: keyPair.publicKey,
                        deviceId: sessionContext.sessionUser.deviceId,
                        signingKey: Curve25519.Signing.PrivateKey(rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey)
                    )
                }

                try await transportDelegate?.updateOneTimeMLKEMKeys(
                    for: sessionContext.sessionUser.secretName,
                    deviceId: sessionContext.sessionUser.deviceId.uuidString,
                    keys: signedMLKEMOneTimeKeys
                )

                sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.append(contentsOf: signedMLKEMOneTimeKeys)
            }

            sessionContext.updateSessionUser(sessionContext.sessionUser)
            await setSessionContext(sessionContext)

            // Encrypt and persist
            let encodedData = try BinaryEncoder().encode(sessionContext)
            guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
                throw PQSSession.SessionErrors.sessionEncryptionError
            }

            try await cache.updateLocalSessionContext(encryptedConfig)
        }
    }

    private func replaceCurrentDeviceOneTimeKeys(
        cache: SessionCache,
        refreshType: KeysType
    ) async throws {
        guard let transportDelegate else {
            throw SessionErrors.transportNotInitialized
        }

        let config = try await cache.fetchLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: config, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }

        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)
        let signingKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey
        )
        let secretName = sessionContext.sessionUser.secretName
        let deviceId = sessionContext.sessionUser.deviceId

        try await transportDelegate.batchDeleteOneTimeKeys(
            for: secretName,
            with: deviceId.uuidString,
            type: refreshType
        )

        switch refreshType {
        case .curve:
            sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.removeAll()
            sessionContext.activeUserConfiguration.signedOneTimePublicKeys.removeAll { $0.deviceId == deviceId }

            let privateOneTimeKeyPairs: [KeyPair] = try (0 ..< PQSSessionConstants.oneTimeKeyBatchSize).map { _ in
                let id = UUID()
                let privateKey = crypto.generateCurve25519PrivateKey()
                let privateKeyRep = try CurvePrivateKey(id: id, privateKey.rawRepresentation)
                let publicKey = try CurvePublicKey(id: id, privateKey.publicKey.rawRepresentation)
                return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
            }

            sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.append(contentsOf: privateOneTimeKeyPairs.map(\.privateKey))
            let signedOneTimePublicKeys: [UserConfiguration.SignedOneTimePublicKey] = try privateOneTimeKeyPairs.map { keyPair in
                try UserConfiguration.SignedOneTimePublicKey(
                    key: keyPair.publicKey,
                    deviceId: deviceId,
                    signingKey: signingKey
                )
            }

            try await transportDelegate.updateOneTimeKeys(
                for: secretName,
                deviceId: deviceId.uuidString,
                keys: signedOneTimePublicKeys
            )

            sessionContext.activeUserConfiguration.signedOneTimePublicKeys.append(contentsOf: signedOneTimePublicKeys)
            logger.log(level: .debug, message: "Replaced local curve OTK batch; count=\(signedOneTimePublicKeys.count)")

        case .mlKEM:
            sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.removeAll()
            sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.removeAll { $0.deviceId == deviceId }

            let mlKEMOneTimeKeyPairs: [KeyPair] = try (0 ..< PQSSessionConstants.oneTimeKeyBatchSize).map { _ in
                let id = UUID()
                let privateKey = try crypto.generateMLKem1024PrivateKey()
                let privateKeyRep = try MLKEMPrivateKey(id: id, privateKey.encode())
                let publicKey = try MLKEMPublicKey(id: id, privateKey.publicKey.rawRepresentation)
                return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
            }

            sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.append(contentsOf: mlKEMOneTimeKeyPairs.map(\.privateKey))
            let signedMLKEMOneTimeKeys: [UserConfiguration.SignedMLKEMOneTimeKey] = try mlKEMOneTimeKeyPairs.map { keyPair in
                try UserConfiguration.SignedMLKEMOneTimeKey(
                    key: keyPair.publicKey,
                    deviceId: deviceId,
                    signingKey: signingKey
                )
            }

            try await transportDelegate.updateOneTimeMLKEMKeys(
                for: secretName,
                deviceId: deviceId.uuidString,
                keys: signedMLKEMOneTimeKeys
            )

            sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.append(contentsOf: signedMLKEMOneTimeKeys)
            logger.log(level: .debug, message: "Replaced local MLKEM OTK batch; count=\(signedMLKEMOneTimeKeys.count)")
        }

        sessionContext.updateSessionUser(sessionContext.sessionUser)
        await setSessionContext(sessionContext)

        let encodedData = try BinaryEncoder().encode(sessionContext)
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }

        try await cache.updateLocalSessionContext(encryptedConfig)
    }

    func synchronizeLocalKeys(cache: SessionCache, keys: [UUID], type: KeysType) async throws -> Int {
        let data = try await cache.fetchLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }

        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)
        var didUpdate = false

        switch type {
        case .curve:
            let deviceId = sessionContext.sessionUser.deviceId
            let publicKeys = sessionContext.activeUserConfiguration.signedOneTimePublicKeys
            let currentDevicePublicKeys = publicKeys.filter { $0.deviceId == deviceId }
            let otherDevicePublicKeys = publicKeys.filter { $0.deviceId != deviceId }
            let remoteKeySet = Set(keys)

            // Only prune the public key list to stop advertising keys the server
            // no longer holds. Private keys are preserved — a consumed-on-server
            // key means an in-flight message needs the private counterpart for
            // decryption. Private keys are removed after use via updateOneTimeKey(remove:).
            if remoteKeySet.isEmpty {
                if !currentDevicePublicKeys.isEmpty {
                    sessionContext.activeUserConfiguration.signedOneTimePublicKeys = otherDevicePublicKeys
                    didUpdate = true
                }
            } else {
                let filteredPublic = currentDevicePublicKeys.filter { remoteKeySet.contains($0.id) }
                if filteredPublic.count != currentDevicePublicKeys.count {
                    sessionContext.activeUserConfiguration.signedOneTimePublicKeys = otherDevicePublicKeys + filteredPublic
                    didUpdate = true
                }
            }

            if didUpdate {
                sessionContext.updateSessionUser(sessionContext.sessionUser)
                await setSessionContext(sessionContext)

                let encodedData = try BinaryEncoder().encode(sessionContext)
                guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
                    throw PQSSession.SessionErrors.sessionEncryptionError
                }

                try await cache.updateLocalSessionContext(encryptedConfig)

                if sessionContext.activeUserConfiguration.signedOneTimePublicKeys.allSatisfy({ $0.deviceId != deviceId }) {
                    try await transportDelegate?.batchDeleteOneTimeKeys(for: sessionContext.sessionUser.secretName, with: sessionContext.sessionUser.deviceId.uuidString, type: type)
                }
            }
            return sessionContext.activeUserConfiguration.signedOneTimePublicKeys.filter { $0.deviceId == deviceId }.count
        case .mlKEM:
            let deviceId = sessionContext.sessionUser.deviceId
            let publicKeys = sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys
            let currentDevicePublicKeys = publicKeys.filter { $0.deviceId == deviceId }
            let otherDevicePublicKeys = publicKeys.filter { $0.deviceId != deviceId }
            let remoteKeySet = Set(keys)

            if remoteKeySet.isEmpty {
                if !currentDevicePublicKeys.isEmpty {
                    sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys = otherDevicePublicKeys
                    didUpdate = true
                }
            } else {
                let filteredPublic = currentDevicePublicKeys.filter { remoteKeySet.contains($0.id) }
                if filteredPublic.count != currentDevicePublicKeys.count {
                    sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys = otherDevicePublicKeys + filteredPublic
                    didUpdate = true
                }
            }

            if didUpdate {
                sessionContext.updateSessionUser(sessionContext.sessionUser)
                await setSessionContext(sessionContext)

                let encodedData = try BinaryEncoder().encode(sessionContext)
                guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
                    throw PQSSession.SessionErrors.sessionEncryptionError
                }

                try await cache.updateLocalSessionContext(encryptedConfig)

                if sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.allSatisfy({ $0.deviceId != deviceId }) {
                    try await transportDelegate?.batchDeleteOneTimeKeys(for: sessionContext.sessionUser.secretName, with: sessionContext.sessionUser.deviceId.uuidString, type: type)
                }
            }
            return sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.filter { $0.deviceId == deviceId }.count
        }
    }

    /// Retrieves the symmetric key for database encryption.
    public func getDatabaseSymmetricKey() async throws -> SymmetricKey {
        guard let data = await sessionContext?.databaseEncryptionKey else {
            throw SessionErrors.sessionNotInitialized
        }
        return SymmetricKey(data: data)
    }

    /// Derives the symmetric key from the application password.
    ///
    /// This key is used to encrypt/decrypt the session context. It's derived from
    /// the application password and device salt using a key derivation function.
    ///
    /// - Returns: The symmetric key derived from the application password
    /// - Throws:
    ///   - `SessionErrors.invalidPassword` if the password cannot be converted to data
    ///   - `SessionErrors.saltError` if the device salt cannot be retrieved
    public func getAppSymmetricKey() async throws -> SymmetricKey {
        guard let passwordData = await appPassword.data(using: .utf8) else {
            throw SessionErrors.invalidPassword
        }

        // Retrieve salt and derive symmetric key
        guard let saltData = try await cache?.fetchLocalDeviceSalt(keyData: passwordData) else { throw SessionErrors.saltError }

        return await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )
    }

    /// Verifies an input password against stored session context.
    ///
    /// This method attempts to decrypt the stored session context using the provided
    /// password. If decryption succeeds, the password is correct.
    ///
    /// - Parameter appPassword: The password to verify
    /// - Returns: `true` if the password is correct and can decrypt the session context,
    ///            `false` otherwise
    public func verifyAppPassword(_ appPassword: String) async -> Bool {
        do {
            guard let passwordData = appPassword.data(using: .utf8) else {
                throw SessionErrors.invalidPassword
            }

            guard let saltData = try await cache?.fetchLocalDeviceSalt(keyData: passwordData) else { throw SessionErrors.saltError }

            let appEncryptionKey = await crypto.deriveStrictSymmetricKey(
                data: passwordData,
                salt: saltData
            )

            await setAppPassword(appPassword)

            guard let data = try await cache?.fetchLocalSessionContext() else { return false }
            let box = try AES.GCM.SealedBox(combined: data)
            _ = try AES.GCM.open(box, using: appEncryptionKey)
            return true
        } catch {
            return false
        }
    }

    /// Changes the application password and re-encrypts the session context.
    ///
    /// This method decrypts the current session context, generates a new device salt,
    /// and re-encrypts the session context with the new password. All session data
    /// remains intact, only the encryption key changes.
    ///
    /// - Parameter newPassword: The new application password
    /// - Throws:
    ///   - `SessionErrors.databaseNotInitialized` if the cache is not available
    ///   - `SessionErrors.sessionDecryptionError` if the current session cannot be decrypted
    ///   - `SessionErrors.appPasswordError` if the new password cannot be converted to data
    ///   - `SessionErrors.sessionEncryptionError` if the session cannot be re-encrypted
    public func changeAppPassword(_ newPassword: String) async throws {
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }

        let data = try await cache.fetchLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }
        // Decode the session context from the decrypted data
        let sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)
        try await cache.deleteLocalDeviceSalt()

        guard let passwordData = newPassword.data(using: .utf8) else {
            throw SessionErrors.appPasswordError
        }

        // Retrieve salt and derive symmetric key
        let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)

        let symmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )

        let encodedData = try BinaryEncoder().encode(sessionContext)
        guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: symmetricKey) else {
            throw SessionErrors.sessionEncryptionError
        }

        await setAppPassword(newPassword)

        // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
        try await cache.updateLocalSessionContext(encryptedConfig)
    }

    /// Resumes processing of any pending tasks in the queue.
    ///
    /// This method loads all pending tasks from the cache and resumes their processing.
    /// Useful after session restoration or when tasks may have been paused.
    ///
    /// - Throws: `SessionErrors.databaseNotInitialized` if the cache is not available
    public func resumeJobQueue() async throws {
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        try await taskProcessor.loadTasks(
            nil,
            cache: cache,
            symmetricKey: getDatabaseSymmetricKey(),
            session: self
        )
    }

    /// Blocks until pending encrypt/send jobs finish (used after OTK bootstrap notify).
    public func waitForOutboundJobDrain(timeout: TimeInterval = 8.0) async {
        guard let cache else { return }
        await taskProcessor.waitForOutboundJobDrain(cache: cache, session: self, timeout: timeout)
    }

    /// Sends OTK notify for a new peer session and waits for outbound encrypt jobs to drain.
    /// Call before the first friendship request so the receiver ratchet is ready.
    public func bootstrapPeerContactSession(secretName: String) async throws {
        _ = try await refreshIdentities(
            secretName: secretName,
            createIdentity: true,
            sendOneTimeIdentities: true)
        await waitForOutboundJobDrain()
    }

    /// Shuts down the session, clearing sensitive state.
    ///
    /// This method performs a complete shutdown of the session, including:
    /// - Shutting down the ratchet manager
    /// - Clearing all delegates
    /// - Resetting session state
    /// - Clearing sensitive data from memory
    ///
    /// After shutdown, the session is no longer viable and must be reinitialized
    /// before use. All cached data remains in persistent storage and can be restored
    /// by calling `startSession(appPassword:)`.
    ///
    /// - Important: This method clears sensitive data from memory. Ensure all
    ///   operations are complete before calling this method.
    public func shutdown() async {
        do {
            try await taskProcessor.ratchetManager.shutdown()
        } catch {
            // Teardown can race with in-flight session cleanup; do not crash the app.
            logger.log(level: .warning, message: "Ratchet manager shutdown encountered non-fatal error: \(error)")
        }
        isViable = false
        cache = nil
        transportDelegate = nil
        receiverDelegate = nil
        linkDelegate = nil
        _sessionContext = nil
        _appPassword = ""
        await setDatabaseDelegate(conformer: nil)
        await setTransportDelegate(conformer: nil)
        setReceiverDelegate(conformer: nil)
        await setPQSSessionDelegate(conformer: nil)
        await setSessionEventDelegate(conformer: nil)
        sessionIdentities.removeAll()

    }

    /// Returns a human-readable device name for the current platform
    ///
    /// On iOS and macOS, this returns a friendly device name (e.g., "iPhone 15 Pro")
    /// by mapping model identifiers to readable names. On other platforms, it returns
    /// a generic identifier.
    ///
    /// - Returns: A string representing the device name
    public func getDeviceName() -> String {
        #if os(iOS) || os(macOS)
            let modelIdentifier = getModelIdentifier()

            // Mapping of model identifiers to friendly names
            let deviceNames: [String: String] = [
                // iPhones
                "iPhone11,2": "iPhone XS",
                "iPhone11,4": "iPhone XS Max",
                "iPhone11,6": "iPhone XS Max Global",
                "iPhone11,8": "iPhone XR",
                "iPhone12,1": "iPhone 11",
                "iPhone12,3": "iPhone 11 Pro",
                "iPhone12,5": "iPhone 11 Pro Max",
                "iPhone12,8": "iPhone SE 2nd Gen",
                "iPhone13,1": "iPhone 12 Mini",
                "iPhone13,2": "iPhone 12",
                "iPhone13,3": "iPhone 12 Pro",
                "iPhone13,4": "iPhone 12 Pro Max",
                "iPhone14,2": "iPhone 13 Pro",
                "iPhone14,3": "iPhone 13 Pro Max",
                "iPhone14,4": "iPhone 13 Mini",
                "iPhone14,5": "iPhone 13",
                "iPhone14,6": "iPhone SE 3rd Gen",
                "iPhone14,7": "iPhone 14",
                "iPhone14,8": "iPhone 14 Plus",
                "iPhone15,2": "iPhone 14 Pro",
                "iPhone15,3": "iPhone 14 Pro Max",
                "iPhone15,4": "iPhone 15",
                "iPhone15,5": "iPhone 15 Plus",
                "iPhone16,1": "iPhone 15 Pro",
                "iPhone16,2": "iPhone 15 Pro Max",
                "iPhone17,1": "iPhone 16 Pro",
                "iPhone17,2": "iPhone 16 Pro Max",
                "iPhone17,3": "iPhone 16",
                "iPhone17,4": "iPhone 16 Plus",

                // iPads
                "iPad11,1": "iPad mini 5th Gen (WiFi)",
                "iPad11,2": "iPad mini 5th Gen (WiFi+Cellular)",
                "iPad11,3": "iPad Air 3rd Gen (WiFi)",
                "iPad11,4": "iPad Air 3rd Gen (WiFi+Cellular)",
                "iPad11,6": "iPad 8th Gen (WiFi)",
                "iPad11,7": "iPad 8th Gen (WiFi+Cellular)",
                "iPad12,1": "iPad 9th Gen (WiFi)",
                "iPad12,2": "iPad 9th Gen (WiFi+Cellular)",
                "iPad14,1": "iPad mini 6th Gen (WiFi)",
                "iPad14,2": "iPad mini 6th Gen (WiFi+Cellular)",
                "iPad13,1": "iPad Air 4th Gen (WiFi)",
                "iPad13,2": "iPad Air 4th Gen (WiFi+Cellular)",
                "iPad13,4": "iPad Pro 11 inch 5th Gen",
                "iPad13,5": "iPad Pro 11 inch 5th Gen",
                "iPad13,6": "iPad Pro 11 inch 5th Gen",
                "iPad13,7": "iPad Pro 11 inch 5th Gen",
                "iPad13,8": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,9": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,10": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,11": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,16": "iPad Air 5th Gen (WiFi)",
                "iPad13,17": "iPad Air 5th Gen (WiFi+Cellular)",
                "iPad13,18": "iPad 10th Gen",
                "iPad13,19": "iPad 10th Gen",
                "iPad14,3": "iPad Pro 11 inch 4th Gen",
                "iPad14,4": "iPad Pro 11 inch 4th Gen",
                "iPad14,5": "iPad Pro 12.9 inch 6th Gen",
                "iPad14,6": "iPad Pro 12.9 inch 6th Gen",
                "iPad14,8": "iPad Air 6th Gen",
                "iPad14,9": "iPad Air 6th Gen",
                "iPad14,10": "iPad Air 7th Gen",
                "iPad14,11": "iPad Air 7th Gen",
                "iPad16,1": "iPad mini 7th Gen (WiFi)",
                "iPad16,2": "iPad mini 7th Gen (WiFi+Cellular)",
                "iPad16,3": "iPad Pro 11 inch 5th Gen",
                "iPad16,4": "iPad Pro 11 inch 5th Gen",
                "iPad16,5": "iPad Pro 12.9 inch 7th Gen",
                "iPad16,6": "iPad Pro 12.9 inch 7th Gen",

                // Macs
                // iMac (2019 and later)
                "iMac19,1": "iMac (2019)",
                "iMac19,2": "iMac (2019)",
                "iMac20,1": "iMac (2020)",
                "iMac21,1": "iMac (2021)",
                "iMac21,2": "iMac 24-inch (M1, 2021)",
                "iMac22,1": "iMac 24-inch (M3, 2024)",
                "iMac22,2": "iMac 24-inch (M3, 2024)",

                // iMac Pro
                "iMacPro1,1": "iMac Pro (2017)",

                // MacBook Air (2020 and later)
                "MacBookAir8,1": "MacBook Air (Retina, 2018)",
                "MacBookAir9,1": "MacBook Air (M1, 2020)",
                "Mac14,2": "MacBook Air (M2, 2022)",
                "Mac14,7": "MacBook Air (M3, 2023)",
                "Mac15,1": "MacBook Air (M4, 2024)",

                // MacBook Pro (2017 and later)
                "MacBookPro14,1": "MacBook Pro (2017)",
                "MacBookPro14,3": "MacBook Pro (2017)",
                "MacBookPro15,1": "MacBook Pro (2019)",
                "MacBookPro15,2": "MacBook Pro (2019)",
                "MacBookPro15,3": "MacBook Pro (2019)",
                "MacBookPro15,4": "MacBook Pro (2019)",
                "MacBookPro16,1": "MacBook Pro (2021)",
                "MacBookPro16,2": "MacBook Pro (2021)",
                "MacBookPro16,3": "MacBook Pro (2021)",
                "MacBookPro16,4": "MacBook Pro (2021)",
                "MacBookPro17,1": "MacBook Pro (2021)",
                "MacBookPro18,1": "MacBook Pro (2021)",
                "MacBookPro18,2": "MacBook Pro (M1, 2020)",
                "MacBookPro18,3": "MacBook Pro (2021)",
                "MacBookPro18,4": "MacBook Pro (2021)",
                "Mac14,5": "MacBook Pro (M2, 2022)",
                "Mac14,6": "MacBook Pro (M2, 2022)",
                "Mac14,8": "MacBook Air/Pro (M2, 2023)",
                "Mac14,9": "MacBook Pro (M2, 2023)",
                "Mac14,10": "MacBook Pro (M3, 2023)",
                "Mac14,11": "MacBook Pro (M3, 2023)",
                "Mac14,13": "MacBook Pro (M3, 2023)",
                "Mac14,14": "MacBook Pro (M3, 2023)",
                "Mac14,15": "MacBook Pro (M3, 2023)",
                "Mac15,2": "MacBook Pro (M4, 2024)",
                "Mac15,3": "MacBook Pro (M4, 2024)",
                "Mac15,4": "MacBook Pro (M4, 2024)",
                "Mac15,5": "MacBook Pro (M4, 2024)",
                "Mac15,6": "MacBook Pro (M4, 2024)",
                "Mac15,7": "MacBook Pro (M4, 2024)",
                "Mac16,1": "MacBook Pro (M4 Pro, 2024)",
                "Mac16,2": "MacBook Pro (M4 Pro, 2024)",
                "Mac16,3": "MacBook Pro (M4 Pro, 2024)",
                "Mac16,4": "MacBook Pro (M4 Pro, 2024)",
                "Mac16,5": "MacBook Pro (M4 Max, 2024)",
                "Mac16,6": "MacBook Pro (M4 Max, 2024)",
                "Mac16,7": "MacBook Pro (M4 Max, 2024)",
                "Mac16,8": "MacBook Pro (M4 Max, 2024)",

                // Mac Pro (2019 and later)
                "MacPro7,1": "Mac Pro (2019)",
                "Mac14,1": "Mac Pro (M2 Ultra, 2023)",

                // Mac Studio (2022 and later)
                "Mac13,1": "Mac Studio (M1 Max, 2022)",
                "Mac13,2": "Mac Studio (M1 Ultra, 2022)",
                "Mac14,3": "Mac Studio (M2 Max, 2023)",
                "Mac14,16": "Mac Studio (M2 Ultra, 2023)",
                "Mac15,8": "Mac Studio (M4, 2024)",
                "Mac15,9": "Mac Studio (M4, 2024)",
                "Mac15,10": "Mac Studio (M4, 2024)",
                "Mac15,11": "Mac Studio (M4, 2024)",

                // Mac mini (2018 and later)
                "Macmini8,1": "Mac mini (2018)",
                "Macmini9,1": "Mac mini (M1, 2020)",
                "Mac14,4": "Mac mini (M2, 2022)",
                "Mac14,12": "Mac mini (M2 Pro, 2023)",
            ]

            return deviceNames[modelIdentifier] ?? modelIdentifier
        #else
            return "Unknown Device"
        #endif
    }

    #if os(iOS)
        private func getModelIdentifier() -> String {
            var systemInfo = utsname()
            uname(&systemInfo)

            // Use Mirror to access the machine field and convert it to a String
            let machineMirror = Mirror(reflecting: systemInfo.machine)
            let identifier = machineMirror.children.reduce("") { identifier, element in
                guard let value = element.value as? Int8, value != 0 else { return identifier }
                return identifier + String(UnicodeScalar(UInt8(value)))
            }

            return identifier
        }

    #elseif os(macOS)
        private func getModelIdentifier() -> String {
            var size = 0
            sysctlbyname("hw.model", nil, &size, nil, 0)

            var model = [CChar](repeating: 0, count: size)
            sysctlbyname("hw.model", &model, &size, nil, 0)

            let data = Data(bytes: model, count: size)
            return String(data: data, encoding: .utf8) ?? "Unknown Model"
        }

    #endif
}

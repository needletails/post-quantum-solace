//
//  Constants.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-01-XX.
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

import Foundation

/// Constants used throughout the Post-Quantum Solace SDK
///
/// This enum provides centralized configuration values for the SDK, ensuring
/// consistent behavior across all components. All constants are `Sendable` and
/// can be safely accessed from any concurrent context.
///
/// ## Usage
///
/// ```swift
/// // Check if keys need refresh
/// if keyCount < PQSSessionConstants.oneTimeKeyLowWatermark {
///     await refreshKeys()
/// }
///
/// // Generate keys in batches
/// let batchSize = PQSSessionConstants.oneTimeKeyBatchSize
/// ```
///
/// - Note: These values are used internally by the SDK but can also be
///   referenced by applications for custom logic or validation.
public enum PQSSessionConstants: Sendable {
    /// The threshold below which one-time keys are automatically refreshed
    ///
    /// When the number of available keys drops to this value, the system
    /// will automatically generate a new batch of keys. This ensures continuous
    /// communication capability without manual intervention.
    ///
    /// - Default: `10`
    /// - See also: `PQSSession.refreshOneTimeKeysTask()`
    public static let oneTimeKeyLowWatermark = 10
    
    /// The number of one-time keys generated in each batch
    ///
    /// This ensures sufficient keys are available for immediate communication
    /// while balancing storage and generation overhead. Larger values provide
    /// more keys but require more storage and generation time.
    ///
    /// - Default: `100`
    /// - See also: `PQSSessionConstants.oneTimeKeyLowWatermark`
    public static let oneTimeKeyBatchSize = 100
    
    /// Maximum number of local one-time *private* keys retained per key type when
    /// the published batch is replaced with `OneTimeKeyRefreshPolicy.replacePublishedBatch`.
    ///
    /// Private keys must outlive the server-side publics they correspond to: a
    /// consumed-on-server key means an in-flight message still needs the private
    /// counterpart to decrypt. This cap bounds the retained pool; the oldest keys
    /// are evicted first. Keys are also removed individually once consumed.
    ///
    /// - Default: `200` (two full batches)
    /// - See also: `PQSSessionConstants.oneTimeKeyBatchSize`
    public static let retainedOneTimePrivateKeyCap = oneTimeKeyBatchSize * 2

    /// The interval (in days) after which MLKEM keys are automatically rotated
    ///
    /// This provides automatic key freshness without manual intervention,
    /// ensuring long-term security even if keys are not actively used.
    ///
    /// - Default: `7` (one week)
    /// - See also: `PQSSession.rotateMLKEMKeysIfNeeded()`
    public static let keyRotationIntervalDays = 7
    
    /// The minimum number of operators required for a channel
    ///
    /// Channels must have at least this many operators to be considered valid.
    /// Operators have elevated permissions compared to regular members.
    ///
    /// - Default: `1`
    /// - See also: `PQSSessionConstants.minimumChannelMembers`
    public static let minimumChannelOperators = 1
    
    /// The minimum number of members required for a channel
    ///
    /// Channels must have at least this many members to be considered valid.
    /// This ensures channels have sufficient participants for meaningful communication.
    ///
    /// - Default: `2`
    /// - See also: `PQSSessionConstants.minimumChannelOperators`
    public static let minimumChannelMembers = 2

    /// Prefix used to mark "inactive session" identities in the local store.
    ///
    /// Inactive identities are **never** used for outbound encryption and are hidden from public
    /// identity lists. They are only used as a bounded fallback for inbound decryption when the
    /// active ratchet state has been invalidated (e.g. after reestablishment) and delayed/offline
    /// messages arrive out-of-order.
    ///
    /// - Important: This must remain stable across versions for backward compatibility.
    public static let inactiveSessionDeviceNamePrefix = "__pqs_inactive_session__:"

    /// Maximum number of inactive ratchet states to retain **per (secretName, deviceId)**.
    ///
    /// Bounds storage while keeping enough history for promote-on-decrypt
    /// after multi-device / offline lag.
    public static let inactiveSessionMaxCountPerDevice = 40

    /// Maximum age (in seconds) to retain inactive ratchet states.
    ///
    /// States older than this are deleted opportunistically during invalidation and on inbound recovery.
    public static let inactiveSessionMaxAgeSeconds: TimeInterval = 60 * 60 * 24 * 30 // 30 days

    /// Bound for in-memory outbound device-send ledger entries (`OutboundDeviceSendRecord`).
    public static let outboundDeviceSendRecordMaxCount = 2_000

    // MARK: - Session Reestablishment Coalescing

    /// Cooldown window during which repeated `peerRefresh` emissions to the same scope are suppressed.
    ///
    /// Lowered relative to other kinds because peer refresh is naturally re-driven by inbound traffic.
    public static let peerRefreshCooldownSeconds: TimeInterval = 30

    /// Cooldown window during which repeated `linkedDeviceRepair` emissions to the same scope are suppressed.
    public static let linkedDeviceRepairCooldownSeconds: TimeInterval = 60

    /// Cooldown window during which repeated `linkedDeviceCompromiseObserved` emissions to the same scope
    /// are suppressed. Compromise events trigger user-visible prompts on the master device, so a generous
    /// window is used to bound how often a single episode can re-notify if recovery has not completed.
    public static let linkedDeviceCompromiseObservedCooldownSeconds: TimeInterval = 300

    /// Maximum lifetime of a single sender-side control episode. After this, a new `intentId` is minted
    /// for the next emission, treating the situation as a fresh problem worthy of fresh attention.
    public static let controlEventEpisodeMaxLifetimeSeconds: TimeInterval = 60 * 60 * 24

    /// Maximum number of in-memory sender-side episode entries before LRU eviction is triggered.
    public static let controlEventEpisodeMaxEntries = 256

    /// Maximum age (in seconds) of receiver-side processed-event state retained for dedup decisions.
    public static let processedControlEventMaxAgeSeconds: TimeInterval = 60 * 60 * 24

    /// Maximum number of in-memory receiver-side processed-event entries before LRU eviction is triggered.
    public static let processedControlEventMaxEntries = 1024

    /// Throttle window for the post-control-event identity refresh per sender secretName.
    /// Coalesces the bursts of `refreshIdentities(forceRefresh: true)` that would otherwise fire
    /// once per inbound control message when a backlog drains.
    public static let forcedIdentityRefreshCoalesceWindowSeconds: TimeInterval = 30

    /// Maximum number of in-memory entries retained per recovery bookkeeping map
    /// (resend-request cooldowns, reconciliation cooldowns, rotation cooldowns,
    /// pending resend-after-reestablishment). Oldest entries are evicted first.
    /// Bounds memory growth under floods of unique failed-message identifiers.
    public static let recoveryTrackingMaxEntries = 512

    /// Maximum total resend-request submissions per failed message before the
    /// requester drops it as exhausted. Defense in depth for when the responder's
    /// `messageResendUnavailable` notice is lost in transit.
    public static let peerResendRequestMaxSubmissions = 3

    /// Distinct undecryptable inbound messages from the same peer device after which
    /// recovery escalates from per-message resend to automatic session
    /// reset (`peerRefresh` on a fresh initiating lane). Prevents a dead ratchet from
    /// spraying unbounded resend requests when every new `sharedId` fails once.
    public static let undecryptableLaneEscalateThreshold = 3

    /// Maximum responder-side memory of known-unavailable resend ids
    /// (`requestingDeviceId|sharedId`) before oldest entries are evicted.
    public static let unavailableResendMemoryMaxEntries = 256

    // MARK: - Schema versioning

    /// Current schema version for persisted session state.
    ///
    /// Bumped whenever a code change makes existing on-disk state semantically incompatible with
    /// the current runtime — for example the per-device identity invariant fix which
    /// requires devices that were corrupted by the prior overwrite-on-reprovision behavior to be
    /// re-linked instead of silently rolling forward. The runtime `startSession` path also
    /// performs a per-device signing key consistency check that catches such corruption directly,
    /// so this constant is primarily a forward-looking marker for future migrations.
    public static let sessionSchemaVersion: Int = 1
}


//
//  PQSSession+ControlEventCoalescing.swift
//  post-quantum-solace
//
//  Created by Cole M on 2026-04-17.
//
//  Copyright (c) 2026 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//

import BinaryCodable
import Foundation
import SessionModels

// MARK: - Supporting Types

/// Identifies the audience an emission is targeted at, for the purpose of single-flight
/// throttling. Two emissions of the same `kind` to the same `scope` within a cooldown
/// window collapse to one wire send.
public enum ControlEventScope: Hashable, Sendable {
    /// Targets the sender's own master/linked devices (`MessageRecipient.personalMessage`).
    case personal
    /// Targets one linked device on the sender's account.
    case personalDevice(deviceId: UUID)
    /// Targets a specific peer secretName (typically `MessageRecipient.nickname(name)`).
    case peer(secretName: String)
    /// Targets one concrete device belonging to a peer.
    case peerDevice(secretName: String, deviceId: UUID)

    var targetDeviceId: UUID? {
        switch self {
        case .personal, .peer:
            return nil
        case .personalDevice(let deviceId), .peerDevice(_, let deviceId):
            return deviceId
        }
    }

    var recoveryPeer: (secretName: String, deviceId: UUID)? {
        switch self {
        case .peerDevice(let secretName, let deviceId):
            return (secretName, deviceId)
        default:
            return nil
        }
    }
}

/// Composite key for the sender-side episode table.
public struct ControlEventEpisodeKey: Hashable, Sendable {
    public let kind: SessionReestablishmentKind
    public let scope: ControlEventScope

    public init(kind: SessionReestablishmentKind, scope: ControlEventScope) {
        self.kind = kind
        self.scope = scope
    }
}

/// Persistent (in-memory) sender-side state for a single control episode.
///
/// An "episode" is the period during which we treat re-emissions as the same logical
/// problem: e.g. one sequence of compromise notifications after a single key divergence,
/// not 30 separate notifications.
public struct ControlEventEpisode: Sendable {
    public var intentId: UUID
    public var epoch: UInt64
    public var firstEmittedAt: Date
    public var lastEmittedAt: Date
    public var emissionsThisEpisode: Int
}

/// Composite key for the receiver-side processed-event table.
public struct ProcessedControlEventKey: Hashable, Sendable {
    public let senderDeviceId: UUID
    public let kind: SessionReestablishmentKind

    public init(senderDeviceId: UUID, kind: SessionReestablishmentKind) {
        self.senderDeviceId = senderDeviceId
        self.kind = kind
    }
}

/// Receiver-side state recording the most recent envelope we acted upon for
/// `(senderDeviceId, kind)`. Used to drop duplicates and stale epochs from offline backlogs.
public struct ProcessedControlEventState: Sendable {
    public var lastProcessedEpoch: UInt64
    public var lastProcessedIntentId: UUID?
    public var lastProcessedAt: Date

    public init(
        lastProcessedEpoch: UInt64,
        lastProcessedIntentId: UUID?,
        lastProcessedAt: Date
    ) {
        self.lastProcessedEpoch = lastProcessedEpoch
        self.lastProcessedIntentId = lastProcessedIntentId
        self.lastProcessedAt = lastProcessedAt
    }
}

/// Outcome of receiver-side dedup evaluation for an inbound envelope.
public enum ProcessedControlEventDecision: Sendable, Equatable {
    /// First time we have seen this `(intentId, epoch)` for `(senderDeviceId, kind)` -> act on it.
    case process
    /// Same epoch, or same `intentId` without newer epoch ordering, as one we already acted on -> drop silently.
    case skipDuplicate
    /// Strictly older epoch than the latest we processed -> drop as out-of-order replay.
    case skipStale
}

extension PQSSession {

    // MARK: - Sender-Side Coalescing

    /// Build a `SessionReestablishmentEnvelope` for `(kind, scope)` if the configured cooldown
    /// allows it; otherwise return `nil` so the caller can skip the wire send.
    ///
    /// - Behaviour:
    ///   - If no episode exists, mints a new `intentId` + bumps the per-kind epoch counter.
    ///   - If an episode exists and we are within `cooldown(for: kind)` of `lastEmittedAt`,
    ///     suppress (returning `nil`).
    ///   - If we are past the cooldown but still within the episode's max lifetime, reuse
    ///     the same `intentId`, bump the epoch, and re-emit.
    ///   - If past the episode lifetime, treat as a new problem and mint a fresh `intentId`.
    func makeSessionReestablishmentEnvelope(
        kind: SessionReestablishmentKind,
        scope: ControlEventScope,
        forceReemit: Bool = false,
        requiresPreDecryptionReset: Bool = false
    ) -> SessionReestablishmentEnvelope? {
        pruneStaleSenderEpisodes()
        let now = Date()
        let key = ControlEventEpisodeKey(kind: kind, scope: scope)
        let cooldown = cooldownSeconds(for: kind)
        let episodeMaxLifetime = PQSSessionConstants.controlEventEpisodeMaxLifetimeSeconds

        if var existing = senderControlEpisodes[key] {
            if now.timeIntervalSince(existing.lastEmittedAt) < cooldown && !forceReemit {
                logger.log(
                    level: .debug,
                    message: "[control-event] sender suppressed kind=\(kind.rawValue) scope=\(scope) (within cooldown=\(Int(cooldown))s, episode=\(existing.intentId.uuidString))"
                )
                return nil
            }
            if now.timeIntervalSince(existing.firstEmittedAt) < episodeMaxLifetime {
                let nextEpoch = (senderControlEpochCounters[kind] ?? 0) + 1
                senderControlEpochCounters[kind] = nextEpoch
                existing.epoch = nextEpoch
                existing.lastEmittedAt = now
                existing.emissionsThisEpisode += 1
                senderControlEpisodes[key] = existing
                logger.log(
                    level: .info,
                    message: "[control-event] sender \(forceReemit ? "forced " : "")re-emit kind=\(kind.rawValue) scope=\(scope) intent=\(existing.intentId.uuidString) epoch=\(nextEpoch) attempt=\(existing.emissionsThisEpisode)")
                return SessionReestablishmentEnvelope(
                    kind: kind,
                    intentId: existing.intentId,
                    epoch: nextEpoch,
                    emittedAt: now,
                    targetDeviceId: scope.targetDeviceId,
                    requiresPreDecryptionReset: requiresPreDecryptionReset)
            }
            // Past episode lifetime: fall through to fresh-episode mint below.
            logger.log(
                level: .info,
                message: "[control-event] sender episode aged out kind=\(kind.rawValue) scope=\(scope); minting new intent"
            )
        }

        let intentId = UUID()
        let nextEpoch = (senderControlEpochCounters[kind] ?? 0) + 1
        senderControlEpochCounters[kind] = nextEpoch
        let episode = ControlEventEpisode(
            intentId: intentId,
            epoch: nextEpoch,
            firstEmittedAt: now,
            lastEmittedAt: now,
            emissionsThisEpisode: 1
        )
        senderControlEpisodes[key] = episode
        enforceSenderEpisodeBound()
        logger.log(
            level: .info,
            message: "[control-event] sender new episode kind=\(kind.rawValue) scope=\(scope) intent=\(intentId.uuidString) epoch=\(nextEpoch)")
        return SessionReestablishmentEnvelope(
            kind: kind,
            intentId: intentId,
            epoch: nextEpoch,
            emittedAt: now,
            targetDeviceId: scope.targetDeviceId,
            requiresPreDecryptionReset: requiresPreDecryptionReset)
    }

    /// Throttled, single-flight emission of a session-reestablishment control event.
    ///
    /// Encodes the envelope into `TransportEvent.sessionReestablishment(_:)` and writes a
    /// personal/peer message via `writeTextMessage(...)`. Returns `true` if a message was
    /// queued for transport, or `false` if the emission was suppressed by the cooldown.
    @discardableResult
    func emitSessionReestablishment(
        kind: SessionReestablishmentKind,
        recipient: MessageRecipient,
        scope: ControlEventScope,
        forceReemit: Bool = false
    ) async throws -> Bool {
        let localSecretName = await sessionContext?.sessionUser.secretName
        let recoveryPeer: (secretName: String, deviceId: UUID)?
        if let peer = scope.recoveryPeer {
            recoveryPeer = peer
        } else if case .personalDevice(let deviceId) = scope,
                  let localSecretName {
            recoveryPeer = (localSecretName, deviceId)
        } else {
            recoveryPeer = nil
        }
        let requiresPreDecryptionReset = kind == .peerRefresh && recoveryPeer != nil
        guard let envelope = makeSessionReestablishmentEnvelope(
            kind: kind,
            scope: scope,
            forceReemit: forceReemit,
            requiresPreDecryptionReset: requiresPreDecryptionReset) else {
            return false
        }
        // Register the pending request before any suspension point. A simultaneous
        // inbound peerRefresh bootstrap resolves its collision against this exact
        // state; registering after the reset `await` opens a window where both
        // devices accept each other's bootstrap and clobber freshly reset lanes.
        if let recoveryPeer, let intentId = envelope.intentId {
            registerExpectedPeerRefreshResponse(
                sender: recoveryPeer.secretName,
                deviceId: recoveryPeer.deviceId,
                intentId: intentId)
        }
        if requiresPreDecryptionReset, let recoveryPeer {
            do {
                _ = try await resetSessionIdentityForFreshSession(
                    secretName: recoveryPeer.secretName,
                    deviceId: recoveryPeer.deviceId,
                    sendOneTimeIdentities: false)
            } catch {
                senderControlEpisodes.removeValue(
                    forKey: ControlEventEpisodeKey(kind: kind, scope: scope))
                unregisterExpectedPeerRefreshResponse(
                    sender: recoveryPeer.secretName,
                    deviceId: recoveryPeer.deviceId)
                throw error
            }
        }
        let metadata = try BinaryEncoder().encode(TransportEvent.sessionReestablishment(envelope))
        do {
            try await writeTextMessage(
                recipient: recipient,
                transportInfo: metadata,
                targetDeviceId: scope.targetDeviceId)
        } catch {
            // Reset may already have committed a state-less row. Drop the expected
            // intent so a later successful emit can register a fresh one; the caller
            // owns ending the open reestablishment episode.
            senderControlEpisodes.removeValue(
                forKey: ControlEventEpisodeKey(kind: kind, scope: scope))
            if let recoveryPeer {
                unregisterExpectedPeerRefreshResponse(
                    sender: recoveryPeer.secretName,
                    deviceId: recoveryPeer.deviceId)
            }
            throw error
        }
        return true
    }

    /// Emits a response for a reestablishment request after the local refresh work has
    /// completed. Responses bypass sender-side cooldown so a legitimate acknowledgement
    /// is not suppressed by the request episode that may already be in flight.
    @discardableResult
    func emitSessionReestablishmentResponse(
        kind: SessionReestablishmentKind,
        recipient: MessageRecipient,
        respondingTo envelope: SessionReestablishmentEnvelope,
        targetDeviceId: UUID? = nil
    ) async throws -> Bool {
        let nextEpoch = max(
            (senderControlEpochCounters[kind] ?? 0) + 1,
            envelope.epoch + 1)
        senderControlEpochCounters[kind] = nextEpoch
        let response = SessionReestablishmentEnvelope(
            kind: kind,
            intentId: envelope.intentId ?? UUID(),
            epoch: nextEpoch,
            isResponse: true,
            targetDeviceId: targetDeviceId)
        let metadata = try BinaryEncoder().encode(TransportEvent.sessionReestablishment(response))
        try await writeTextMessage(
            recipient: recipient,
            transportInfo: metadata,
            targetDeviceId: targetDeviceId)
        return true
    }

    // MARK: - Receiver-Side Coalescing

    /// Decide whether an inbound `SessionReestablishmentEnvelope` should be acted upon, and
    /// atomically record that decision so exact replays from `senderDeviceId` are dropped while
    /// higher-epoch re-emits of the same intent can still drive a fresh idempotent response.
    func recordReceivedSessionReestablishment(
        envelope: SessionReestablishmentEnvelope,
        senderDeviceId: UUID
    ) -> ProcessedControlEventDecision {
        pruneStaleProcessedEvents()
        let key = ProcessedControlEventKey(senderDeviceId: senderDeviceId, kind: envelope.kind)
        let now = Date()

        if let existing = processedControlEvents[key] {
            if envelope.epoch > 0 && existing.lastProcessedEpoch > 0 {
                if envelope.epoch < existing.lastProcessedEpoch {
                    return .skipStale
                }
                if envelope.epoch == existing.lastProcessedEpoch {
                    return .skipDuplicate
                }
            } else if let existingIntent = existing.lastProcessedIntentId,
                      let incomingIntent = envelope.intentId,
                      existingIntent == incomingIntent {
                return .skipDuplicate
            }
        }

        processedControlEvents[key] = ProcessedControlEventState(
            lastProcessedEpoch: envelope.epoch,
            lastProcessedIntentId: envelope.intentId,
            lastProcessedAt: now
        )
        enforceProcessedEventsBound()
        return .process
    }

    func forgetReceivedSessionReestablishment(
        envelope: SessionReestablishmentEnvelope,
        senderDeviceId: UUID
    ) {
        let key = ProcessedControlEventKey(senderDeviceId: senderDeviceId, kind: envelope.kind)
        guard let existing = processedControlEvents[key] else { return }

        if envelope.epoch > 0, existing.lastProcessedEpoch == envelope.epoch {
            processedControlEvents.removeValue(forKey: key)
            return
        }

        if envelope.epoch == 0,
           let existingIntent = existing.lastProcessedIntentId,
           let incomingIntent = envelope.intentId,
           existingIntent == incomingIntent {
            processedControlEvents.removeValue(forKey: key)
        }
    }

    /// Returns `true` if a forced identity refresh for `secretName` should run now,
    /// throttled to one fire per `forcedIdentityRefreshCoalesceWindowSeconds`.
    /// The act of returning `true` records the timestamp so subsequent calls within
    /// the window return `false`.
    func shouldForceIdentityRefresh(secretName: String) -> Bool {
        let now = Date()
        if let last = lastForcedIdentityRefresh[secretName],
           now.timeIntervalSince(last) < PQSSessionConstants.forcedIdentityRefreshCoalesceWindowSeconds {
            return false
        }
        lastForcedIdentityRefresh[secretName] = now
        return true
    }

    // MARK: - Episode Lifecycle

    /// Reset sender-side compromise/repair episodes and clear the OTK upload circuit breaker
    /// after a successful `recoverFromSigningKeyMismatch()` so the next legitimate event can
    /// fire immediately rather than being silenced by a stale cooldown.
    func clearCompromiseEpisode() {
        let before = senderControlEpisodes.count
        senderControlEpisodes = senderControlEpisodes.filter { key, _ in
            key.kind != .linkedDeviceCompromiseObserved && key.kind != .linkedDeviceRepair
        }
        let removedCount = before - senderControlEpisodes.count
        otkUploadCircuitOpen = false
        otkUploadCircuitOpenedAt = nil
        if removedCount > 0 {
            logger.log(level: .info, message: "[control-event] cleared \(removedCount) compromise/repair episode(s) after successful recovery")
        }
    }

    // MARK: - Internals

    private func cooldownSeconds(for kind: SessionReestablishmentKind) -> TimeInterval {
        switch kind {
        case .peerRefresh:
            return PQSSessionConstants.peerRefreshCooldownSeconds
        case .linkedDeviceRepair:
            return PQSSessionConstants.linkedDeviceRepairCooldownSeconds
        case .linkedDeviceCompromiseObserved:
            return PQSSessionConstants.linkedDeviceCompromiseObservedCooldownSeconds
        }
    }

    private func pruneStaleSenderEpisodes() {
        let cutoff = Date().addingTimeInterval(-PQSSessionConstants.controlEventEpisodeMaxLifetimeSeconds)
        senderControlEpisodes = senderControlEpisodes.filter { _, episode in
            episode.firstEmittedAt > cutoff
        }
    }

    private func enforceSenderEpisodeBound() {
        let cap = PQSSessionConstants.controlEventEpisodeMaxEntries
        guard senderControlEpisodes.count > cap else { return }
        let sorted = senderControlEpisodes.sorted { lhs, rhs in
            lhs.value.lastEmittedAt < rhs.value.lastEmittedAt
        }
        for (key, _) in sorted.prefix(senderControlEpisodes.count - cap) {
            senderControlEpisodes.removeValue(forKey: key)
        }
    }

    private func pruneStaleProcessedEvents() {
        let cutoff = Date().addingTimeInterval(-PQSSessionConstants.processedControlEventMaxAgeSeconds)
        processedControlEvents = processedControlEvents.filter { _, value in
            value.lastProcessedAt > cutoff
        }
    }

    private func enforceProcessedEventsBound() {
        let cap = PQSSessionConstants.processedControlEventMaxEntries
        guard processedControlEvents.count > cap else { return }
        let sorted = processedControlEvents.sorted { lhs, rhs in
            lhs.value.lastProcessedAt < rhs.value.lastProcessedAt
        }
        for (key, _) in sorted.prefix(processedControlEvents.count - cap) {
            processedControlEvents.removeValue(forKey: key)
        }
    }
}

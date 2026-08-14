//
//  PQSSession+RecoveryBookkeeping.swift
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

/// Inbound-failure classification, quarantine, resend-request throttling,
/// reestablishment episodes, and accepted-envelope/send-record ledgers.
extension PQSSession {
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

    /// Marks an inbound tuple as terminally unrecoverable. Returns `true` only
    /// the first time the tuple is marked so callers notify the host exactly
    /// once per loss instead of once per redelivered copy.
    @discardableResult
    func markInboundContentUnrecoverable(
        sender: String,
        deviceId: UUID,
        sharedId: String,
        now: Date = Date()
    ) -> Bool {
        pruneRecoveryTimestamps(
            &terminalInboundOutcomeAt,
            ttl: PQSSessionConstants.terminalInboundOutcomeTTLSeconds,
            now: now)
        let key = inboundFailureQuarantineKey(sender: sender, deviceId: deviceId, messageId: sharedId)
        if terminalInboundOutcomeAt[key] != nil {
            return false
        }
        terminalInboundOutcomeAt[key] = now
        return true
    }

    /// True when this tuple already reached a terminal unrecoverable outcome.
    /// Consulted on decrypt failure so redelivered poison copies are swallowed
    /// without a fresh NACK round; never consulted before decrypt, so a late
    /// orphan replay that decrypts still recovers the content.
    func isInboundContentUnrecoverable(
        sender: String,
        deviceId: UUID,
        sharedId: String,
        now: Date = Date()
    ) -> Bool {
        let key = inboundFailureQuarantineKey(sender: sender, deviceId: deviceId, messageId: sharedId)
        guard let markedAt = terminalInboundOutcomeAt[key] else {
            return false
        }
        return now.timeIntervalSince(markedAt) < PQSSessionConstants.terminalInboundOutcomeTTLSeconds
    }

    /// Clears the terminal mark after content is recovered (late replay landed).
    func clearInboundTerminalOutcome(sender: String, deviceId: UUID, sharedId: String) {
        let key = inboundFailureQuarantineKey(sender: sender, deviceId: deviceId, messageId: sharedId)
        terminalInboundOutcomeAt.removeValue(forKey: key)
    }
    
    /// True when this sharedId already entered orphan-resend (discard + request resend) and is
    /// awaiting sender `orphanResend`. Used to keep `missingOneTimeKey` bootstrap from opening
    /// receive-side ASR on the same tuple (dogfood `883B532C`: maxSkipped → OTK ASR poisoned
    /// the orphan replay).
    func isAwaitingSenderOrphanResend(
        sender: String,
        deviceId: UUID,
        messageId: String,
        now: Date = Date()
    ) -> Bool {
        if resendRequestSubmissionCount(
            sender: sender,
            deviceId: deviceId,
            failedMessageId: messageId,
            now: now) > 0
        {
            return true
        }
        cleanupInboundFailurePolicy(now: now)
        let prefix = "\(sender)|\(deviceId.uuidString)|\(messageId)|"
        for (key, expiry) in inboundFailurePolicyUntil {
            guard expiry > now, key.hasPrefix(prefix) else { continue }
            let failureClass = String(key.dropFirst(prefix.count))
            // OTK bootstrap is the documented product exception — it must not count
            // as "already on orphan-resend" or we would never open a genuine OTK recovery.
            if failureClass == "ratchet.missingOneTimeKey" { continue }
            if failureClass.hasPrefix("ratchet.")
                || failureClass.hasPrefix("crypto.")
                || failureClass.hasPrefix("payload.")
                || failureClass.hasPrefix("signature.")
            {
                return true
            }
        }
        return false
    }

    /// Returns whether a specific inbound failure class should be suppressed for this tuple.
    func shouldSuppressInboundFailure(_ inbound: InboundTaskMessage, failureClass: String, now: Date = Date()) async -> Bool {
        cleanupInboundFailurePolicy(now: now)
        let key = inboundFailureKey(
            sender: inbound.senderSecretName,
            deviceId: inbound.senderDeviceId,
            messageId: inbound.sharedMessageId,
            failureClass: failureClass)
        guard let expiry = inboundFailurePolicyUntil[key] else {
            return false
        }
        if await hasPendingResendAfterReestablishment(
            sender: inbound.senderSecretName,
            deviceId: inbound.senderDeviceId,
            failedMessageId: inbound.sharedMessageId,
            now: now
        ) {
            return false
        }
        return expiry > now
    }

    /// True when the app delegate wants decrypt recovery dropped for a deleted peer.
    func shouldSuppressInboundRecoveryFromSender(_ senderSecretName: String) async -> Bool {
        await sessionDelegate?.shouldSuppressInboundRecoveryFromSender(senderSecretName) ?? false
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

    /// Records a distinct undecryptable inbound for this peer device and returns
    /// `true` when the lane is saturated (audit / metrics). Orphan-resend does **not**
    /// open receive-side session reset — the sender heals via orphanResend.
    func noteUndecryptableLaneFailure(
        sender: String,
        deviceId: UUID,
        sharedId: String,
        now: Date = Date()
    ) -> Bool {
        cleanupUndecryptableLaneFailures(now: now)
        let key = reestablishmentEpisodeKey(sender: sender, deviceId: deviceId)
        var entry = undecryptableLaneFailureIdsByPeer[key] ?? (ids: [], firstAt: now)
        entry.ids.insert(sharedId)
        undecryptableLaneFailureIdsByPeer[key] = entry
        return entry.ids.count >= PQSSessionConstants.undecryptableLaneEscalateThreshold
    }

    /// Clears lane-level undecryptable tracking after a heal or session reset.
    func clearUndecryptableLaneFailures(sender: String, deviceId: UUID) async {
        undecryptableLaneFailureIdsByPeer.removeValue(
            forKey: reestablishmentEpisodeKey(sender: sender, deviceId: deviceId))
        await messagePipeline.clearArchivedInboundFallbackExhausted(
            sender: sender,
            deviceId: deviceId)
    }

    private func cleanupUndecryptableLaneFailures(now: Date) {
        let ttl = inboundFailurePolicyTTL
        undecryptableLaneFailureIdsByPeer = undecryptableLaneFailureIdsByPeer.filter {
            now.timeIntervalSince($0.value.firstAt) < ttl
        }
        let cap = PQSSessionConstants.recoveryTrackingMaxEntries
        guard undecryptableLaneFailureIdsByPeer.count >= cap else { return }
        let overflowKeys = undecryptableLaneFailureIdsByPeer
            .sorted { $0.value.firstAt < $1.value.firstAt }
            .prefix(undecryptableLaneFailureIdsByPeer.count - cap + 1)
            .map(\.key)
        for key in overflowKeys {
            undecryptableLaneFailureIdsByPeer.removeValue(forKey: key)
        }
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
    func pruneRecoveryTimestamps(
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
    /// SHA256-ready raw fingerprint of an undecryptable inbound frame (signed payload).
    static func nackFrameFingerprint(for message: InboundTaskMessage) -> Data {
        message.message.signed?.data ?? Data(message.sharedMessageId.utf8)
    }

    /// Remember the frame fingerprint when a NACK is queued/submitted so rearm can
    /// distinguish backlog redelivery from new sender orphan material.
    func rememberNackFrameFingerprint(
        sender: String,
        deviceId: UUID,
        failedMessageId: String,
        fingerprint: Data
    ) {
        let requestKey = peerResendRequestKey(
            sender: sender,
            deviceId: deviceId,
            failedMessageId: failedMessageId)
        lastNackFrameFingerprintByKey[requestKey] = fingerprint
        if lastNackFrameFingerprintByKey.count > PQSSessionConstants.recoveryTrackingMaxEntries {
            let overflow = lastNackFrameFingerprintByKey.count
                - PQSSessionConstants.recoveryTrackingMaxEntries
            for key in lastNackFrameFingerprintByKey.keys.prefix(overflow) {
                lastNackFrameFingerprintByKey.removeValue(forKey: key)
            }
        }
    }

    /// A fresh ciphertext for a sharedId that already had a transport-confirmed
    /// NACK still failed decrypt — the prior sender `orphanResend` did not prove.
    /// Clear send-cooldown and failure-class suppress so we can re-request within
    /// ``PQSSessionConstants.peerResendRequestMaxSubmissions``. Event-driven (failed
    /// decrypt of *new* sender material), not a timer retry. No receive-side ASR.
    @discardableResult
    func armPeerResendRetryAfterFailedReplay(
        sender: String,
        deviceId: UUID,
        failedMessageId: String,
        currentFingerprint: Data,
        now: Date = Date()
    ) -> Bool {
        let attempts = resendRequestSubmissionCount(
            sender: sender,
            deviceId: deviceId,
            failedMessageId: failedMessageId,
            now: now)
        let requestKey = peerResendRequestKey(
            sender: sender,
            deviceId: deviceId,
            failedMessageId: failedMessageId)
        let priorFingerprint = lastNackFrameFingerprintByKey[requestKey]
        guard OrphanReplayRearmPolicy.shouldRearm(
            priorFingerprint: priorFingerprint,
            currentFingerprint: currentFingerprint,
            attempts: attempts)
        else {
            return false
        }
        lastResendRequestAtByPeer.removeValue(forKey: requestKey)
        _ = takeInboundFailureClasses(
            sender: sender,
            deviceId: deviceId,
            messageId: failedMessageId,
            now: now)
        auditSink.log(.recovery, "pqs.recovery.orphanReplayStillUndecryptable sharedId=\(failedMessageId) sender=\(sender) deviceId=\(deviceId.uuidString) priorAttempts=\(attempts) action=rearmNack")
        return true
    }
    
    /// Marks a resend/refresh control request as sent (queued) for this failed message.
    /// Only arms the request cooldown; attempts toward
    /// `PQSSessionConstants.peerResendRequestMaxSubmissions` are counted by
    /// ``markPeerResendRequestTransported(sender:deviceId:failedMessageIds:now:)`` when
    /// the request frame actually reaches the transport. Queue-time counting burned
    /// attempts for requests that died before the wire and dropped recoverable content.
    func markPeerResendRequestSent(sender: String, deviceId: UUID, failedMessageId: String, now: Date = Date()) {
        let requestKey = peerResendRequestKey(sender: sender, deviceId: deviceId, failedMessageId: failedMessageId)
        pruneRecoveryTimestamps(&lastResendRequestAtByPeer, ttl: peerResendRequestCooldown, now: now)
        lastResendRequestAtByPeer[requestKey] = now
    }

    /// Counts one confirmed submission per failed message id after the resend-request
    /// frame was handed to the transport. This is the event that spends an attempt
    /// toward `PQSSessionConstants.peerResendRequestMaxSubmissions`.
    func markPeerResendRequestTransported(sender: String, deviceId: UUID, failedMessageIds: [String], now: Date = Date()) {
        pruneResendRequestAttempts(now: now)
        for failedMessageId in failedMessageIds {
            let requestKey = peerResendRequestKey(sender: sender, deviceId: deviceId, failedMessageId: failedMessageId)
            let attempts = (resendRequestAttemptsByKey[requestKey]?.attempts ?? 0) + 1
            resendRequestAttemptsByKey[requestKey] = (attempts, now)
        }
    }

    /// Total transport-confirmed resend-request submissions recorded for this failed
    /// message inside the durable attempt window
    /// (`PQSSessionConstants.resendRequestAttemptWindowSeconds`).
    func resendRequestSubmissionCount(sender: String, deviceId: UUID, failedMessageId: String, now: Date = Date()) -> Int {
        pruneResendRequestAttempts(now: now)
        let requestKey = peerResendRequestKey(sender: sender, deviceId: deviceId, failedMessageId: failedMessageId)
        return resendRequestAttemptsByKey[requestKey]?.attempts ?? 0
    }

    /// `true` when any resend-request for this peer device has been transport-confirmed.
    /// Used to open a coalesce episode after undecryptable-lane saturation without minting
    /// a receive-side repair session.
    func hasTransportedPeerResendRequest(
        sender: String,
        deviceId: UUID,
        now: Date = Date()
    ) -> Bool {
        pruneResendRequestAttempts(now: now)
        let prefix = "\(sender)|\(deviceId.uuidString)|"
        return resendRequestAttemptsByKey.contains { key, entry in
            key.hasPrefix(prefix) && entry.attempts > 0
        }
    }

    private func pruneResendRequestAttempts(now: Date) {
        resendRequestAttemptsByKey = resendRequestAttemptsByKey.filter { _, entry in
            now.timeIntervalSince(entry.lastAt) < PQSSessionConstants.resendRequestAttemptWindowSeconds
        }
        let cap = PQSSessionConstants.recoveryTrackingMaxEntries
        guard resendRequestAttemptsByKey.count >= cap else { return }
        let overflowKeys = resendRequestAttemptsByKey
            .sorted { $0.value.lastAt < $1.value.lastAt }
            .prefix(resendRequestAttemptsByKey.count - cap + 1)
            .map(\.key)
        for key in overflowKeys {
            resendRequestAttemptsByKey.removeValue(forKey: key)
        }
    }

    /// Builds a stable key for responder-side resend servicing, scoped to the requesting device
    /// and the specific failed message being replayed.
    func peerResendServiceKey(requestingDeviceId: UUID, sharedId: String) -> String {
        "\(requestingDeviceId.uuidString)|\(sharedId)"
    }

    /// Returns whether we may service (replay a frame for) an inbound resend request for this
    /// `(requestingDeviceId, sharedId)`. Repeated identical requests inside the cooldown are
    /// refused so a looping peer cannot amplify replay work or drain our one-time keys.
    func canServicePeerResendRequest(requestingDeviceId: UUID, sharedId: String, now: Date = Date()) -> Bool {
        let requestKey = peerResendServiceKey(requestingDeviceId: requestingDeviceId, sharedId: sharedId)
        if let lastServicedAt = lastServicedResendAtByRequest[requestKey],
           now.timeIntervalSince(lastServicedAt) < peerResendServiceCooldown {
            return false
        }
        return true
    }

    /// Records that we serviced an inbound resend request for this `(requestingDeviceId, sharedId)`.
    func markPeerResendRequestServiced(requestingDeviceId: UUID, sharedId: String, now: Date = Date()) {
        let requestKey = peerResendServiceKey(requestingDeviceId: requestingDeviceId, sharedId: sharedId)
        pruneRecoveryTimestamps(&lastServicedResendAtByRequest, ttl: peerResendServiceCooldown, now: now)
        lastServicedResendAtByRequest[requestKey] = now
    }

    /// Remembers that a requested shared message id has no local replay source for this
    /// requesting device, so repeat requests can skip the lookup and just re-notify.
    func markResendUnavailable(requestingDeviceId: UUID, sharedId: String, now: Date = Date()) {
        let key = peerResendServiceKey(requestingDeviceId: requestingDeviceId, sharedId: sharedId)
        let cap = PQSSessionConstants.unavailableResendMemoryMaxEntries
        if unavailableResendIds[key] == nil, unavailableResendIds.count >= cap {
            let overflowKeys = unavailableResendIds
                .sorted { $0.value < $1.value }
                .prefix(unavailableResendIds.count - cap + 1)
                .map(\.key)
            for overflowKey in overflowKeys {
                unavailableResendIds.removeValue(forKey: overflowKey)
            }
        }
        unavailableResendIds[key] = now
    }

    /// True when a previous replay lookup already proved this requested id unreplayable.
    func isKnownUnavailableResend(requestingDeviceId: UUID, sharedId: String) -> Bool {
        unavailableResendIds[peerResendServiceKey(requestingDeviceId: requestingDeviceId, sharedId: sharedId)] != nil
    }

    func deferPeerResendUntilReestablished(
        sender: String,
        deviceId: UUID,
        failedMessageId: String,
        failureClass: String,
        now: Date = Date(),
        notifyDelegate: Bool = true
    ) async {
        await cleanupPendingResendAfterReestablishment(now: now)
        let requestKey = peerResendRequestKey(sender: sender, deviceId: deviceId, failedMessageId: failedMessageId)
        pendingResendAfterReestablishment[requestKey] = PendingResendAfterReestablishment(
            senderName: sender,
            senderDeviceId: deviceId,
            failedSharedMessageId: failedMessageId,
            failureClass: failureClass,
            createdAt: now)
        guard notifyDelegate else { return }
        await noteInboundMessagePendingRecovery(
            sender: sender,
            deviceId: deviceId,
            sharedMessageId: failedMessageId)
        let delegate = sessionDelegate
        // Protocol signal: drives the transport's bounded claim-and-purge of the
        // undecryptable spool copy. Dropping it on a viability flap leaves the
        // copy immortal server-side (redelivered every backlog wave).
        _ = await scheduleTransportProtocolWork {
            await delegate?.inboundRecoveryDeferred(
                senderSecretName: sender,
                senderDeviceId: deviceId,
                failedSharedMessageId: failedMessageId,
                failureClass: failureClass)
        }
    }

    /// Notifies the host once per logical sharedId that inbound recovery is pending
    /// (placeholder UI). Subsequent coalesce/redelivery of the same id is silent.
    func noteInboundMessagePendingRecovery(
        sender: String,
        deviceId: UUID,
        sharedMessageId: String
    ) async {
        let trimmed = sharedMessageId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let key = inboundFailureQuarantineKey(
            sender: sender,
            deviceId: deviceId,
            messageId: trimmed)
        if pendingRecoveryNotifiedKeys.contains(key) { return }
        pendingRecoveryNotifiedKeys.insert(key)
        let cap = PQSSessionConstants.recoveryTrackingMaxEntries
        if pendingRecoveryNotifiedKeys.count > cap {
            let overflow = pendingRecoveryNotifiedKeys.count - cap
            for stale in pendingRecoveryNotifiedKeys.prefix(overflow) {
                pendingRecoveryNotifiedKeys.remove(stale)
            }
        }
        let delegate = sessionDelegate
        _ = await scheduleTransportProtocolWork {
            await delegate?.inboundMessagePendingRecovery(
                senderSecretName: sender,
                senderDeviceId: deviceId,
                sharedMessageId: trimmed)
        }
    }

    /// Takes deferred NACKs for a peer-device lane and submits one chunked OOB request.
    func flushPendingResends(
        sender: String,
        deviceId: UUID,
        reason: String,
        now: Date = Date()
    ) async {
        let pending = await takePendingResendsAfterReestablishment(
            sender: sender,
            deviceId: deviceId,
            now: now)
        guard !pending.isEmpty else { return }
        await messagePipeline.drainDeferredResendRequests(
            pending,
            session: self,
            reason: reason)
    }

    /// Batch boundary after an offline backlog wave: drain every deferred lane so
    /// idle senders still receive durable OOB NACKs (spooled if offline).
    public func flushPendingResendsAfterOfflineReplay(now: Date = Date()) async {
        await cleanupPendingResendAfterReestablishment(now: now)
        struct Lane: Hashable {
            let sender: String
            let deviceId: UUID
        }
        let lanes = Set(
            pendingResendAfterReestablishment.values.map {
                Lane(sender: $0.senderName, deviceId: $0.senderDeviceId)
            })
        for lane in lanes {
            await flushPendingResends(
                sender: lane.sender,
                deviceId: lane.deviceId,
                reason: "offlineReplayComplete",
                now: now)
        }
    }

    /// Host re-arm after process relaunch: PQS pending-resend state is in-memory,
    /// while the host's recovery placeholder rows are durable. Repopulating the
    /// deferred NACK lane lets the next drain event retry recovery for rows that
    /// would otherwise wait forever. `notifyDelegate: false` because the host
    /// already owns the placeholder row and the spool copy was purged when the
    /// failure was originally deferred — re-arming must not re-fire purge or
    /// pending-recovery callbacks.
    public func rearmInboundRecoveryPendingResend(
        sender: String,
        deviceId: UUID,
        sharedMessageId: String,
        now: Date = Date()
    ) async {
        await deferPeerResendUntilReestablished(
            sender: sender,
            deviceId: deviceId,
            failedMessageId: sharedMessageId,
            failureClass: "hostRearm",
            now: now,
            notifyDelegate: false)
        auditSink.log(.recovery, "pqs.recovery.pendingResendRearmed sharedId=\(sharedMessageId) sender=\(sender) deviceId=\(deviceId.uuidString)")
    }

    func hasPendingResendAfterReestablishment(
        sender: String,
        deviceId: UUID,
        now: Date = Date()
    ) async -> Bool {
        await cleanupPendingResendAfterReestablishment(now: now)
        return pendingResendAfterReestablishment.values.contains { pending in
            pending.senderName == sender && pending.senderDeviceId == deviceId
        }
    }

    func hasPendingResendAfterReestablishment(
        sender: String,
        deviceId: UUID,
        failedMessageId: String,
        now: Date = Date()
    ) async -> Bool {
        await cleanupPendingResendAfterReestablishment(now: now)
        let requestKey = peerResendRequestKey(sender: sender, deviceId: deviceId, failedMessageId: failedMessageId)
        return pendingResendAfterReestablishment[requestKey] != nil
    }

    func reestablishmentEpisodeKey(sender: String, deviceId: UUID) -> String {
        "\(sender)|\(deviceId.uuidString)"
    }

    func cleanupOpenReestablishmentEpisodes(now: Date = Date()) async {
        let cutoff = now.addingTimeInterval(-reestablishmentEpisodeTTL)
        let expiredKeys = openReestablishmentEpisodes.compactMap { key, startedAt in
            startedAt <= cutoff ? key : nil
        }
        guard !expiredKeys.isEmpty else { return }
        openReestablishmentEpisodes = openReestablishmentEpisodes.filter { _, startedAt in
            startedAt > cutoff
        }
        for key in expiredKeys {
            expectedPeerRefreshIntentByPeer.removeValue(forKey: key)
            deadSessionCiphertextEpisodes.remove(key)
        }
        // TTL expiry is a terminal lifecycle event, same as an explicit end. Hosts
        // latch state on open episodes (e.g. NudgeKit defers its offline backlog
        // request) and only release it from `reestablishmentEpisodeDidEnd` — a
        // silently expired episode would leave that state stuck until an unrelated
        // episode ends or the app foregrounds.
        let expiredPeers = expiredKeys.compactMap { key -> (sender: String, deviceId: UUID)? in
            let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
            guard parts.count == 2, let deviceId = UUID(uuidString: parts[1]) else { return nil }
            return (parts[0], deviceId)
        }
        for peer in expiredPeers {
            auditSink.log(.recovery, "pqs.recovery.episodeExpired sender=\(peer.sender) deviceId=\(peer.deviceId.uuidString) ttlSeconds=\(Int(reestablishmentEpisodeTTL))")
            // Idle senders never produce a peerRefresh response; drain deferred
            // NACKs on the concrete episode-end event so the queue cannot rot.
            await flushPendingResends(
                sender: peer.sender,
                deviceId: peer.deviceId,
                reason: "episodeExpired")
        }
        guard !expiredPeers.isEmpty else { return }
        let delegate = sessionDelegate
        // Protocol signal: the transport releases held offline ciphertext on it.
        _ = await scheduleTransportProtocolWork {
            for peer in expiredPeers {
                await delegate?.reestablishmentEpisodeDidEnd(
                    senderSecretName: peer.sender,
                    senderDeviceId: peer.deviceId)
            }
        }
    }

    /// `true` when a reestablishment episode for this peer device is already open.
    public func hasOpenReestablishmentEpisode(
        sender: String,
        deviceId: UUID,
        now: Date = Date()
    ) async -> Bool {
        await cleanupOpenReestablishmentEpisodes(now: now)
        return openReestablishmentEpisodes[reestablishmentEpisodeKey(sender: sender, deviceId: deviceId)] != nil
    }

    /// `true` when any peer-device recovery episode is open. Used by transport to
    /// coalesce offline backlog requests while recovery owns inbound decrypt order.
    public func hasAnyOpenReestablishmentEpisode(now: Date = Date()) async -> Bool {
        await cleanupOpenReestablishmentEpisodes(now: now)
        return !openReestablishmentEpisodes.isEmpty
    }

    /// `true` when an open episode for this peer device should make transport
    /// hold offline ciphertext replay (held frames may decrypt once the lane
    /// heals, e.g. after a sender orphan-resend). Episodes opened for
    /// dead-session classes (`missingOneTimeKey`) return `false`: their spooled
    /// frames can never decrypt, so holding them only builds an immortal
    /// redelivery queue — they must flow to the bounded attempt-and-purge path.
    public func shouldHoldOfflineCiphertextDuringRecovery(
        sender: String,
        deviceId: UUID,
        now: Date = Date()
    ) async -> Bool {
        await cleanupOpenReestablishmentEpisodes(now: now)
        let key = reestablishmentEpisodeKey(sender: sender, deviceId: deviceId)
        guard openReestablishmentEpisodes[key] != nil else { return false }
        return !deadSessionCiphertextEpisodes.contains(key)
    }

    /// Opens a single-flight episode. Returns `true` when this caller is the leader
    /// (should attempt reset + peerRefresh). Returns `false` when an episode is
    /// already open and the caller must only coalesce deferred resend.
    ///
    /// `heldOfflineFramesCanHeal: false` marks the episode as covering a dead
    /// session epoch (see `deadSessionCiphertextEpisodes`). The mark also
    /// applies when the episode is already open: a `missingOneTimeKey` failure
    /// proves the epoch is dead no matter which class opened the episode first.
    @discardableResult
    func tryBeginReestablishmentEpisode(
        sender: String,
        deviceId: UUID,
        heldOfflineFramesCanHeal: Bool = true,
        now: Date = Date()
    ) async -> Bool {
        await cleanupOpenReestablishmentEpisodes(now: now)
        let key = reestablishmentEpisodeKey(sender: sender, deviceId: deviceId)
        if !heldOfflineFramesCanHeal {
            deadSessionCiphertextEpisodes.insert(key)
        }
        if openReestablishmentEpisodes[key] != nil {
            return false
        }
        openReestablishmentEpisodes[key] = now
        return true
    }

    func endReestablishmentEpisode(sender: String, deviceId: UUID) async {
        let key = reestablishmentEpisodeKey(sender: sender, deviceId: deviceId)
        let wasOpen = openReestablishmentEpisodes.removeValue(forKey: key) != nil
        expectedPeerRefreshIntentByPeer.removeValue(forKey: key)
        deadSessionCiphertextEpisodes.remove(key)
        await clearUndecryptableLaneFailures(sender: sender, deviceId: deviceId)
        guard wasOpen else { return }
        auditSink.log(.recovery, "pqs.recovery.episodeEnded sender=\(sender) deviceId=\(deviceId.uuidString)")
        // Drain any leftover deferred NACKs (emit-failure / explicit end). Success
        // paths that already `takePending` leave this a no-op.
        await flushPendingResends(
            sender: sender,
            deviceId: deviceId,
            reason: "episodeEnded")
        let delegate = sessionDelegate
        // Protocol signal: the transport releases held offline ciphertext on it.
        _ = await scheduleTransportProtocolWork {
            await delegate?.reestablishmentEpisodeDidEnd(
                senderSecretName: sender,
                senderDeviceId: deviceId)
        }
    }

    func setAccountIdentityRequiresAcknowledgement(_ requiresAcknowledgement: Bool) {
        accountIdentityRequiresAcknowledgement = requiresAcknowledgement
    }

    func registerExpectedPeerRefreshResponse(
        sender: String,
        deviceId: UUID,
        intentId: UUID
    ) {
        expectedPeerRefreshIntentByPeer[
            reestablishmentEpisodeKey(sender: sender, deviceId: deviceId)
        ] = intentId
    }

    func unregisterExpectedPeerRefreshResponse(sender: String, deviceId: UUID) {
        expectedPeerRefreshIntentByPeer.removeValue(
            forKey: reestablishmentEpisodeKey(sender: sender, deviceId: deviceId))
    }

    func isExpectedPeerRefreshResponse(
        sender: String,
        deviceId: UUID,
        intentId: UUID?
    ) -> Bool {
        guard let intentId else { return false }
        return expectedPeerRefreshIntentByPeer[
            reestablishmentEpisodeKey(sender: sender, deviceId: deviceId)
        ] == intentId
    }

    /// Returns whether this lane still owns a live local peer-refresh request.
    /// Used to defer resend drain until the correlated peerRefresh response arrives.
    func hasActiveLocalPeerRefreshRequest(
        sender: String,
        deviceId: UUID,
        now: Date = Date()
    ) async -> Bool {
        await cleanupOpenReestablishmentEpisodes(now: now)
        let key = reestablishmentEpisodeKey(sender: sender, deviceId: deviceId)
        guard openReestablishmentEpisodes[key] != nil else {
            expectedPeerRefreshIntentByPeer.removeValue(forKey: key)
            return false
        }
        return expectedPeerRefreshIntentByPeer[key] != nil
    }

    /// Records which local SessionIdentity encrypted an envelope to a recipient device
    /// (MessageRecord-lite). Supersedes any prior live envelope for the same
    /// logical `(sharedId, recipientDeviceId)`.
    func recordOutboundDeviceSend(
        sharedId: String,
        recipientSecretName: String,
        recipientDeviceId: UUID,
        sessionIdentityId: UUID,
        envelopeMessageId: String,
        resendAttempt: Int = 0
    ) async {
        let envelopeId = envelopeMessageId
        let logicalKey = OutboundDeviceSendRecord.logicalKey(
            sharedId: sharedId,
            recipientDeviceId: recipientDeviceId)
        var priorLiveRecord = outboundDeviceSendRecordsByKey[logicalKey]
        if priorLiveRecord == nil {
            priorLiveRecord = await outboundDeviceSendRecord(
                sharedId: sharedId,
                recipientDeviceId: recipientDeviceId)
        }
        if let prior = priorLiveRecord,
           prior.envelopeMessageId != envelopeId,
           prior.supersededAt == nil {
            let superseded = OutboundDeviceSendRecord(
                envelopeMessageId: prior.envelopeMessageId,
                sharedId: prior.sharedId,
                recipientSecretName: prior.recipientSecretName,
                recipientDeviceId: prior.recipientDeviceId,
                sessionIdentityId: prior.sessionIdentityId,
                resendAttempt: prior.resendAttempt,
                createdAt: prior.createdAt,
                supersededAt: Date())
            outboundDeviceSendRecordsByKey[OutboundDeviceSendRecord.key(envelopeMessageId: prior.envelopeMessageId)] = superseded
            try? await cache?.upsertOutboundDeviceSendRecord(superseded)
        }
        let record = OutboundDeviceSendRecord(
            envelopeMessageId: envelopeId,
            sharedId: sharedId,
            recipientSecretName: recipientSecretName,
            recipientDeviceId: recipientDeviceId,
            sessionIdentityId: sessionIdentityId,
            resendAttempt: resendAttempt)
        outboundDeviceSendRecordsByKey[logicalKey] = record
        outboundDeviceSendRecordsByKey[OutboundDeviceSendRecord.key(envelopeMessageId: envelopeId)] = record
        if outboundDeviceSendRecordsByKey.count > PQSSessionConstants.outboundDeviceSendRecordMaxCount {
            let overflow = outboundDeviceSendRecordsByKey.count
                - PQSSessionConstants.outboundDeviceSendRecordMaxCount
            let oldestKeys = outboundDeviceSendRecordsByKey
                .sorted { $0.value.createdAt < $1.value.createdAt }
                .prefix(overflow)
                .map(\.key)
            for oldKey in oldestKeys {
                outboundDeviceSendRecordsByKey.removeValue(forKey: oldKey)
            }
        }
        do {
            try await cache?.upsertOutboundDeviceSendRecord(record)
        } catch {
            logger.log(
                level: .debug,
                message: "pqs.send.recordPersistFailed sharedId=\(sharedId) envelope=\(envelopeId) deviceId=\(recipientDeviceId) error=\(error)")
        }
        logger.log(
            level: .debug,
            message: "pqs.send.envelopeRecorded logicalSharedId=\(sharedId) envelopeMessageId=\(envelopeId) deviceId=\(recipientDeviceId.uuidString)")
    }

    func outboundDeviceSendRecord(
        sharedId: String,
        recipientDeviceId: UUID
    ) async -> OutboundDeviceSendRecord? {
        let key = OutboundDeviceSendRecord.logicalKey(
            sharedId: sharedId,
            recipientDeviceId: recipientDeviceId)
        if let cached = outboundDeviceSendRecordsByKey[key], cached.supersededAt == nil {
            return cached
        }
        if let stored = try? await cache?.fetchOutboundDeviceSendRecord(
            sharedId: sharedId,
            recipientDeviceId: recipientDeviceId
        ), stored.supersededAt == nil {
            outboundDeviceSendRecordsByKey[key] = stored
            outboundDeviceSendRecordsByKey[OutboundDeviceSendRecord.key(envelopeMessageId: stored.envelopeMessageId)] = stored
            return stored
        }
        return nil
    }

    func outboundDeviceSendRecord(envelopeMessageId: String) async -> OutboundDeviceSendRecord? {
        let key = OutboundDeviceSendRecord.key(envelopeMessageId: envelopeMessageId)
        if let cached = outboundDeviceSendRecordsByKey[key] {
            return cached
        }
        if let stored = try? await cache?.fetchOutboundDeviceSendRecord(
            envelopeMessageId: envelopeMessageId
        ) {
            outboundDeviceSendRecordsByKey[key] = stored
            outboundDeviceSendRecordsByKey[
                OutboundDeviceSendRecord.logicalKey(
                    sharedId: stored.sharedId,
                    recipientDeviceId: stored.recipientDeviceId)] = stored
            return stored
        }
        return nil
    }

    func hasAcceptedEnvelope(
        senderSecretName: String,
        senderDeviceId: UUID,
        envelopeMessageId: String
    ) async throws -> Bool {
        let key = AcceptedEnvelopeKey(
            senderSecretName: senderSecretName,
            senderDeviceId: senderDeviceId,
            envelopeMessageId: envelopeMessageId)
        if AcceptedEnvelopeLedgerPolicy.shouldAckAndDrop(key: key, accepted: acceptedEnvelopeKeys) {
            return true
        }
        guard let cache else { throw PQSError.databaseNotInitialized }
        if let stored = try await cache.fetchAcceptedEnvelope(
            senderSecretName: senderSecretName,
            senderDeviceId: senderDeviceId,
            envelopeMessageId: envelopeMessageId
        ) {
            rememberAcceptedEnvelopeKey(stored.storageKey)
            return true
        }
        return false
    }

    func markEnvelopeAccepted(
        senderSecretName: String,
        senderDeviceId: UUID,
        envelopeMessageId: String,
        logicalSharedId: String
    ) async throws {
        guard AcceptedEnvelopeLedgerPolicy.shouldMarkAccepted(
            decryptSucceeded: true,
            payloadDecoded: true,
            hostHandlingSucceeded: true
        ) else { return }
        let record = AcceptedEnvelopeRecord(
            senderSecretName: senderSecretName,
            senderDeviceId: senderDeviceId,
            envelopeMessageId: envelopeMessageId,
            logicalSharedId: logicalSharedId)
        // Durability precedes the in-memory marker and transport ACK. If this
        // write fails, the caller must not delete the spool entry.
        guard let cache else { throw PQSError.databaseNotInitialized }
        try await cache.upsertAcceptedEnvelope(record)
        rememberAcceptedEnvelopeKey(record.storageKey)
        auditSink.log(.recovery, "pqs.recovery.envelopeAccepted sender=\(senderSecretName) deviceId=\(senderDeviceId.uuidString) envelope=\(envelopeMessageId) logical=\(logicalSharedId)",
            level: .debug)
    }

    func pruneAcceptedEnvelopes(now: Date = Date()) async {
        let cutoff = now.addingTimeInterval(-acceptedEnvelopeRetention)
        if let pruned = try? await cache?.pruneAcceptedEnvelopes(olderThan: cutoff), pruned > 0 {
            logger.log(level: .info, message: "pqs.recovery.acceptedEnvelopePruned count=\(pruned)")
        }
        acceptedEnvelopeKeys.removeAll(keepingCapacity: true)
        acceptedEnvelopeKeyOrder.removeAll(keepingCapacity: true)
    }

    private func rememberAcceptedEnvelopeKey(_ key: String) {
        guard acceptedEnvelopeKeys.insert(key).inserted else { return }
        acceptedEnvelopeKeyOrder.append(key)
        while acceptedEnvelopeKeyOrder.count > 4_096 {
            let evicted = acceptedEnvelopeKeyOrder.removeFirst()
            acceptedEnvelopeKeys.remove(evicted)
        }
    }

    /// Terminal clear for ids the peer reported as unreplayable: drops their pending
    /// resend entries and attempt/cooldown bookkeeping, and quarantines each tuple so
    /// a redelivered poison copy is dropped instead of reopening recovery.
    /// Returns the ids that actually had a pending resend entry.
    @discardableResult
    func clearPendingResends(
        sender: String,
        deviceId: UUID,
        messageIds: [String],
        now: Date = Date()
    ) async -> [String] {
        await cleanupPendingResendAfterReestablishment(now: now)
        var clearedIds: [String] = []
        for messageId in messageIds {
            let requestKey = peerResendRequestKey(sender: sender, deviceId: deviceId, failedMessageId: messageId)
            if pendingResendAfterReestablishment.removeValue(forKey: requestKey) != nil {
                clearedIds.append(messageId)
            }
            resendRequestAttemptsByKey.removeValue(forKey: requestKey)
            lastResendRequestAtByPeer.removeValue(forKey: requestKey)
            quarantineInboundFailure(sender: sender, deviceId: deviceId, messageId: messageId, now: now)
        }
        return clearedIds
    }

    func takePendingResendsAfterReestablishment(
        sender: String,
        deviceId: UUID,
        satisfiedSharedMessageId: String? = nil,
        now: Date = Date()
    ) async -> [PendingResendAfterReestablishment] {
        await cleanupPendingResendAfterReestablishment(now: now)
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

    private func cleanupPendingResendAfterReestablishment(now: Date = Date()) async {
        // Event-driven terminality only (unavailable / submission cap / dead-epoch).
        // Wall-clock age must not terminalize deferred NACKs for idle senders.
        // Bound the in-memory queue by LRU only.
        _ = now
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
}

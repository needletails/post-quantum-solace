//
//  TaskProcessor+RatchetRecovery.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-14.
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
import SessionEvents
import SessionModels
import NeedleTailLogger

/// Recovery and resend path: pending outbound transport bookkeeping,
/// authenticated resend servicing, and deferred resend drains.
extension MessagePipeline {
    func pendingOutboundTransport(
        sharedId: String,
        now: Date = Date()
    ) -> PendingOutboundTransport? {
        cleanupPendingOutboundTransport(now: now)
        return pendingOutboundTransportBySharedId[sharedId]
    }

    func logRecoveryTransportSendSuccess(_ event: TransportEvent?, sharedId: String) {
        guard let event else { return }

        switch event {
        case .sessionReestablishment(let envelope):
            logger.log(
                level: .info,
                message: "pqs.recovery.reestablishmentSent sharedId=\(sharedId) kind=\(envelope.kind.rawValue) response=\(envelope.isResponse) epoch=\(envelope.epoch) intent=\(envelope.intentId?.uuidString ?? "nil")")
        case .linkedDeviceReprovisioning(let bundle):
            logger.log(
                level: .info,
                message: "pqs.recovery.linkedDeviceReprovisioningSent sharedId=\(sharedId) targetDeviceId=\(bundle.targetDeviceId)")
        case .synchronizeOneTimeKeys,
             .refreshOneTimeKeys,
             .publishedOneTimeKeysReplenished:
            break
        }
    }

    func shouldRememberPendingOutboundTransport(_ message: CryptoMessage) -> Bool {
        guard let transportInfo = message.transportInfo,
              let event = try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo)
        else {
            return true
        }

        switch event {
        case .sessionReestablishment,
             .linkedDeviceReprovisioning,
             .synchronizeOneTimeKeys,
             .refreshOneTimeKeys,
             .publishedOneTimeKeysReplenished:
            return true
        }
    }

    func rememberPendingOutboundTransport(
        sharedId: String,
        message: SignedRatchetMessage,
        metadata: SignedRatchetMessageMetadata,
        sessionIdentityId: UUID,
        needsRemoteDeletion: Bool,
        x25519OneTimeKeyId: String?,
        mlKEMOneTimeKeyId: String,
        now: Date = Date()
    ) {
        cleanupPendingOutboundTransport(now: now)
        pendingOutboundTransportBySharedId[sharedId] = PendingOutboundTransport(
            message: message,
            metadata: metadata,
            sessionIdentityId: sessionIdentityId,
            needsRemoteDeletion: needsRemoteDeletion,
            x25519OneTimeKeyId: x25519OneTimeKeyId,
            mlKEMOneTimeKeyId: mlKEMOneTimeKeyId,
            createdAt: now)

        guard pendingOutboundTransportBySharedId.count > pendingOutboundTransportLimit else { return }
        let overflow = pendingOutboundTransportBySharedId.count - pendingOutboundTransportLimit
        let oldestKeys = pendingOutboundTransportBySharedId
            .sorted { $0.value.createdAt < $1.value.createdAt }
            .prefix(overflow)
            .map(\.key)
        for key in oldestKeys {
            pendingOutboundTransportBySharedId.removeValue(forKey: key)
        }
    }

    private func orphanResendServiceKey(requestingDeviceId: UUID, sharedId: String) -> String {
        "\(requestingDeviceId.uuidString)|\(sharedId)"
    }

    private func cleanupOrphanResendTransport(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-orphanResendTransportTTL)
        orphanResendTransportByServiceKey = orphanResendTransportByServiceKey.filter { _, pending in
            pending.createdAt > cutoff
        }
    }

    private func orphanResendTransport(forServiceKey serviceKey: String, now: Date = Date()) -> PendingOutboundTransport? {
        cleanupOrphanResendTransport(now: now)
        return orphanResendTransportByServiceKey[serviceKey]
    }

    func rememberOrphanResendTransport(
        requestingDeviceId: UUID,
        sharedId: String,
        message: SignedRatchetMessage,
        metadata: SignedRatchetMessageMetadata,
        sessionIdentityId: UUID,
        needsRemoteDeletion: Bool,
        x25519OneTimeKeyId: String?,
        mlKEMOneTimeKeyId: String,
        now: Date = Date()
    ) {
        cleanupOrphanResendTransport(now: now)
        let key = orphanResendServiceKey(requestingDeviceId: requestingDeviceId, sharedId: sharedId)
        orphanResendTransportByServiceKey[key] = PendingOutboundTransport(
            message: message,
            metadata: metadata,
            sessionIdentityId: sessionIdentityId,
            needsRemoteDeletion: needsRemoteDeletion,
            x25519OneTimeKeyId: x25519OneTimeKeyId,
            mlKEMOneTimeKeyId: mlKEMOneTimeKeyId,
            createdAt: now)
        guard orphanResendTransportByServiceKey.count > orphanResendTransportLimit else { return }
        let overflow = orphanResendTransportByServiceKey.count - orphanResendTransportLimit
        let oldestKeys = orphanResendTransportByServiceKey
            .sorted { $0.value.createdAt < $1.value.createdAt }
            .prefix(overflow)
            .map(\.key)
        for oldKey in oldestKeys {
            orphanResendTransportByServiceKey.removeValue(forKey: oldKey)
        }
    }

    func sendPreparedOutbound(
        _ prepared: JobModel.PreparedOutbound,
        outboundTask: OutboundTaskMessage,
        session: PQSSession
    ) async throws {
        let metadata = SignedRatchetMessageMetadata(
            secretName: prepared.secretName,
            deviceId: prepared.deviceId,
            recipient: prepared.recipient,
            transportMetadata: prepared.transportMetadata,
            sharedMessageId: prepared.sharedMessageId,
            envelopeMessageId: prepared.envelopeMessageId,
            transportEvent: prepared.transportEvent,
            requiresServerAck: prepared.requiresServerAck)
        let pending = PendingOutboundTransport(
            message: prepared.signedMessage,
            metadata: metadata,
            sessionIdentityId: prepared.sessionIdentityId,
            needsRemoteDeletion: prepared.needsRemoteDeletion,
            x25519OneTimeKeyId: prepared.x25519OneTimeKeyId,
            mlKEMOneTimeKeyId: prepared.mlKEMOneTimeKeyId,
            createdAt: prepared.createdAt)
        try await sendPendingOutboundTransport(
            pending,
            outboundTask: outboundTask,
            session: session)
    }

    func sendPendingOutboundTransport(
        _ pendingTransport: PendingOutboundTransport,
        outboundTask: OutboundTaskMessage,
        session: PQSSession
    ) async throws {
        try await session.transportDelegate?.sendMessage(
            pendingTransport.message,
            metadata: pendingTransport.metadata)
        logRecoveryTransportSendSuccess(
            pendingTransport.metadata.transportEvent,
            sharedId: outboundTask.sharedId)
        await noteResendReplayTransported(sharedId: outboundTask.sharedId)
        await session.recordOutboundDeviceSend(
            sharedId: outboundTask.sharedId,
            recipientSecretName: pendingTransport.metadata.secretName,
            recipientDeviceId: pendingTransport.metadata.deviceId,
            sessionIdentityId: pendingTransport.sessionIdentityId,
            envelopeMessageId: pendingTransport.metadata.envelopeMessageId)
        pendingOutboundTransportBySharedId.removeValue(forKey: outboundTask.sharedId)
        await completeResponderPeerRefreshIfNeeded(
            pendingTransport.metadata.transportEvent,
            peerSecretName: pendingTransport.metadata.secretName,
            peerDeviceId: pendingTransport.metadata.deviceId,
            session: session)

        await rememberRecentOutboundReplayIfNeeded(outboundTask, session: session)

        if outboundTask.isPersistedOutbound || pendingTransport.metadata.requiresServerAck {
            await registerUnackedServerAccept(
                pending: pendingTransport,
                localId: outboundTask.localId,
                sharedId: outboundTask.sharedId,
                isPersistedOutbound: outboundTask.isPersistedOutbound,
                session: session)
        }

        if pendingTransport.needsRemoteDeletion {
            try await removeKeys(
                session: session,
                x25519Id: pendingTransport.x25519OneTimeKeyId,
                mlKEMId: pendingTransport.mlKEMOneTimeKeyId)
        }
    }

    private func cleanupPendingOutboundTransport(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-pendingOutboundTransportTTL)
        pendingOutboundTransportBySharedId = pendingOutboundTransportBySharedId.filter { _, pendingTransport in
            pendingTransport.createdAt > cutoff
        }
    }

    func rememberRecentOutboundReplayIfNeeded(
        _ outboundTask: OutboundTaskMessage,
        session: PQSSession,
        now: Date = Date()
    ) async {
        guard !outboundTask.isPersistedOutbound else { return }
        guard await isReplayableNonPersistentControl(outboundTask.message, session: session) else { return }
        recentOutboundReplayStore.remember(
            outboundTask.message,
            sharedId: outboundTask.sharedId,
            now: now)
    }

    private func hasRecentOutboundReplay(
        sharedId: String,
        now: Date = Date()
    ) -> Bool {
        recentOutboundReplayStore.contains(sharedId: sharedId, now: now)
    }

    private func recentOutboundReplayMessage(
        sharedId: String,
        now: Date = Date()
    ) -> (message: CryptoMessage, replayCount: Int)? {
        recentOutboundReplayStore.consume(sharedId: sharedId, now: now)
    }

    /// Friendship packets must never be replayed from the recovery ring; peers
    /// converge via fresh `friendshipStateRequest` or sibling `synchronizeContacts`.
    private func isFriendshipStateControlMessage(_ message: CryptoMessage) -> Bool {
        (try? BinaryDecoder().decode(FriendshipMetadata.self, from: message.metadata)) != nil
    }

    /// Records that a replay job for a peer's resend request was queued, so its
    /// terminal outcome (transported or dropped) is audited. Without this, a replay
    /// that dies before transport is invisible to both sides.
    /// `servicedFromPersistedStore` controls whether transport hand-off arms the
    /// responder servicing cooldown.
    func rememberResendReplayQueued(
        sharedId: String,
        requesterName: String,
        requesterDeviceId: UUID,
        servicedFromPersistedStore: Bool,
        now: Date = Date()
    ) {
        let cutoff = now.addingTimeInterval(-pendingResendReplayTTL)
        pendingResendReplayBySharedId = pendingResendReplayBySharedId.filter { _, replay in
            replay.queuedAt > cutoff
        }
        if pendingResendReplayBySharedId.count >= pendingResendReplayLimit {
            let overflowKeys = pendingResendReplayBySharedId
                .sorted { $0.value.queuedAt < $1.value.queuedAt }
                .prefix(pendingResendReplayBySharedId.count - pendingResendReplayLimit + 1)
                .map(\.key)
            for key in overflowKeys {
                pendingResendReplayBySharedId.removeValue(forKey: key)
            }
        }
        pendingResendReplayBySharedId[sharedId] = PendingResendReplay(
            requesterName: requesterName,
            requesterDeviceId: requesterDeviceId,
            servicedFromPersistedStore: servicedFromPersistedStore,
            queuedAt: now)
        audit(.recovery, "pqs.recovery.resendReplayQueued sharedId=\(sharedId) requester=\(requesterName) requesterDeviceId=\(requesterDeviceId.uuidString)")
    }

    /// Audits that a tracked resend replay actually reached the transport, and only
    /// then arms the persisted-store servicing cooldown. Arming at queue time let a
    /// replay that died before the wire coalesce the requester's next ask into
    /// silence — request loops with no reply and no audit trail.
    func noteResendReplayTransported(sharedId: String) async {
        guard let replay = pendingResendReplayBySharedId.removeValue(forKey: sharedId) else { return }
        audit(.recovery, "pqs.recovery.resendReplayTransported sharedId=\(sharedId) requester=\(replay.requesterName) requesterDeviceId=\(replay.requesterDeviceId.uuidString)")
        await clearOrphanResendWaveIfDrained(
            requesterName: replay.requesterName,
            requesterDeviceId: replay.requesterDeviceId)
        guard replay.servicedFromPersistedStore, let session else { return }
        await session.markPeerResendRequestServiced(
            requestingDeviceId: replay.requesterDeviceId,
            sharedId: sharedId)
    }

    /// Audits that a tracked resend replay job died before transport. The requester
    /// re-requests after its cooldown (bounded by the transported-attempt cap), so
    /// this is observability, not retry machinery. The servicing cooldown is
    /// intentionally not armed — a dropped replay must not silence the next ask.
    func noteResendReplayDropped(sharedId: String, reason: String) async {
        guard let replay = pendingResendReplayBySharedId.removeValue(forKey: sharedId) else { return }
        audit(.recovery, "pqs.recovery.resendReplayDropped sharedId=\(sharedId) requester=\(replay.requesterName) requesterDeviceId=\(replay.requesterDeviceId.uuidString) reason=\(reason)")
        await clearOrphanResendWaveIfDrained(
            requesterName: replay.requesterName,
            requesterDeviceId: replay.requesterDeviceId)
    }

    func hasPendingResendReplay(requesterName: String, requesterDeviceId: UUID) -> Bool {
        pendingResendReplayBySharedId.values.contains {
            $0.requesterName == requesterName && $0.requesterDeviceId == requesterDeviceId
        }
    }

    /// Serial recovery wave end audit: local replay jobs for this requester drained.
    /// Does **not** clear the orphan initiating mark — mark clears on wipe /
    /// non-orphan reset only, not queue emptiness or generic inbound activate.
    private func clearOrphanResendWaveIfDrained(
        requesterName: String,
        requesterDeviceId: UUID
    ) async {
        guard !hasPendingResendReplay(
            requesterName: requesterName,
            requesterDeviceId: requesterDeviceId
        ) else {
            return
        }
        audit(.recovery, "pqs.recovery.orphanResendWaveDrained requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString)")
    }

    /// Tells the requesting device that these ids have no replay source anywhere so it
    /// stops re-requesting them. Delivered on the requester device's existing active
    /// lane — an unanswerable retry request must never reset session state. An
    /// initiating row is minted only when no active session exists for that device.
    /// Send failures are non-fatal: the requester-side attempt
    /// cap (`PQSSessionConstants.peerResendRequestMaxSubmissions`) still bounds the loop
    /// when the notice is lost.
    private func emitResendUnavailableNotice(
        to fallbackIdentity: SessionIdentity,
        requesterName: String,
        requesterDeviceId: UUID,
        unavailableIds: [String],
        session: PQSSession
    ) async {
        guard !unavailableIds.isEmpty else { return }
        guard let context = await session.sessionContext else { return }
        _ = fallbackIdentity

        // Strict §4.1: unavailable notices are out-of-band — no DR encrypt /
        // surgical lane selection (closes S7 for the response leg).
        do {
            try await session.transportDelegate?.sendOutOfBandResendUnavailable(
                unavailableEnvelopeMessageIds: unavailableIds,
                to: requesterName,
                deviceId: requesterDeviceId,
                respondingDeviceId: context.sessionUser.deviceId)
            logger.log(
                level: .info,
                message: "pqs.recovery.resendUnavailableSentOutOfBand requester=\(requesterName) unavailableCount=\(unavailableIds.count) ids=\(unavailableIds.joined(separator: ","))")
            audit(.recovery, "pqs.recovery.resendUnavailableSentOutOfBand requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) unavailableCount=\(unavailableIds.count) ids=\(unavailableIds.joined(separator: ","))")
            audit(.recovery, "pqs.recovery.resendUnavailableSameAccountNoRemint requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) sessionId=\(fallbackIdentity.id.uuidString) unavailableCount=\(unavailableIds.count)")
        } catch {
            logger.log(
                level: .warning,
                message: "pqs.recovery.resendUnavailableEmitFailed requester=\(requesterName) unavailableCount=\(unavailableIds.count) error=\(error)")
            audit(.recovery, "pqs.recovery.resendUnavailableEmitFailed requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) unavailableCount=\(unavailableIds.count) error=\(error)")
        }
    }

    /// Delivery identity for unavailable NACKs. A retry request we cannot service
    /// must never tear down session state (discard, don't reset): deliver the notice
    /// on the requester device's existing active lane. Mint an initiating row only
    /// when that peer device has no active session at all — with no actives the
    /// reset demotes nothing (`laneReset ... demotedActive=0`). Never stamp a
    /// preferred lane here; general outbound must not be captured by a NACK row.
    private func resolveResendUnavailableDeliveryIdentity(
        fallback: SessionIdentity,
        requesterName: String,
        requesterDeviceId: UUID,
        session: PQSSession
    ) async -> SessionIdentity {
        do {
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            let identities = try await session.cache?.fetchSessionIdentities() ?? []
            let preferredDevice = await currentDeviceConfiguration(
                secretName: requesterName,
                deviceId: requesterDeviceId,
                session: session)
            if let active = await outboundSessionIdentity(
                secretName: requesterName,
                deviceId: requesterDeviceId,
                in: identities,
                symmetricKey: symmetricKey,
                session: session,
                preferredDevice: preferredDevice
            ) {
                audit(.recovery, "pqs.recovery.resendUnavailableUsingActive requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) sessionId=\(active.id.uuidString)")
                return active
            }
            let identity = try await session.resetSessionIdentityForFreshSession(
                secretName: requesterName,
                deviceId: requesterDeviceId,
                sendOneTimeIdentities: false,
                reason: "resendUnavailable")
            audit(.recovery, "pqs.recovery.resendUnavailableInitiating requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) newSessionId=\(identity.id.uuidString)")
            return identity
        } catch {
            logger.log(
                level: .warning,
                message: "pqs.recovery.resendUnavailableInitiatingFailed requester=\(requesterName) deviceId=\(requesterDeviceId) error=\(error)")
            audit(.recovery, "pqs.recovery.resendUnavailableInitiatingFailed requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) error=\(error)")
            return fallback
        }
    }

    private func cleanupRecentUnavailableNotices(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-recentUnavailableNoticeTTL)
        recentUnavailableNoticeByRequesterDevice = recentUnavailableNoticeByRequesterDevice.filter {
            $0.value.createdAt > cutoff
        }
    }

    /// §4.1 sender-side servicing for authenticated OOB retry ingress.
    /// Owns MessageRecord lookup, orphan remint/retransport, and bounded
    /// unavailable notices.
    @discardableResult
    func serviceAuthenticatedResendRequest(
        requesterSecretName: String,
        requesterWireDeviceId: UUID,
        request: ResendRequest,
        session: PQSSession
    ) async throws -> PQSSession.OutOfBandResendResult {
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        var queuedIds: [String] = []
        let identities = try await session.cache?.fetchSessionIdentities() ?? []
        logger.log(
            level: .info,
            message: "pqs.recovery.resendRequestReceived sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) requestingDeviceId=\(request.requestingDeviceId) requestedCount=\(request.failedSharedMessageIds.count) ids=\(request.failedSharedMessageIds.joined(separator: ","))")
        // Production console logs filter info; the audit file must show
        // the request arrived so a silent servicing path is attributable.
        audit(.recovery, "pqs.recovery.resendRequestReceived requester=\(requesterSecretName) requestingDeviceId=\(request.requestingDeviceId.uuidString) ids=\(request.failedSharedMessageIds.joined(separator: ","))")
        let requestedDevice = await currentDeviceConfiguration(
            secretName: requesterSecretName,
            deviceId: request.requestingDeviceId,
            session: session)
        let senderDevice = await currentDeviceConfiguration(
            secretName: requesterSecretName,
            deviceId: requesterWireDeviceId,
            session: session)
        let requestedIdentity = await outboundSessionIdentity(
            secretName: requesterSecretName,
            deviceId: request.requestingDeviceId,
            in: identities,
            symmetricKey: symmetricKey,
            session: session,
            preferredDevice: requestedDevice
        )
        let senderIdentity = await outboundSessionIdentity(
            secretName: requesterSecretName,
            deviceId: requesterWireDeviceId,
            in: identities,
            symmetricKey: symmetricKey,
            session: session,
            preferredDevice: senderDevice
        )
        guard var identity = requestedIdentity ?? senderIdentity else {
            // No outbound lane to the requester yet: still resolve local
            // missing/unavailable without reminting or throwing.
            logger.log(
                level: .warning,
                message: "pqs.recovery.resendReplayFailed reason=missingIdentity sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) requestingDeviceId=\(request.requestingDeviceId) requestedCount=\(request.failedSharedMessageIds.count)")
            var permanentlyUnavailableIds: [String] = []
            let symmetricKeyForLookup = try? await session.getDatabaseSymmetricKey()
            for requestedEnvelopeMessageId in request.failedSharedMessageIds {
                let messageRecord = await session.outboundDeviceSendRecord(
                    envelopeMessageId: requestedEnvelopeMessageId)
                let logicalSharedId = messageRecord?.sharedId ?? requestedEnvelopeMessageId
                if await session.isKnownUnavailableResend(
                    requestingDeviceId: request.requestingDeviceId,
                    sharedId: requestedEnvelopeMessageId)
                {
                    permanentlyUnavailableIds.append(requestedEnvelopeMessageId)
                    continue
                }
                if recentOutboundReplayMessage(sharedId: logicalSharedId) != nil {
                    continue
                }
                let foundMessage: EncryptedMessage?
                do {
                    foundMessage = try await session.cache?.fetchMessageIfExists(
                        sharedId: logicalSharedId)
                } catch {
                    foundMessage = nil
                }
                var readable = false
                if let foundMessage, let symmetricKeyForLookup {
                    readable = await foundMessage.props(symmetricKey: symmetricKeyForLookup)?.message != nil
                }
                if !readable {
                    permanentlyUnavailableIds.append(requestedEnvelopeMessageId)
                    await session.markResendUnavailable(
                        requestingDeviceId: request.requestingDeviceId,
                        sharedId: requestedEnvelopeMessageId)
                }
            }
            return PQSSession.OutOfBandResendResult(
                queuedIds: [],
                permanentlyUnavailableIds: permanentlyUnavailableIds)
        }

        var replayQueuedCount = 0
        var replayMissingCount = 0
        var replayCoalescedCount = 0
        var unavailableIds: [String] = []
        var knownUnavailableCount = 0
        var missingByReason: [String: Int] = [:]
        var pendingOrphanEncrypts: [(
            sharedId: String,
            requestedEnvelopeMessageId: String,
            message: CryptoMessage,
            identity: SessionIdentity,
            retransportCached: Bool
        )] = []
        let localSecretName = await session.sessionContext?.sessionUser.secretName
        let isSameAccountRequester =
            localSecretName == requesterSecretName
        // Process escape-remint candidates first so a settled prove-fail
        // remints before sibling reuseRecoveryWave advances the old row.
        // Classify only — remint still happens in the per-id switch.
        var orderedFailedSharedMessageIds = request.failedSharedMessageIds
        if let recoveryForOrder = await session.orphanResendRecoverySessionId(
            secretName: requesterSecretName,
            deviceId: request.requestingDeviceId)
        {
            var escapeFirst: [String] = []
            var remainder: [String] = []
            for candidateId in request.failedSharedMessageIds {
                let candidateRecord = await session.outboundDeviceSendRecord(
                    envelopeMessageId: candidateId)
                let candidateLogicalId = candidateRecord?.sharedId ?? candidateId
                let candidateKey = orphanResendServiceKey(
                    requestingDeviceId: request.requestingDeviceId,
                    sharedId: candidateLogicalId)
                if OrphanResendRemintPolicy.needsEscapeRemintAfterRetransportProveFail(
                    messageRecordSessionId: candidateRecord?.sessionIdentityId,
                    recoverySessionId: recoveryForOrder,
                    priorRetransportCount:
                        orphanResendRetransportCountByServiceKey[candidateKey] ?? 0,
                    remintsAfterRetransportProveFail:
                        orphanResendRemintsAfterProveFailByServiceKey[candidateKey] ?? 0)
                {
                    escapeFirst.append(candidateId)
                } else {
                    remainder.append(candidateId)
                }
            }
            orderedFailedSharedMessageIds = escapeFirst + remainder
        }
        for failedEnvelopeMessageId in orderedFailedSharedMessageIds {
            // Strict §4.1 retry requests identify the failed encrypted
            // envelope. Resolve its MessageRecord before looking up plaintext,
            // whose durable content key remains the logical shared id.
            let requestedMessageRecord = await session.outboundDeviceSendRecord(
                envelopeMessageId: failedEnvelopeMessageId)
            let failedSharedMessageId =
                requestedMessageRecord?.sharedId ?? failedEnvelopeMessageId
            // A previous lookup already proved this id unreplayable; skip the
            // DB pass and just re-notify the requester below.
            if await session.isKnownUnavailableResend(
                requestingDeviceId: request.requestingDeviceId,
                sharedId: failedEnvelopeMessageId
            ) {
                unavailableIds.append(failedEnvelopeMessageId)
                knownUnavailableCount += 1
                continue
            }

            let cryptoMessage: CryptoMessage
            // Recent non-persistent recovery controls are intentionally replayable
            // multiple times while a peer repairs; they are already bounded by
            // `recentOutboundReplayMaxReplays`, so they bypass the servicing cooldown.
            var servicedFromPersistedStore = false
            let hasRecentReplay =
                hasRecentOutboundReplay(sharedId: failedSharedMessageId)
            if let replay = recentOutboundReplayMessage(sharedId: failedSharedMessageId) {
                cryptoMessage = replay.message
                logger.log(
                    level: .info,
                    message: "pqs.recovery.resendReplayUsingRecentControl sharedId=\(failedSharedMessageId) replayCount=\(replay.replayCount)")
            } else {
                let hasMessageRecord = requestedMessageRecord != nil
                // Persisted-message replays are otherwise unbounded: a peer stuck in a
                // decrypt-failure loop could force us to re-ratchet and re-consume OTKs
                // for the same message on every request. Coalesce repeats per requester.
                guard await session.canServicePeerResendRequest(
                    requestingDeviceId: request.requestingDeviceId,
                    sharedId: failedEnvelopeMessageId)
                else {
                    replayCoalescedCount += 1
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendReplayCoalesced reason=servicingCooldown sharedId=\(failedSharedMessageId) requestingDeviceId=\(request.requestingDeviceId)")
                    continue
                }

                let foundMessage: EncryptedMessage?
                do {
                    foundMessage = try await session.cache?.fetchMessageIfExists(sharedId: failedSharedMessageId)
                } catch {
                    replayMissingCount += 1
                    unavailableIds.append(failedEnvelopeMessageId)
                    missingByReason["messageLookupFailed", default: 0] += 1
                    await session.markResendUnavailable(
                        requestingDeviceId: request.requestingDeviceId,
                        sharedId: failedEnvelopeMessageId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendReplaySkipped reason=messageLookupFailed sharedId=\(failedSharedMessageId) error=\(error)")
                    continue
                }
                let ownership = OrphanResendOwnershipPolicy.decision(
                    isSameAccount: isSameAccountRequester,
                    hasRecentOutboundReplay: hasRecentReplay,
                    hasLocalMessage: foundMessage != nil,
                    hasOutboundDeviceSendRecord: hasMessageRecord)
                if ownership == .deferNotContentOwner {
                    audit(.recovery, "pqs.recovery.orphanResendDeferredNotContentOwner sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString)")
                    continue
                }
                guard let foundMessage else {
                    // MessageRecord owner without plaintext: consult remint
                    // counters (cross- or same-account). Dogfood: gating on
                    // isSameAccount skipped escape remint → missingLocalMessage.
                    if hasMessageRecord {
                        let serviceKey = orphanResendServiceKey(
                            requestingDeviceId: request.requestingDeviceId,
                            sharedId: failedSharedMessageId)
                        let messageRecord = await session.outboundDeviceSendRecord(
                            envelopeMessageId: failedEnvelopeMessageId)
                        let recoverySessionId = await session.orphanResendRecoverySessionId(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId)
                        let priorRetransportCount =
                            orphanResendRetransportCountByServiceKey[serviceKey] ?? 0
                        let remintsAfterProveFail =
                            orphanResendRemintsAfterProveFailByServiceKey[serviceKey] ?? 0
                        let ownerDecision = OrphanResendRemintPolicy.decision(
                            messageRecordSessionId: messageRecord?.sessionIdentityId,
                            recoverySessionId: recoverySessionId,
                            initiatingMarkSessionId: nil,
                            markIsStateLess: false,
                            priorRetransportCount: priorRetransportCount,
                            remintsAfterRetransportProveFail: remintsAfterProveFail)
                        if ownerDecision == .retransportAlreadyServiced,
                           orphanResendTransport(forServiceKey: serviceKey) != nil,
                           let recoverySessionId,
                           let recovered = ((try? await session.cache?.fetchSessionIdentities())
                            ?? identities).first(where: { $0.id == recoverySessionId })
                        {
                            orphanResendRetransportCountByServiceKey[serviceKey] =
                                priorRetransportCount + 1
                            rememberResendReplayQueued(
                                sharedId: failedSharedMessageId,
                                requesterName: requesterSecretName,
                                requesterDeviceId: request.requestingDeviceId,
                                servicedFromPersistedStore: false)
                            pendingOrphanEncrypts.append((
                                sharedId: failedSharedMessageId,
                                requestedEnvelopeMessageId: failedEnvelopeMessageId,
                                message: CryptoMessage(
                                    text: "",
                                    metadata: .init(),
                                    recipient: .personalMessage,
                                    sentDate: Date(),
                                    destructionTime: nil),
                                identity: recovered,
                                retransportCached: true
                            ))
                            audit(.recovery, "pqs.recovery.orphanResendRetransport sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) sessionId=\(recoverySessionId.uuidString)")
                            continue
                        }
                        if ownerDecision == .mintFreshAfterRetransportProveFailed {
                            // Remint lane for later siblings; this id stays
                            // unavailable without plaintext to re-encrypt.
                            do {
                                identity = try await performOrphanEscapeRemint(
                                    serviceKey: serviceKey,
                                    remintsAfterProveFail: remintsAfterProveFail,
                                    priorRecordSessionId: messageRecord?.sessionIdentityId,
                                    secretName: requesterSecretName,
                                    deviceId: request.requestingDeviceId,
                                    sharedId: failedSharedMessageId,
                                    session: session)
                            } catch {
                                logger.log(
                                    level: .warning,
                                    message: "pqs.recovery.orphanResendFailed sharedId=\(failedSharedMessageId) error=\(error)")
                            }
                        } else if ownerDecision == .exhaustedUnrecoverable {
                            audit(.recovery, "pqs.recovery.orphanResendHealExhausted sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString)")
                            replayMissingCount += 1
                            unavailableIds.append(failedEnvelopeMessageId)
                            missingByReason["healExhausted", default: 0] += 1
                            await session.markResendUnavailable(
                                requestingDeviceId: request.requestingDeviceId,
                                sharedId: failedEnvelopeMessageId)
                            continue
                        }
                        audit(.recovery, "pqs.recovery.orphanResendOwnerMissingPlaintext sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString)")
                        replayMissingCount += 1
                        unavailableIds.append(failedEnvelopeMessageId)
                        missingByReason["ownerMissingPlaintext", default: 0] += 1
                        await session.markResendUnavailable(
                            requestingDeviceId: request.requestingDeviceId,
                            sharedId: failedEnvelopeMessageId)
                        continue
                    }
                    replayMissingCount += 1
                    unavailableIds.append(failedEnvelopeMessageId)
                    missingByReason["missingLocalMessage", default: 0] += 1
                    await session.markResendUnavailable(
                        requestingDeviceId: request.requestingDeviceId,
                        sharedId: failedEnvelopeMessageId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendReplaySkipped reason=missingLocalMessage sharedId=\(failedSharedMessageId)")
                    continue
                }

                guard let fetchedCryptoMessage = await foundMessage.props(symmetricKey: symmetricKey)?.message else {
                    replayMissingCount += 1
                    unavailableIds.append(failedEnvelopeMessageId)
                    missingByReason["unreadableLocalMessage", default: 0] += 1
                    await session.markResendUnavailable(
                        requestingDeviceId: request.requestingDeviceId,
                        sharedId: failedEnvelopeMessageId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendReplaySkipped reason=unreadableLocalMessage sharedId=\(failedSharedMessageId)")
                    continue
                }
                cryptoMessage = fetchedCryptoMessage
                servicedFromPersistedStore = true
            }

            // Orphan-resend: first mint for a sharedId must be initiating
            // (msg0). After MessageRecord names the recovery SessionID,
            // rearmNack retransports that ciphertext — do not remint
            // (dogfood C3 / 2FA48892 triple newSessionId thrash).
            var replayIdentity = identity
            var retransportCached = false
            let messageRecord = await session.outboundDeviceSendRecord(
                envelopeMessageId: failedEnvelopeMessageId)
            let recoverySessionId = await session.orphanResendRecoverySessionId(
                secretName: requesterSecretName,
                deviceId: request.requestingDeviceId)
            let protectedId = await session.orphanResendInitiatingSessionId(
                secretName: requesterSecretName,
                deviceId: request.requestingDeviceId)
            var markIsStateLess = false
            var protectedIdentity: SessionIdentity?
            if let protectedId {
                let latestIdentities =
                    (try? await session.cache?.fetchSessionIdentities()) ?? identities
                if let protected = latestIdentities.first(where: { $0.id == protectedId }),
                   let protectedProps = await protected.props(symmetricKey: symmetricKey),
                   protectedProps.secretName == requesterSecretName,
                   protectedProps.deviceId == request.requestingDeviceId,
                   !protectedProps.deviceName.hasPrefix(
                    PQSSessionConstants.inactiveSessionDeviceNamePrefix)
                {
                    markIsStateLess = !protectedProps.hasRatchetState
                    if markIsStateLess {
                        protectedIdentity = protected
                    }
                }
            }

            let serviceKeyForPolicy = orphanResendServiceKey(
                requestingDeviceId: request.requestingDeviceId,
                sharedId: failedSharedMessageId)
            let priorRetransportCount =
                orphanResendRetransportCountByServiceKey[serviceKeyForPolicy] ?? 0
            let remintsAfterProveFail =
                orphanResendRemintsAfterProveFailByServiceKey[serviceKeyForPolicy] ?? 0
            var recoverySessionIsLiveActive = false
            var recoveryLiveIdentity: SessionIdentity?
            if let recoverySessionId {
                let latestIdentities =
                    (try? await session.cache?.fetchSessionIdentities()) ?? identities
                if let recovered = latestIdentities.first(where: { $0.id == recoverySessionId }),
                   let recoveredProps = await recovered.props(symmetricKey: symmetricKey),
                   recoveredProps.secretName == requesterSecretName,
                   recoveredProps.deviceId == request.requestingDeviceId,
                   !recoveredProps.deviceName.hasPrefix(
                    PQSSessionConstants.inactiveSessionDeviceNamePrefix)
                {
                    recoverySessionIsLiveActive = true
                    recoveryLiveIdentity = recovered
                }
            }
            let remintDecision = OrphanResendRemintPolicy.decision(
                messageRecordSessionId: messageRecord?.sessionIdentityId,
                recoverySessionId: recoverySessionId,
                initiatingMarkSessionId: protectedId,
                markIsStateLess: markIsStateLess,
                recoverySessionIsLiveActive: recoverySessionIsLiveActive,
                priorRetransportCount: priorRetransportCount,
                remintsAfterRetransportProveFail: remintsAfterProveFail)

            switch remintDecision {
            case .retransportAlreadyServiced:
                let serviceKey = serviceKeyForPolicy
                if orphanResendTransport(forServiceKey: serviceKey) != nil {
                    retransportCached = true
                    if let recoverySessionId,
                       let recovered = ((try? await session.cache?.fetchSessionIdentities())
                        ?? identities).first(where: { $0.id == recoverySessionId })
                    {
                        replayIdentity = recovered
                    }
                    orphanResendRetransportCountByServiceKey[serviceKey] =
                        priorRetransportCount + 1
                    audit(.recovery, "pqs.recovery.orphanResendRetransport sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) sessionId=\(recoverySessionId?.uuidString ?? "nil")")
                } else {
                    // Process restart / cache eviction: mint once more.
                    audit(.recovery, "pqs.recovery.orphanResendRetransportCacheMiss sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString)")
                    do {
                        let priorRecordSessionId = messageRecord?.sessionIdentityId
                        replayIdentity = try await session.resetSessionIdentityForFreshSession(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            sendOneTimeIdentities: true,
                            reason: "orphanResend")
                        await session.markOrphanResendInitiatingSession(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            sessionId: replayIdentity.id)
                        identity = replayIdentity
                        clearPreferredSessionIdentity(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId)
                        await demotePriorOrphanMessageRecordSession(
                            priorSessionId: priorRecordSessionId,
                            newSessionId: replayIdentity.id,
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            session: session)
                        audit(.recovery, "pqs.recovery.orphanResend sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) newSessionId=\(replayIdentity.id.uuidString)")
                    } catch {
                        logger.log(
                            level: .warning,
                            message: "pqs.recovery.orphanResendFailed sharedId=\(failedSharedMessageId) error=\(error)")
                    }
                }

            case .mintFreshAfterRetransportProveFailed:
                // Escape blankForHeaderExists trap: new OTK header on settled
                // recovery NACK (identical-CT retransport cannot rearm). Cap per serviceKey (P3).
                do {
                    replayIdentity = try await performOrphanEscapeRemint(
                        serviceKey: serviceKeyForPolicy,
                        remintsAfterProveFail: remintsAfterProveFail,
                        priorRecordSessionId: messageRecord?.sessionIdentityId,
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId,
                        sharedId: failedSharedMessageId,
                        session: session)
                    identity = replayIdentity
                } catch {
                    logger.log(
                        level: .warning,
                        message: "pqs.recovery.orphanResendFailed sharedId=\(failedSharedMessageId) error=\(error)")
                }

            case .reuseStateLessMark:
                if let protected = protectedIdentity {
                    replayIdentity = protected
                    identity = protected
                    clearPreferredSessionIdentity(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.orphanResendReused sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId) sessionId=\(protected.id)")
                    audit(.recovery, "pqs.recovery.orphanResendReused sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) sessionId=\(protected.id.uuidString)")
                } else if let protectedId {
                    await session.clearOrphanResendInitiatingSession(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    audit(.recovery, "pqs.recovery.orphanResendStickyAdvancedRemint sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) priorSessionId=\(protectedId.uuidString)")
                }

            case .reuseRecoveryWave:
                // Continue the same recovery ratchet for unrecovered
                // sharedIds (msg1+). Do not mint a competing blank.
                if let recovered = recoveryLiveIdentity {
                    replayIdentity = recovered
                    identity = recovered
                    clearPreferredSessionIdentity(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    audit(.recovery, "pqs.recovery.orphanResendReused sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) sessionId=\(recovered.id.uuidString) reason=reuseRecoveryWave")
                }

            case .exhaustedUnrecoverable:
                // Heal sequence done (retransport → remint → retransport
                // prove-fail). Terminal unavailable — no further remint
                // or retransport; keep recovery lane for other sharedIds.
                audit(.recovery, "pqs.recovery.orphanResendHealExhausted sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString)")
                replayMissingCount += 1
                unavailableIds.append(failedEnvelopeMessageId)
                missingByReason["healExhausted", default: 0] += 1
                await session.markResendUnavailable(
                    requestingDeviceId: request.requestingDeviceId,
                    sharedId: failedEnvelopeMessageId)
                continue

            case .mintFresh:
                if let protectedId, !markIsStateLess {
                    await session.clearOrphanResendInitiatingSession(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    if protectedId != replayIdentity.id {
                        audit(.recovery, "pqs.recovery.orphanResendStickyAdvancedRemint sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) priorSessionId=\(protectedId.uuidString)")
                    }
                }
                let replayProps = await replayIdentity.props(symmetricKey: symmetricKey)
                if replayProps?.hasRatchetState != true,
                   let record = messageRecord,
                   record.sessionIdentityId == replayIdentity.id
                {
                    await session.markOrphanResendInitiatingSession(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId,
                        sessionId: replayIdentity.id)
                    clearPreferredSessionIdentity(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.orphanResendRearmed sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId) sessionId=\(replayIdentity.id) reason=stateLess")
                    audit(.recovery, "pqs.recovery.orphanResendRearmed sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) sessionId=\(replayIdentity.id.uuidString) reason=stateLess")
                } else {
                    do {
                        let priorRecordSessionId = messageRecord?.sessionIdentityId
                        replayIdentity = try await session.resetSessionIdentityForFreshSession(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            sendOneTimeIdentities: true,
                            reason: "orphanResend")
                        await session.markOrphanResendInitiatingSession(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            sessionId: replayIdentity.id)
                        identity = replayIdentity
                        clearPreferredSessionIdentity(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId)
                        await demotePriorOrphanMessageRecordSession(
                            priorSessionId: priorRecordSessionId,
                            newSessionId: replayIdentity.id,
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            session: session)
                        logger.log(
                            level: .info,
                            message: "pqs.recovery.orphanResend sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId) newSessionId=\(replayIdentity.id)")
                        audit(.recovery, "pqs.recovery.orphanResend sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) newSessionId=\(replayIdentity.id.uuidString)")
                    } catch {
                        logger.log(
                            level: .warning,
                            message: "pqs.recovery.orphanResendFailed sharedId=\(failedSharedMessageId) error=\(error)")
                    }
                }
            }

            // Track pending for the whole wave before any encrypt so
            // MessageRecord/ledger updates and wave-drain stay serial
            // within this mailbox item (no interleaved inbound jobs).
            rememberResendReplayQueued(
                sharedId: failedSharedMessageId,
                requesterName: requesterSecretName,
                requesterDeviceId: request.requestingDeviceId,
                servicedFromPersistedStore: servicedFromPersistedStore)
            pendingOrphanEncrypts.append((
                sharedId: failedSharedMessageId,
                requestedEnvelopeMessageId: failedEnvelopeMessageId,
                message: cryptoMessage,
                identity: replayIdentity,
                retransportCached: retransportCached
            ))
        }

        // Serial recovery mailbox: encrypt+send each orphan replay inline.
        // One recovery ratchet per peer-device wave — continue msg1+ when
        // an earlier sharedId already advanced the row (no PerSharedId remint).
        for pending in pendingOrphanEncrypts {
            let serviceKey = orphanResendServiceKey(
                requestingDeviceId: request.requestingDeviceId,
                sharedId: pending.sharedId)
            do {
                if pending.retransportCached,
                   let cached = orphanResendTransport(forServiceKey: serviceKey)
                {
                    try await session.transportDelegate?.sendMessage(
                        cached.message,
                        metadata: cached.metadata)
                    await noteResendReplayTransported(sharedId: pending.sharedId)
                    audit(.recovery, "pqs.recovery.orphanResendRetransport sharedId=\(pending.sharedId) sessionId=\(pending.identity.id.uuidString) requesterDeviceId=\(request.requestingDeviceId.uuidString)")
                    replayQueuedCount += 1
                    queuedIds.append(pending.requestedEnvelopeMessageId)
                    continue
                }

                // Mid-wave: if MessageRecord already settled on recovery for
                // this sharedId and we have cached ciphertext, retransport.
                let encryptIdentity = pending.identity
                let encryptProps = await encryptIdentity.props(symmetricKey: symmetricKey)
                if encryptProps?.hasRatchetState == true {
                    let record = await session.outboundDeviceSendRecord(
                        sharedId: pending.sharedId,
                        recipientDeviceId: request.requestingDeviceId)
                    let recoveryId = await session.orphanResendRecoverySessionId(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    let midWave = OrphanResendRemintPolicy.decision(
                        messageRecordSessionId: record?.sessionIdentityId,
                        recoverySessionId: recoveryId,
                        initiatingMarkSessionId: encryptIdentity.id,
                        markIsStateLess: false,
                        recoverySessionIsLiveActive: true)
                    if midWave == .retransportAlreadyServiced,
                       let cached = orphanResendTransport(forServiceKey: serviceKey)
                    {
                        try await session.transportDelegate?.sendMessage(
                            cached.message,
                            metadata: cached.metadata)
                        await noteResendReplayTransported(sharedId: pending.sharedId)
                        audit(.recovery, "pqs.recovery.orphanResendRetransport sharedId=\(pending.sharedId) sessionId=\(encryptIdentity.id.uuidString) requesterDeviceId=\(request.requestingDeviceId.uuidString)")
                        replayQueuedCount += 1
                        queuedIds.append(pending.requestedEnvelopeMessageId)
                        continue
                    }
                    // Else continue encrypt on the same recovery identity.
                }
                try await handleWriteMessage(
                    outboundTask: OutboundTaskMessage(
                        message: pending.message,
                        recipientIdentity: encryptIdentity,
                        localId: UUID(),
                        sharedId: pending.sharedId,
                        isPersistedOutbound: false
                    ),
                    session: session)
                audit(.recovery, "pqs.recovery.orphanResendMessageRecordUpdated sharedId=\(pending.sharedId) sessionId=\(encryptIdentity.id.uuidString) requesterDeviceId=\(request.requestingDeviceId.uuidString)")
                replayQueuedCount += 1
                queuedIds.append(pending.requestedEnvelopeMessageId)
            } catch {
                logger.log(
                    level: .warning,
                    message: "pqs.recovery.orphanResendEncryptFailed sharedId=\(pending.sharedId) error=\(error)")
                await noteResendReplayDropped(
                    sharedId: pending.sharedId,
                    reason: "orphanResendEncryptFailed")
            }
        }
        if replayQueuedCount > 0 {
            logger.log(
                level: .info,
                message: "pqs.recovery.resendReplayQueued sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) queuedCount=\(replayQueuedCount) skippedCount=\(replayMissingCount) coalescedCount=\(replayCoalescedCount) requestedCount=\(request.failedSharedMessageIds.count)")
        } else if replayCoalescedCount > 0 {
            logger.log(
                level: .info,
                message: "pqs.recovery.resendReplayCoalescedAll sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) coalescedCount=\(replayCoalescedCount) skippedCount=\(replayMissingCount) requestedCount=\(request.failedSharedMessageIds.count)")
            // Fully coalesced servicing sends nothing back; without this
            // audit the requester's retries look unanswered for no reason.
            audit(.recovery, "pqs.recovery.resendReplayCoalescedAll requester=\(requesterSecretName) requestingDeviceId=\(request.requestingDeviceId.uuidString) coalescedCount=\(replayCoalescedCount) requestedCount=\(request.failedSharedMessageIds.count)")
        } else if replayMissingCount == 0, knownUnavailableCount > 0 {
            // Every requested id was already proven unreplayable in a
            // previous pass: re-send the notice below without re-running
            // lookups or re-auditing a full resendReplayFailed.
            logger.log(
                level: .info,
                message: "pqs.recovery.resendReplayShortCircuited reason=knownUnavailable sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) knownUnavailableCount=\(knownUnavailableCount) requestedCount=\(request.failedSharedMessageIds.count)")
        } else {
            // Terminal for the requested content: we have nothing to
            // replay. The messageResendUnavailable notice below tells the
            // requester to stop asking. Content the sender never persisted
            // is unrecoverable by design — the requester's lane still
            // heals via peerRefresh and *new* messages flow; only the
            // original frames stay lost. Audit which ids hit this so
            // production logs show whether they were ephemeral/control
            // frames (expected) or persisted chat (a replay-lookup bug).
            let reasonsSummary = missingByReason
                .sorted { $0.key < $1.key }
                .map { "\($0.key):\($0.value)" }
                .joined(separator: ",")
            logger.log(
                level: .warning,
                message: "pqs.recovery.resendReplayFailed reason=noReplayableMessages sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) skippedCount=\(replayMissingCount) requestedCount=\(request.failedSharedMessageIds.count) reasons=\(reasonsSummary)")
            audit(.recovery, "pqs.recovery.resendReplayFailed reason=noReplayableMessages requester=\(requesterSecretName) requesterDeviceId=\(requesterWireDeviceId.uuidString) requestedCount=\(request.failedSharedMessageIds.count) reasons=\(reasonsSummary) sharedIds=\(request.failedSharedMessageIds.joined(separator: ","))")
        }

        await emitResendUnavailableNotice(
            to: identity,
            requesterName: requesterSecretName,
            requesterDeviceId: request.requestingDeviceId,
            unavailableIds: unavailableIds,
            session: session)
        // Local honesty: if we told the peer these ids are gone, any
        // matching outbound rows on this device must not keep a
        // delivered/read glyph.
        if let sessionDelegate = await session.sessionDelegate {
            for envelopeMessageId in unavailableIds {
                let sharedId =
                    await session.outboundDeviceSendRecord(
                        envelopeMessageId: envelopeMessageId)?.sharedId
                    ?? envelopeMessageId
                await sessionDelegate.outboundMessageUnrecoverable(
                    sharedMessageId: sharedId,
                    reason: "noReplay")
            }
        }

        return PQSSession.OutOfBandResendResult(
            queuedIds: queuedIds,
            permanentlyUnavailableIds: unavailableIds)
    }

    func handleOutOfBandResendRequest(
        from senderName: String,
        deviceId senderDeviceId: UUID,
        failedSharedMessageIds: [String],
        session: PQSSession
    ) async throws -> PQSSession.OutOfBandResendResult {
        let requestedIds = failedSharedMessageIds
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !requestedIds.isEmpty else {
            return PQSSession.OutOfBandResendResult(queuedIds: [], permanentlyUnavailableIds: [])
        }
        let request = ResendRequest(
            failedSharedMessageIds: requestedIds,
            requestingDeviceId: senderDeviceId)
        return try await serviceAuthenticatedResendRequest(
            requesterSecretName: senderName,
            requesterWireDeviceId: senderDeviceId,
            request: request,
            session: session)
    }

    private func isReplayableNonPersistentControl(
        _ message: CryptoMessage,
        session: PQSSession
    ) async -> Bool {
        guard let transportInfo = message.transportInfo,
              let event = try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo)
        else {
            return await session.sessionDelegate?
                .shouldReplayNonPersistentOutbound(transportInfo: message.transportInfo) == true
        }

        switch event {
        case .sessionReestablishment(let envelope):
            return envelope.isResponse
        case .linkedDeviceReprovisioning:
            return true
        case .synchronizeOneTimeKeys,
             .refreshOneTimeKeys,
             .publishedOneTimeKeysReplenished:
            return false
        }
    }

    func removeKeys(session: PQSSession, x25519Id: String?, mlKEMId: String) async throws {
        
        guard let cache = await session.cache else { return }
        let data = try await cache.fetchLocalSessionContext()
        
        // Decrypt the session context data using the app's symmetric key
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: session.getAppSymmetricKey()) else {
            return
        }
        
        // Decode the session context from the decrypted data
        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)
        
        if let x25519Id {
            try await delegate?.deleteOneTimeKeys(for: sessionContext.sessionUser.secretName, with: x25519Id, type: .x25519)
        }
        try await delegate?.deleteOneTimeKeys(for: sessionContext.sessionUser.secretName, with: mlKEMId, type: .mlKEM)
        logger.log(level: .info, message: "Requested to Remove Remote Public Curve and MLKEM One Time Keys")
        
        sessionContext.activeUserConfiguration.signedOneTimePublicKeys.removeAll(where: { $0.id.uuidString == x25519Id })
        sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.removeAll(where: { $0.id.uuidString == mlKEMId })
        sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.removeAll(where: { $0.id.uuidString == x25519Id })
        sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.removeAll(where: { $0.id.uuidString == mlKEMId })
        
        await session.setSessionContext(sessionContext)
        
        let encodedData = try BinaryEncoder().encode(sessionContext)
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: session.getAppSymmetricKey()) else {
            throw PQSError.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encryptedConfig)
        logger.log(level: .info, message: "Removed Local Curve and MLKEM One Time Keys")
    }

    /// Drains deferred NACK entries for idle-sender / episode-end paths.
    /// Shared by peerRefresh-response drains and `PQSSession.flushPendingResends`.
    func drainDeferredResendRequests(
        _ pendingRequests: [PQSSession.PendingResendAfterReestablishment],
        session: PQSSession,
        reason: String
    ) async {
        await sendDeferredResendRequests(pendingRequests, session: session, reason: reason)
    }

    func sendDeferredResendRequests(
        _ pendingRequests: [PQSSession.PendingResendAfterReestablishment],
        session: PQSSession,
        reason: String
    ) async {
        guard !pendingRequests.isEmpty else { return }

        struct ResendGroupKey: Hashable {
            let senderName: String
            let senderDeviceId: UUID
        }

        let grouped = Dictionary(grouping: pendingRequests) {
            ResendGroupKey(senderName: $0.senderName, senderDeviceId: $0.senderDeviceId)
        }

        for (key, groupedRequests) in grouped {
            var ready: [PQSSession.PendingResendAfterReestablishment] = []
            for pending in groupedRequests {
                // Terminal cap: if the peer's unavailable notice never arrived, stop
                // after a bounded number of submissions instead of looping until the
                // pending TTL. Dropped ids are not re-deferred.
                let attempts = await session.resendRequestSubmissionCount(
                    sender: pending.senderName,
                    deviceId: pending.senderDeviceId,
                    failedMessageId: pending.failedSharedMessageId)
                if attempts >= PQSSessionConstants.peerResendRequestMaxSubmissions {
                    logger.log(
                        level: .warning,
                        message: "pqs.recovery.pendingResendExhausted sharedId=\(pending.failedSharedMessageId) sender=\(pending.senderName) deviceId=\(pending.senderDeviceId) failureClass=\(pending.failureClass) attempts=\(attempts)")
                    audit(.recovery, "pqs.recovery.pendingResendExhausted sharedId=\(pending.failedSharedMessageId) sender=\(pending.senderName) deviceId=\(pending.senderDeviceId.uuidString) failureClass=\(pending.failureClass) attempts=\(attempts)")
                    // Terminal on the requester: stop asking and quarantine so poison
                    // redelivery cannot reopen recovery for this sharedId.
                    await session.clearPendingResends(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        messageIds: [pending.failedSharedMessageId])
                    let newlyTerminal = await session.markInboundContentUnrecoverable(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        sharedId: pending.failedSharedMessageId)
                    if newlyTerminal {
                        audit(.recovery, "pqs.recovery.contentUnrecoverable sharedId=\(pending.failedSharedMessageId) sender=\(pending.senderName) deviceId=\(pending.senderDeviceId.uuidString) reason=resendSubmissionCap attempts=\(attempts)")
                        await session.sessionDelegate?.inboundContentUnrecoverable(
                            senderSecretName: pending.senderName,
                            senderDeviceId: pending.senderDeviceId,
                            sharedMessageId: pending.failedSharedMessageId)
                    }
                    continue
                }

                guard await session.canSendPeerResendRequest(
                    sender: pending.senderName,
                    deviceId: pending.senderDeviceId,
                    failedMessageId: pending.failedSharedMessageId
                ) else {
                    await session.deferPeerResendUntilReestablished(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        failedMessageId: pending.failedSharedMessageId,
                        failureClass: pending.failureClass)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendDeferredStillWaiting reason=cooldown sharedId=\(pending.failedSharedMessageId) sender=\(pending.senderName) deviceId=\(pending.senderDeviceId) failureClass=\(pending.failureClass)")
                    continue
                }
                ready.append(pending)
            }

            guard !ready.isEmpty else { continue }

            do {
                let sharedIds = ready.map(\.failedSharedMessageId)
                logger.log(
                    level: .info,
                    message: "pqs.recovery.resendDrainStarted reason=\(reason) count=\(sharedIds.count) sender=\(key.senderName) deviceId=\(key.senderDeviceId) ids=\(sharedIds.joined(separator: ","))")
                for pending in ready {
                    await session.deferPeerResendUntilReestablished(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        failedMessageId: pending.failedSharedMessageId,
                        failureClass: pending.failureClass,
                        notifyDelegate: false)
                }
                try await session.requestMessageResend(
                    sharedMessageIds: sharedIds,
                    senderName: key.senderName,
                    senderDeviceId: key.senderDeviceId)
                for pending in ready {
                    await session.markPeerResendRequestSent(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        failedMessageId: pending.failedSharedMessageId)
                    await session.markInboundFailure(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        messageId: pending.failedSharedMessageId,
                        failureClass: pending.failureClass)
                }
                logger.log(
                    level: .info,
                    message: "pqs.recovery.resendDrainSubmitted reason=\(reason) count=\(sharedIds.count) sender=\(key.senderName) deviceId=\(key.senderDeviceId) ids=\(sharedIds.joined(separator: ","))")
                audit(.recovery, "pqs.recovery.resendDrainSubmitted reason=\(reason) count=\(sharedIds.count) sender=\(key.senderName) deviceId=\(key.senderDeviceId.uuidString) ids=\(sharedIds.joined(separator: ","))")
            } catch {
                for pending in ready {
                    await session.deferPeerResendUntilReestablished(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        failedMessageId: pending.failedSharedMessageId,
                        failureClass: pending.failureClass)
                }
                logger.log(
                    level: .warning,
                    message: "pqs.recovery.resendDrainFailed reason=\(reason) count=\(ready.count) sender=\(key.senderName) deviceId=\(key.senderDeviceId) error=\(error)")
                audit(.recovery, "pqs.recovery.resendDrainFailed reason=\(reason) count=\(ready.count) sender=\(key.senderName) deviceId=\(key.senderDeviceId.uuidString) error=\(error)")
            }
        }
    }
    
}

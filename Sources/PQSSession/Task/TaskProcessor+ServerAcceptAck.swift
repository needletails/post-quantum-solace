//
//  TaskProcessor+ServerAcceptAck.swift
//  post-quantum-solace
//

import Foundation

extension TaskProcessor {
    func registerUnackedServerAccept(
        pending: PendingOutboundTransport,
        localId: UUID,
        sharedId: String,
        isPersistedOutbound: Bool,
        session: PQSSession
    ) async {
        let envelopeMessageId = pending.metadata.envelopeMessageId
        unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)?.cancel()
        await cleanupUnackedServerAccept(session: session)
        unackedServerAcceptByEnvelopeId[envelopeMessageId] = UnackedOutboundEnvelope(
            pending: pending,
            localId: localId,
            sharedId: sharedId,
            isPersistedOutbound: isPersistedOutbound,
            connectionEpoch: messagingConnectionEpoch,
            resendAttempts: 0)
        startServerAcceptDeadline(envelopeMessageId: envelopeMessageId, session: session)
    }

    func confirmServerAcceptedEnvelope(_ envelopeMessageId: String, session: PQSSession) async {
        guard let entry = unackedServerAcceptByEnvelopeId.removeValue(forKey: envelopeMessageId) else {
            return
        }
        unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)?.cancel()
        PQSAuditLog.log(
            .send,
            "pqs.send.serverAccepted envelopeMessageId=\(envelopeMessageId) sharedId=\(entry.sharedId)",
            level: .info)

        guard entry.isPersistedOutbound else { return }
        let stillAwaitingAnotherDevice = unackedServerAcceptByEnvelopeId.values.contains {
            $0.localId == entry.localId && $0.isPersistedOutbound
        }
        if !stillAwaitingAnotherDevice {
            await markPersistedOutboundPastSendingIfNeeded(
                session: session,
                localMessageId: entry.localId)
        }
    }

    /// True while this envelope still awaits `privateMessageAccepted`.
    func isAwaitingServerAccept(_ envelopeMessageId: String) -> Bool {
        unackedServerAcceptByEnvelopeId[envelopeMessageId] != nil
    }

    /// Restart the accept deadline for one envelope (e.g. backlog still draining).
    func rearmServerAcceptDeadline(envelopeMessageId: String, session: PQSSession) {
        guard unackedServerAcceptByEnvelopeId[envelopeMessageId] != nil else { return }
        unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)?.cancel()
        startServerAcceptDeadline(envelopeMessageId: envelopeMessageId, session: session)
    }

    /// Fresh accept window for every pending envelope after offline backlog settles.
    func rearmAllServerAcceptDeadlines(session: PQSSession) {
        for envelopeMessageId in Array(unackedServerAcceptByEnvelopeId.keys) {
            rearmServerAcceptDeadline(envelopeMessageId: envelopeMessageId, session: session)
        }
    }

    func resendUnackedOutboundEnvelopes(reason: String, session: PQSSession) async {
        messagingConnectionEpoch &+= 1
        let currentEpoch = messagingConnectionEpoch
        await cleanupUnackedServerAccept(session: session)

        for envelopeMessageId in Array(unackedServerAcceptByEnvelopeId.keys) {
            guard var entry = unackedServerAcceptByEnvelopeId[envelopeMessageId],
                  entry.connectionEpoch < currentEpoch
            else {
                continue
            }

            if entry.resendAttempts >= maxServerAcceptResendAttempts {
                // Keep the identical ciphertext so a user Retry can re-arm the send.
                unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)?.cancel()
                entry.connectionEpoch = currentEpoch
                unackedServerAcceptByEnvelopeId[envelopeMessageId] = entry
                if entry.isPersistedOutbound {
                    await markPersistedOutboundFailed(
                        session: session,
                        localMessageId: entry.localId,
                        reason: "serverAcceptExhausted")
                }
                continue
            }

            guard let transportDelegate = await session.transportDelegate else {
                PQSAuditLog.log(
                    .send,
                    "pqs.send.resendEpoch transportMissing envelopeMessageId=\(envelopeMessageId) reason=\(reason)",
                    level: .error)
                continue
            }

            do {
                try await transportDelegate.sendMessage(entry.pending.message, metadata: entry.pending.metadata)
                entry.resendAttempts += 1
                entry.connectionEpoch = currentEpoch
                unackedServerAcceptByEnvelopeId[envelopeMessageId] = entry
                unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)?.cancel()
                startServerAcceptDeadline(envelopeMessageId: envelopeMessageId, session: session)
                PQSAuditLog.log(
                    .send,
                    "pqs.send.resendEpoch envelopeMessageId=\(envelopeMessageId) sharedId=\(entry.sharedId) epoch=\(currentEpoch) attempt=\(entry.resendAttempts) reason=\(reason)",
                    level: .info)
            } catch {
                PQSAuditLog.log(
                    .send,
                    "pqs.send.resendEpoch failed envelopeMessageId=\(envelopeMessageId) reason=\(reason) error=\(error)",
                    level: .error)
            }
        }
    }

    /// Message-delivery recovery only: resend identical ciphertext while still unacked,
    /// then fail the persisted bubble. Never owns connection health / core recycle.
    func handleServerAcceptAckOverdue(
        envelopeMessageId: String,
        session: PQSSession
    ) async {
        guard var entry = unackedServerAcceptByEnvelopeId[envelopeMessageId] else { return }
        // Detach the map slot only — do **not** cancel. This function runs inside that
        // deadline Task; cancelling it makes the in-place resend throw CancellationError.
        _ = unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)
        PQSAuditLog.log(
            .send,
            "pqs.send.ackOverdue envelopeMessageId=\(envelopeMessageId) sharedId=\(entry.sharedId) attempt=\(entry.resendAttempts)",
            level: .warning)
        await session.notifyServerAcceptAckOverdue(envelopeMessageId: envelopeMessageId)

        // Accept may have landed while notifying the owner.
        guard unackedServerAcceptByEnvelopeId[envelopeMessageId] != nil else { return }
        entry = unackedServerAcceptByEnvelopeId[envelopeMessageId] ?? entry

        if entry.resendAttempts >= maxServerAcceptResendAttempts {
            unackedServerAcceptByEnvelopeId[envelopeMessageId] = entry
            if entry.isPersistedOutbound {
                await markPersistedOutboundFailed(
                    session: session,
                    localMessageId: entry.localId,
                    reason: "serverAcceptExhausted")
            }
            PQSAuditLog.log(
                .send,
                "pqs.send.ackOverdueExhausted envelopeMessageId=\(envelopeMessageId) sharedId=\(entry.sharedId)",
                level: .warning)
            return
        }

        guard let transportDelegate = await session.transportDelegate else {
            // Keep waiting on the same envelope; re-arm so a later writer can recover.
            startServerAcceptDeadline(envelopeMessageId: envelopeMessageId, session: session)
            PQSAuditLog.log(
                .send,
                "pqs.send.ackOverdueResend transportMissing envelopeMessageId=\(envelopeMessageId)",
                level: .error)
            return
        }

        do {
            try await transportDelegate.sendMessage(entry.pending.message, metadata: entry.pending.metadata)
            // Dropped if accept won the race during send.
            guard unackedServerAcceptByEnvelopeId[envelopeMessageId] != nil else { return }
            entry.resendAttempts += 1
            unackedServerAcceptByEnvelopeId[envelopeMessageId] = entry
            startServerAcceptDeadline(envelopeMessageId: envelopeMessageId, session: session)
            PQSAuditLog.log(
                .send,
                "pqs.send.ackOverdueResend envelopeMessageId=\(envelopeMessageId) sharedId=\(entry.sharedId) attempt=\(entry.resendAttempts)",
                level: .info)
        } catch is CancellationError {
            // External cancel (e.g. teardown) — only re-arm if still awaiting accept.
            guard unackedServerAcceptByEnvelopeId[envelopeMessageId] != nil else { return }
            startServerAcceptDeadline(envelopeMessageId: envelopeMessageId, session: session)
            PQSAuditLog.log(
                .send,
                "pqs.send.ackOverdueResend cancelled envelopeMessageId=\(envelopeMessageId)",
                level: .info)
        } catch {
            guard unackedServerAcceptByEnvelopeId[envelopeMessageId] != nil else { return }
            startServerAcceptDeadline(envelopeMessageId: envelopeMessageId, session: session)
            PQSAuditLog.log(
                .send,
                "pqs.send.ackOverdueResend failed envelopeMessageId=\(envelopeMessageId) error=\(error)",
                level: .error)
        }
    }

    /// User-initiated retry after ``serverAcceptExhausted``: reset attempts, return to
    /// `.sending`, and resend the identical ciphertext on the current epoch.
    @discardableResult
    func retryFailedServerAcceptOutbound(
        localMessageId: UUID,
        session: PQSSession
    ) async -> Bool {
        let matching = unackedServerAcceptByEnvelopeId.filter { $0.value.localId == localMessageId }
        guard !matching.isEmpty else { return false }

        await markPersistedOutboundSending(session: session, localMessageId: localMessageId)

        var didSend = false
        for (envelopeMessageId, var entry) in matching {
            entry.resendAttempts = 0
            entry.connectionEpoch = messagingConnectionEpoch
            guard let transportDelegate = await session.transportDelegate else {
                unackedServerAcceptByEnvelopeId[envelopeMessageId] = entry
                continue
            }
            do {
                try await transportDelegate.sendMessage(entry.pending.message, metadata: entry.pending.metadata)
                unackedServerAcceptByEnvelopeId[envelopeMessageId] = entry
                unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)?.cancel()
                startServerAcceptDeadline(envelopeMessageId: envelopeMessageId, session: session)
                PQSAuditLog.log(
                    .send,
                    "pqs.send.retryFailedServerAccept envelopeMessageId=\(envelopeMessageId) sharedId=\(entry.sharedId)",
                    level: .info)
                didSend = true
            } catch {
                unackedServerAcceptByEnvelopeId[envelopeMessageId] = entry
                PQSAuditLog.log(
                    .send,
                    "pqs.send.retryFailedServerAccept failed envelopeMessageId=\(envelopeMessageId) error=\(error)",
                    level: .error)
            }
        }
        return didSend
    }

    func markPersistedOutboundSending(session: PQSSession, localMessageId: UUID) async {
        guard let cache = await session.cache else { return }
        do {
            let persisted = try await cache.fetchMessage(id: localMessageId)
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            guard var props = await persisted.props(symmetricKey: symmetricKey) else { return }
            guard case .failed = props.deliveryState else { return }
            props.deliveryState = .sending
            let updated = try await persisted.updateMessage(with: props, symmetricKey: symmetricKey)
            try await cache.updateMessage(updated, symmetricKey: symmetricKey)
            await session.receiverDelegate?.updatedMessage(updated)
        } catch {
            logger.log(level: .debug, message: "markPersistedOutboundSending failed: \(error)")
        }
    }

    func markPersistedOutboundFailed(
        session: PQSSession,
        localMessageId: UUID,
        reason: String
    ) async {
        guard let cache = await session.cache else { return }
        do {
            let persisted = try await cache.fetchMessage(id: localMessageId)
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            guard var props = await persisted.props(symmetricKey: symmetricKey) else { return }
            props.deliveryState = .failed(reason)
            let updated = try await persisted.updateMessage(with: props, symmetricKey: symmetricKey)
            try await cache.updateMessage(updated, symmetricKey: symmetricKey)
            await session.receiverDelegate?.updatedMessage(updated)
        } catch {
            logger.log(level: .debug, message: "markPersistedOutboundFailed failed: \(error)")
        }
    }

    func testInsertUnackedForTests(
        envelopeMessageId: String,
        entry: UnackedOutboundEnvelope
    ) {
        unackedServerAcceptByEnvelopeId[envelopeMessageId] = entry
    }

    func testUnackedCountForTests() -> Int {
        unackedServerAcceptByEnvelopeId.count
    }

    func testSetAckDeadlineNanosecondsForTests(_ nanoseconds: UInt64?) {
        serverAcceptAckDeadlineNanosecondsOverride = nanoseconds
    }

    private func startServerAcceptDeadline(envelopeMessageId: String, session: PQSSession) {
        let deadline = serverAcceptAckDeadlineNanosecondsOverride ?? serverAcceptAckDeadlineNanoseconds
        unackedServerAcceptDeadlineTasks[envelopeMessageId] = Task { [weak self, weak session] in
            do {
                try await Task.sleep(nanoseconds: deadline)
            } catch {
                return
            }
            guard !Task.isCancelled, let self, let session else { return }
            await self.handleServerAcceptAckOverdue(
                envelopeMessageId: envelopeMessageId,
                session: session)
        }
    }

    private func cleanupUnackedServerAccept(session: PQSSession, now: Date = Date()) async {
        let cutoff = now.addingTimeInterval(-unackedServerAcceptTTL)
        let expired = unackedServerAcceptByEnvelopeId.compactMap { envelopeMessageId, entry in
            entry.pending.createdAt <= cutoff ? envelopeMessageId : nil
        }
        for envelopeMessageId in expired {
            guard let entry = unackedServerAcceptByEnvelopeId.removeValue(forKey: envelopeMessageId) else {
                continue
            }
            unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)?.cancel()
            if entry.isPersistedOutbound {
                await markPersistedOutboundFailed(
                    session: session,
                    localMessageId: entry.localId,
                    reason: "serverAcceptTTL")
            }
        }

        while unackedServerAcceptByEnvelopeId.count >= unackedServerAcceptLimit,
              let oldest = unackedServerAcceptByEnvelopeId.min(by: {
                  $0.value.pending.createdAt < $1.value.pending.createdAt
              })?.key {
            guard let entry = unackedServerAcceptByEnvelopeId.removeValue(forKey: oldest) else {
                break
            }
            unackedServerAcceptDeadlineTasks.removeValue(forKey: oldest)?.cancel()
            if entry.isPersistedOutbound {
                await markPersistedOutboundFailed(
                    session: session,
                    localMessageId: entry.localId,
                    reason: "serverAcceptLimit")
            }
        }
    }
}

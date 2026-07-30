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
        session: PQSSession
    ) {
        let envelopeMessageId = pending.metadata.envelopeMessageId
        unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)?.cancel()
        cleanupUnackedServerAccept()
        unackedServerAcceptByEnvelopeId[envelopeMessageId] = UnackedOutboundEnvelope(
            pending: pending,
            localId: localId,
            sharedId: sharedId,
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

        let stillAwaitingAnotherDevice = unackedServerAcceptByEnvelopeId.values.contains {
            $0.localId == entry.localId
        }
        if !stillAwaitingAnotherDevice {
            await markPersistedOutboundPastSendingIfNeeded(
                session: session,
                localMessageId: entry.localId)
        }
    }

    func resendUnackedOutboundEnvelopes(reason: String, session: PQSSession) async {
        messagingConnectionEpoch &+= 1
        let currentEpoch = messagingConnectionEpoch
        cleanupUnackedServerAccept()

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
                await markPersistedOutboundFailed(
                    session: session,
                    localMessageId: entry.localId,
                    reason: "serverAcceptExhausted")
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

    func handleServerAcceptAckOverdue(
        envelopeMessageId: String,
        session: PQSSession
    ) async {
        guard unackedServerAcceptByEnvelopeId[envelopeMessageId] != nil else { return }
        unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)
        PQSAuditLog.log(
            .send,
            "pqs.send.ackOverdue envelopeMessageId=\(envelopeMessageId)",
            level: .warning)
        await session.notifyServerAcceptAckOverdue(envelopeMessageId: envelopeMessageId)
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

    private func cleanupUnackedServerAccept(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-unackedServerAcceptTTL)
        let expired = unackedServerAcceptByEnvelopeId.compactMap { envelopeMessageId, entry in
            entry.pending.createdAt <= cutoff ? envelopeMessageId : nil
        }
        for envelopeMessageId in expired {
            unackedServerAcceptByEnvelopeId.removeValue(forKey: envelopeMessageId)
            unackedServerAcceptDeadlineTasks.removeValue(forKey: envelopeMessageId)?.cancel()
        }

        while unackedServerAcceptByEnvelopeId.count >= unackedServerAcceptLimit,
              let oldest = unackedServerAcceptByEnvelopeId.min(by: {
                  $0.value.pending.createdAt < $1.value.pending.createdAt
              })?.key {
            unackedServerAcceptByEnvelopeId.removeValue(forKey: oldest)
            unackedServerAcceptDeadlineTasks.removeValue(forKey: oldest)?.cancel()
        }
    }
}

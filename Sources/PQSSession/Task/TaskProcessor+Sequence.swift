//
//  TaskProcessor+Sequence.swift
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
//

import Foundation
import NeedleTailAsyncSequence
import SessionModels
import Crypto
import DoubleRatchetKit
import BinaryCodable

extension TaskProcessor {
    
    // MARK: - Atomic sequence
    
    func incrementId() -> Int {
        sequenceId += 1
        return sequenceId
    }
    
    // MARK: - Public API
    
    public func feedTask(
        _ task: EncryptableTask,
        session: PQSSession
    ) async throws {
        
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        
        let seq = incrementId()
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let job = try createJobModel(sequenceId: seq, task: task, symmetricKey: symmetricKey)
        try await cache.createJob(job)
        
        // Important: `feedTask` can be called while the processor is already running.
        // Persisting to cache alone is not enough because the active processing loop consumes
        // from `jobConsumer`. If we don't enqueue here, the job may not run until a future
        // cache reload happens (which can look like the task processor "stalled").
        try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
        
        try await startProcessingIfNeeded(session)
    }
    
    public func loadTasks(
        _ job: JobModel? = nil,
        cache: SessionCache,
        symmetricKey: SymmetricKey,
        session: PQSSession? = nil
    ) async throws {
        
        if let job {
            try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
        } else {
            try await loadFromCache(cache: cache, symmetricKey: symmetricKey)
        }
        
        if let session {
            try await startProcessingIfNeeded(session)
        }
    }
    
    // MARK: - Running Lock
    
    private func tryStart() -> Bool {
        if isRunning { return false }
        isRunning = true
        return true
    }
    
    private func stop() {
        isRunning = false
    }
    
    // MARK: - Startup
    
    private func startProcessingIfNeeded(_ session: PQSSession) async throws {
        guard tryStart() else {
            return
        }
        
        try await Task {
            defer {
                stop()
            }
            do {
                try await self.processingLoop(session)
            } catch {
                self.logger.log(level: .error, message: "Processor crashed: \(error)")
                throw error
            }
        }.value

        guard session.isViable else {
            return
        }

        if let cache = await session.cache,
           let hasJobs = try? await !cache.fetchJobs().isEmpty,
           hasJobs {
            try await startProcessingIfNeeded(session)
        }
    }
    // MARK: - Core loop
    
    private func processingLoop(_ session: PQSSession) async throws {
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }

        guard session.isViable else {
            await jobConsumer.gracefulShutdown()
            return
        }
        
        deferredDelayedJobIds.removeAll()
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        // If `loadTasks(...)` already seeded the consumer, don't immediately re-load from cache,
        // otherwise the same JobModel can be enqueued twice and processed twice.
        if await jobConsumer.deque.isEmpty {
            try await loadFromCache(cache: cache, symmetricKey: symmetricKey)
        }
        
        func startLoop() async throws {
            // If the session is not viable, pause processing to avoid busy-looping and
            // repeatedly re-loading the same jobs from cache.
            guard session.isViable else {
                await jobConsumer.gracefulShutdown()
                return
            }
            
            if await jobConsumer.deque.isEmpty {
                let remaining = try await cache.fetchJobs()
                if remaining.isEmpty {
                    await jobConsumer.gracefulShutdown()
                    return
                }
                try await loadFromCache(cache: cache, symmetricKey: symmetricKey)
            }
            
            for try await result in NeedleTailAsyncSequence(consumer: jobConsumer) {
                switch result {
                case let .success(job):
                    do {
                        // Track the in-flight job so a concurrent bulk reload
                        // (`loadTasks(nil, ...)`) cannot re-enqueue it from cache
                        // between dequeue and cache-row deletion — that window is
                        // exactly a reconnect drain racing an executing send.
                        inFlightJobIds.insert(job.id)
                        defer { inFlightJobIds.remove(job.id) }
                        let outcome = try await process(
                            job,
                            cache: cache,
                            session: session,
                            symmetricKey: symmetricKey)
                        
                        if outcome == .paused {
                            await jobConsumer.gracefulShutdown()
                            return
                        }
                        if await jobConsumer.deque.isEmpty {
                            await jobConsumer.gracefulShutdown()
                            return
                        }
                    } catch {
                        await jobConsumer.gracefulShutdown()
                        throw error
                    }
                case .consumed:
                    break
                }
            }
            try await startLoop()
        }
        try await startLoop()
    }
    
    // MARK: - Cache loading
    
    /// Sole cache→consumer bulk loader. Reconnect can trigger reloads from more
    /// than one place at once (host `resumeJobQueue`, the viability-transition
    /// auto-drain, and the processing loop's own refill); `process` never
    /// re-checks cache existence before running a job, so a duplicate enqueue
    /// would send the same frame twice. Serializing the whole
    /// snapshot-fetch-enqueue span means every reload computes its skip set
    /// against a quiescent view: a job is either still enqueued (skipped),
    /// executing (`inFlightJobIds`, skipped), or completed (cache row deleted,
    /// never fetched).
    private func loadFromCache(
        cache: SessionCache,
        symmetricKey: SymmetricKey
    ) async throws {
        while isBulkReloadingJobs {
            await withCheckedContinuation { continuation in
                bulkReloadWaiters.append(continuation)
            }
        }
        isBulkReloadingJobs = true
        defer {
            isBulkReloadingJobs = false
            let waiters = bulkReloadWaiters
            bulkReloadWaiters.removeAll()
            for waiter in waiters {
                waiter.resume()
            }
        }
        let enqueuedJobIds = Set(await jobConsumer.deque.map { $0.item.id })
        let skippedJobIds = enqueuedJobIds.union(inFlightJobIds)
        for job in try await cache.fetchJobs() where !skippedJobIds.contains(job.id) {
            try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
        }
    }
    
    // MARK: - Job execution
    private func process(
        _ job: JobModel,
        cache: SessionCache,
        session: PQSSession,
        symmetricKey: SymmetricKey
    ) async throws -> JobProcessingOutcome {
        
        guard let props = await job.props(symmetricKey: symmetricKey) else {
            try await cache.deleteJob(job)
            return .deleted
        }
        
#if DEBUG
        if let delayedUntil = props.delayedUntil {
            logger.log(level: .debug, message: "Job \(job.id) has delayedUntil=\(delayedUntil) (now=\(Date()))")
        }
#endif
        
        if let delayedUntil = props.delayedUntil, delayedUntil > Date() {
            // A not-yet-due retry must not head-of-line block ready jobs queued
            // behind it (e.g. new outbound sends during an inbound recovery
            // flood). Skip ahead once by re-queueing it at the back; if it
            // cycles back to the front still not due, every remaining job is
            // waiting on a future due date, so wait this one out.
            if !deferredDelayedJobIds.contains(job.id), await !jobConsumer.deque.isEmpty {
                deferredDelayedJobIds.insert(job.id)
                await jobConsumer.feedConsumer(job, priority: .background)
                return .deferredToBack
            }
            deferredDelayedJobIds.remove(job.id)
            let sleep = delayedUntil.timeIntervalSinceNow
            do {
                try await Task.sleep(nanoseconds: UInt64(sleep * 1_000_000_000))
            } catch {
                // If the task was cancelled while sleeping, just pause and let a future resume reload from cache.
                return .paused
            }
        } else {
            deferredDelayedJobIds.remove(job.id)
        }
        
        guard session.isViable else {
            // Leave the job in cache; we will reload it once the session becomes viable again.
            return .paused
        }

        do {
            if let taskDelegate {
                try await taskDelegate.performRatchet(task: props.task.task, session: session)
            } else {
                try await performRatchet(task: props.task.task, session: session)
            }
            
            try await cache.deleteJob(job)
            return .processed
            
        } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
            switch props.task.task {
            case .streamMessage(let message):
                // Orphan-resend policy: request resend only. Sender creates a new initiating
                // session on orphanResend when still on the orphaned SessionID.
                return try await handleUndecryptableInboundResend(
                    message: message,
                    failureClass: "ratchet.maxSkippedHeadersExceeded",
                    job: job,
                    cache: cache,
                    session: session,
                    diagnostic: "compromiseRotation=false")
            case .writeMessage(let message):
                logger.log(level: .error, message: "MaxSkippedHeadersExceeded for writeMessage to recipient: \(message.message.recipient)")
                await noteResendReplayDropped(sharedId: message.sharedId, reason: "maxSkippedHeadersExceeded")
                try await cache.deleteJob(job)
            }
            
        } catch let ratchetError as RatchetError where ratchetError == .stateUninitialized {
            // Dogfood poison: try-all fails with stateUninitialized when the preferred
            // row is state-less (prior outboundRepair / freshSessionRepair). Orphan-resend:
            // discard + request resend; the **sender** inserts a new initiating session
            // on orphanResend. Receive-side ASR here leaves another state-less active
            // that cannot decrypt the peer's already-sent non-initiating frames.
            switch props.task.task {
                
            case .streamMessage(let message):
                // If we return any value defer the job to be processed at the right time.
                if let deferred = try await tryDeferInboundDuringContactBootstrap(
                    message: message,
                    error: ratchetError,
                    job: job,
                    props: props,
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey) {
                    return deferred
                }
                
                // The job could not be processed, try and request resend if at all possible
                return try await handleUndecryptableInboundResend(
                    message: message,
                    failureClass: "ratchet.stateUninitialized",
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                return try await handleFreshOutboundRepair(
                    message: message,
                    error: ratchetError,
                    job: job,
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey)
            }

        } catch let ratchetError as RatchetError where isFreshSessionRepairError(ratchetError) {
            switch props.task.task {
            case .streamMessage(let message):
                
                // If we return any value defer the job to be processed at the right time.
                if let deferred = try await tryDeferInboundDuringContactBootstrap(
                    message: message,
                    error: ratchetError,
                    job: job,
                    props: props,
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey) {
                    return deferred
                }
                
                // The job could not be processed, try and request resend if at all possible
                return try await handleUndecryptableInboundResend(
                    message: message,
                    failureClass: freshSessionFailureClass(ratchetError),
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                return try await handleFreshOutboundRepair(
                    message: message,
                    error: ratchetError,
                    job: job,
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey)
            }

        } catch let ratchetError as RatchetError where ratchetError == .decryptionFailed {
            switch props.task.task {
            case .streamMessage(let message):
                
                // If we return any value defer the job to be processed at the right time.
                if let deferred = try await tryDeferInboundDuringContactBootstrap(
                    message: message,
                    error: ratchetError,
                    job: job,
                    props: props,
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey) {
                    return deferred
                }
                
                // The job could not be processed, try and request resend if at all possible
                return try await handleUndecryptableInboundResend(
                    message: message,
                    failureClass: "ratchet.decryptionFailed",
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                logger.log(level: .error, message: "decryptionFailed for writeMessage to recipient: \(message.message.recipient)")
                await noteResendReplayDropped(sharedId: message.sharedId, reason: "decryptionFailed")
                try await cache.deleteJob(job)
            }

        } catch let ratchetError as RatchetError where isInboundSessionDesyncError(ratchetError) {
            switch props.task.task {
            case .streamMessage(let message):
                
                // If we return any value defer the job to be processed at the right time.
                if let deferred = try await tryDeferInboundDuringContactBootstrap(
                    message: message,
                    error: ratchetError,
                    job: job,
                    props: props,
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey) {
                    return deferred
                }
                
                // The job could not be processed, try and request resend if at all possible
                return try await handleUndecryptableInboundResend(
                    message: message,
                    failureClass: inboundSessionDesyncFailureClass(ratchetError),
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                logger.log(level: .error, message: "\(ratchetError) for writeMessage to recipient: \(message.message.recipient)")
                await noteResendReplayDropped(sharedId: message.sharedId, reason: "\(ratchetError)")
                try await cache.deleteJob(job)
            }

        } catch let ratchetError as RatchetError where ratchetError == .expiredKey {
            switch props.task.task {
            case .streamMessage(let message):
                
                /// This will occur when the `skippedMessageKeys`'s  `key.remoteOneTimePublicKey` is not equivalent to the heder `OTK`
                let failureClass = "ratchet.expiredKey"
                if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
                    auditInboundDecryptFailure(
                        message: message,
                        failureClass: failureClass,
                        action: "dropExpiredSkippedKey",
                        suppressed: true)
                    try await cache.deleteJob(job)
                    return .deleted
                }

                auditInboundDecryptFailure(
                    message: message,
                    failureClass: failureClass,
                    action: "dropExpiredSkippedKey")
                await session.markInboundFailure(message, failureClass: failureClass)
                try await cache.deleteJob(job)
                return .deleted
            case .writeMessage(let message):
                logger.log(level: .error, message: "expiredKey for writeMessage to recipient: \(message.message.recipient)")
                await noteResendReplayDropped(sharedId: message.sharedId, reason: "expiredKey")
                try await cache.deleteJob(job)
            }

        } catch let ratchetError as RatchetError where ratchetError == .missingOneTimeKey {
            switch props.task.task {
            case .streamMessage(let message):
                
                let failureClass = "ratchet.missingOneTimeKey"
                
                // Checks if the contact is has been removed locally
                if await session.shouldSuppressInboundRecoveryFromSender(message.senderSecretName) {
                    auditInboundDecryptFailure(
                        message: message,
                        failureClass: failureClass,
                        action: "dropDeletedPeer",
                        suppressed: true)
                    logger.log(
                        level: .info,
                        message: "Dropping \(failureClass) for deleted peer \(message.senderSecretName); skipping recovery")
                    try await cache.deleteJob(job)
                    return .deleted
                }
                
                // Checks if the message Failed inbound messages whose replay should be requested only after the peer/device has completed the reestablishment round.
                if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
                    auditInboundDecryptFailure(
                        message: message,
                        failureClass: failureClass,
                        suppressed: true)
                    logger.log(level: .info, message: "Suppressing repeated \(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
                    try await cache.deleteJob(job)
                    return .deleted
                }

                // Orphan-resend already owns this sharedId (maxSkipped/body fail → resend).
                // Do not open receive-side OTK ASR — that poisoned dogfood orphan replay
                // (`883B532C`: maxSkipped → missingOneTimeKey → coalescedPendingPeerRecovery).
                if await session.isAwaitingSenderOrphanResend(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId,
                    messageId: message.sharedMessageId) {
                    auditInboundDecryptFailure(
                        message: message,
                        failureClass: failureClass,
                        action: "resendAwaitingSender",
                        suppressed: true)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendAwaitingSender failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) reason=orphanResendOwnsSharedId")
                    DecryptFailureAuditLog.log(
                        "pqs.recovery.otkBootstrapDeferredToOrphanResend sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId.uuidString)")
                    try await cache.deleteJob(job)
                    return .deleted
                }

                // Pending replay IDs outlive the single-flight episode. Only a live
                // episode may suppress a new event-driven repair attempt.
                let hasOpenOTKEpisode = await session.hasOpenReestablishmentEpisode(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId)
                if hasOpenOTKEpisode {
                    auditInboundDecryptFailure(
                        message: message,
                        failureClass: failureClass,
                        action: "coalescedPendingPeerRecovery")
                    await session.deferPeerResendUntilReestablished(
                        sender: message.senderSecretName,
                        deviceId: message.senderDeviceId,
                        failedMessageId: message.sharedMessageId,
                        failureClass: failureClass)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.coalesced failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) reason=pendingPeerRefresh")
                    await session.markInboundFailure(message, failureClass: failureClass)
                    try await cache.deleteJob(job)
                    return .deleted
                }

                auditInboundDecryptFailure(
                    message: message,
                    failureClass: failureClass,
                    action: "replaceOTKBatchThenPeerRefresh")
                logger.log(
                    level: .warning,
                    message: "pqs.recovery.started failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) action=replaceOTKBatchThenPeerRefresh")

                // If we make it to this point we will try and reestablish session and refresh OTK(s)
                
                _ = await session.tryBeginReestablishmentEpisode(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId)
                await session.deferPeerResendUntilReestablished(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId,
                    failedMessageId: message.sharedMessageId,
                    failureClass: failureClass)
                logger.log(
                    level: .info,
                    message: "pqs.recovery.deferred failureClass=\(failureClass) sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) waitingFor=peerRefresh")

                // Record the accepted recovery *before* the network-bound side effects so
                // redelivery of the same frame is suppressed instead of repeating the OTK
                // batch replacement and the cooldown-bypassing peerRefresh re-emit.
                await session.markInboundFailure(message, failureClass: failureClass)

                // The published-batch replacement (key generation + two uploads with
                // retry backoff) and the subsequent peerRefresh emit must not block the
                // job queue: an offline-backlog flood would otherwise stall every queued
                // outbound send behind this recovery. The recovery episode state above
                // is already recorded, so subsequent failures coalesce against it while
                // this continuation runs. Ordering inside the continuation is preserved:
                // peerRefresh is only emitted once fresh keys are on the server.
                let logger = logger
                let senderSecretName = message.senderSecretName
                let senderDeviceId = message.senderDeviceId
                let sharedMessageId = message.sharedMessageId
                await session.scheduleBackgroundWork { [self] in
                    let curveReplaced = await session.refreshOneTimeKeysTask(policy: .replacePublishedBatch)
                    guard !Task.isCancelled else { return }
                    let mlKEMReplaced = await session.refreshMLKEMOneTimeKeysTask(policy: .replacePublishedBatch)
                    guard !Task.isCancelled else { return }
                    guard curveReplaced && mlKEMReplaced else {
                        logger.log(
                            level: .error,
                            message: "pqs.recovery.failed failureClass=\(failureClass) sender=\(senderSecretName) deviceId=\(senderDeviceId) sharedId=\(sharedMessageId) reason=otkBatchReplacementFailed")
                        await session.endReestablishmentEpisode(
                            sender: senderSecretName,
                            deviceId: senderDeviceId)
                        return
                    }

                    let mySecretName = await session.sessionContext?.sessionUser.secretName
                    let isSelf = senderSecretName == mySecretName

                    do {
                        // Documented receive-side ASR must not emit peerRefresh toward a
                        // peer whose advertised signing key no longer matches the pin.
                        if !isSelf {
                            try await session.validatePeerAccountSigningKeyAgainstRemote(
                                secretName: senderSecretName)
                        }
                        _ = try await session.emitSessionReestablishment(
                            kind: .peerRefresh,
                            recipient: isSelf ? .personalMessage : .nickname(senderSecretName),
                            scope: isSelf
                                ? .personalDevice(deviceId: senderDeviceId)
                                : .peerDevice(
                                    secretName: senderSecretName,
                                    deviceId: senderDeviceId),
                            forceReemit: true)
                        logger.log(
                            level: .info,
                            message: "pqs.recovery.reestablishmentQueued kind=peerRefresh failureClass=\(failureClass) sender=\(senderSecretName) deviceId=\(senderDeviceId) sharedId=\(sharedMessageId)")
                    } catch let sessionError as PQSSession.SessionErrors where sessionError == .peerSigningKeyOutOfSync {
                        await self.reportPeerSigningKeyOutOfSync(message: message, session: session)
                    } catch {
                        // Terminal for this episode: nothing is on the wire, so keeping
                        // it open would coalesce failures against a request that was
                        // never sent. Same handling as the fresh-repair catch-all.
                        await session.markRecoveryEmitBlocked(
                            sender: senderSecretName,
                            deviceId: senderDeviceId)
                        await session.endReestablishmentEpisode(
                            sender: senderSecretName,
                            deviceId: senderDeviceId)
                        logger.log(
                            level: .warning,
                            message: "pqs.recovery.reestablishmentFailed kind=peerRefresh failureClass=\(failureClass) sender=\(senderSecretName) deviceId=\(senderDeviceId) sharedId=\(sharedMessageId) error=\(error)")
                    }
                }

                try await cache.deleteJob(job)
                return .deleted
            case .writeMessage(let message):
                logger.log(level: .error, message: "missingOneTimeKey for writeMessage to recipient: \(message.message.recipient)")
                await noteResendReplayDropped(sharedId: message.sharedId, reason: "missingOneTimeKey")
                try await cache.deleteJob(job)
            }
        } catch let cryptoError as CryptoKitError {
            switch props.task.task {
            case .streamMessage(let message):
                
                // If we return any value defer the job to be processed at the right time.
                if let deferred = try await tryDeferInboundUntilPeerRatchetReady(
                    message: message,
                    job: job,
                    props: props,
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey,
                    failureClass: "crypto.bodyDecryptionFailed") {
                    return deferred
                }
                
                
                // Body AEAD auth failure: same orphan-resend policy as
                // `ratchet.decryptionFailed` (sender orphanResend heals).
                //
                // The job could not be processed, try and request resend if at all possible
                return try await handleUndecryptableInboundResend(
                    message: message,
                    failureClass: "crypto.bodyDecryptionFailed",
                    job: job,
                    cache: cache,
                    session: session,
                    diagnostic: "error=\(cryptoError)")
            case .writeMessage(let message):
                logger.log(level: .error, message: "CryptoKitError for writeMessage to recipient: \(message.message.recipient) — \(cryptoError)")
                await noteResendReplayDropped(sharedId: message.sharedId, reason: "cryptoKitError")
                try await cache.deleteJob(job)
            }
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .sessionDecryptionError {
            switch props.task.task {
            case .streamMessage(let message):
                
                // Payload/context decode failure after ratchet decrypt: same
                // Same undecryptable policy as CryptoKit / decryptionFailed.
                //
                // The job could not be processed, try and request resend if at all possible
                return try await handleUndecryptableInboundResend(
                    message: message,
                    failureClass: "payload.sessionDecryptionError",
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                logger.log(level: .error, message: "sessionDecryptionError for writeMessage to recipient: \(message.message.recipient)")
                await noteResendReplayDropped(sharedId: message.sharedId, reason: "sessionDecryptionError")
                try await cache.deleteJob(job)
            }
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .peerSigningKeyOutOfSync {
            switch props.task.task {
            case .streamMessage(let message):
                
                // This will cause quarantining of the contact's sessionIdentity and send a trust message
                return try await handlePeerSigningKeyOutOfSync(
                    message: message,
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                logger.log(
                    level: .error,
                    message: "peerSigningKeyOutOfSync for writeMessage to recipient: \(message.message.recipient); dropping until peer identity is reverified")
                await noteResendReplayDropped(sharedId: message.sharedId, reason: "peerSigningKeyOutOfSync")
            }
            try await cache.deleteJob(job)
            return .deleted
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .signingKeyOutOfSync {
            logger.log(level: .error, message: "signingKeyOutOfSync during job processing; child device likely needs reprovisioning from master")
            switch props.task.task {
            case .streamMessage:
                do {
                    // This is for our linked devices, if the signing key changes on a device we need to trust it and reestablish the session
                    _ = try await session.emitSessionReestablishment(
                        kind: .linkedDeviceCompromiseObserved,
                        recipient: .personalMessage,
                        scope: .personal
                    )
                } catch {
                    logger.log(level: .warning, message: "Failed to send reprovisioning request to master: \(error)")
                }
            case .writeMessage:
                break
            }
            try await cache.deleteJob(job)
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
            switch props.task.task {
            case .streamMessage(let message):
                
                // If we have an invalid signature we are potentially compromised we need to reestablish the session
                return try await handleInvalidSignature(
                    message: message,
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                logger.log(level: .error, message: "invalidSignature for writeMessage to recipient: \(message.message.recipient)")
                await noteResendReplayDropped(sharedId: message.sharedId, reason: "invalidSignature")
                try await cache.deleteJob(job)
            }
        } catch {
            
            // If we are throwing an error for some other reason... On write we delay the message sending for retry before considering it a loss and deleting
            if case .writeMessage(let message) = props.task.task,
               pendingOutboundTransportBySharedId[message.sharedId] != nil {
                return try await deferPendingOutboundTransportRetry(
                    job: job,
                    props: props,
                    cache: cache,
                    session: session,
                    symmetricKey: symmetricKey,
                    error: error)
            }
            if case .writeMessage(let message) = props.task.task {
                // No remembered signed frame, but the failure is connectivity, not
                // content: the connection died mid-write (or viability flipped after
                // this job was dequeued). Deleting here would silently lose a message
                // composed while going offline. Park it instead — the job stays in
                // cache and the viability-transition drain replays it on reconnect,
                // re-encrypting from scratch.
                if !session.isViable || isConnectionNonViableError(error) {
                    logger.log(
                        level: .info,
                        message: "pqs.outbound.parkedForViability sharedId=\(message.sharedId) recipient=\(message.message.recipient) error=\(error)")
                    return .paused
                }
                await noteResendReplayDropped(sharedId: message.sharedId, reason: "unhandledError=\(error)")
            }
            
            // If we are throwing an error for some other reason... On stream we just delete the job
            logger.log(level: .error, message: "Unhandled error during job processing: \(error). Deleting job...")
            try await cache.deleteJob(job)
            logger.log(level: .info, message: "Deleted Job")
        }
        return .failed
    }

    // MARK: - Job Processing Outcomes
    
    enum JobProcessingOutcome: Sendable, Equatable {
        /// Job completed successfully and was removed from cache.
        case processed
        /// Job was removed from cache without running (e.g., invalid/missing identity).
        case deleted
        /// Processing should pause (e.g., session non-viable); job remains in cache to be reloaded later.
        case paused
        /// Job failed but was not deleted (best-effort retry semantics).
        case failed
        /// Job is delayed and not yet due; it was re-queued at the back of the deque
        /// so ready jobs behind it can run first. It remains in cache.
        case deferredToBack
    }
    
    // MARK: - Errors
    
    enum JobProcessorErrors: Error, LocalizedError {
        case missingIdentity
        
        public var errorDescription: String? {
            "Job references a missing session identity"
        }
        
        public var recoverySuggestion: String? {
            "Ensure the session identity exists before processing the job"
        }
    }
    
    private func inboundTask(from task: TaskType) -> InboundTaskMessage? {
        guard case let .streamMessage(inbound) = task else { return nil }
        return inbound
    }

    /// When the peer OTK handshake is still in flight, encrypted payloads (often a
    /// friendship request sent immediately after bootstrap) can arrive before the
    /// ratchet is ready. Re-queue at the back of the job deque so earlier handshake
    /// jobs can run first; fall through to full repair only after bounded passes.
    private func tryDeferInboundUntilPeerRatchetReady(
        message: InboundTaskMessage,
        job: JobModel,
        props: JobModel.UnwrappedProps,
        cache: SessionCache,
        session: PQSSession,
        symmetricKey: SymmetricKey,
        failureClass: String
    ) async throws -> JobProcessingOutcome? {
        
        // Here we are checking if the persisted cache has a session identity that is not marked as archived and has state because we must have an active session identity created before proceeding.
        guard await session.isAwaitingInboundPeerRatchetHandshake(
            secretName: message.senderSecretName,
            deviceId: message.senderDeviceId) else {
            return nil
        }

        // Only try {maxAttempts} for this given job
        let maxAttempts = 24
        guard props.attempts < maxAttempts else { return nil }

        logger.log(
            level: .info,
            message: "Re-queueing inbound message until peer OTK handshake completes for \(message.senderSecretName) deviceId=\(message.senderDeviceId) failureClass=\(failureClass) pass=\(props.attempts + 1)/\(maxAttempts)")

        var updatedProps = props
        updatedProps.attempts += 1
        _ = try await job.updateProps(symmetricKey: symmetricKey, props: updatedProps)
        try await cache.updateJob(job)
        
        // If we are running the consumer proceed
        if await !jobConsumer.deque.isEmpty {
            await jobConsumer.feedConsumer(job, priority: .background)
            return .deferredToBack
        }
        // Consumer is not running let's wait for it to start
        return .paused
    }

    /// This method allows us to wait for the peer ratchet to be active before proceeding with decryption under certain fail case scenarios. If it is not ready we wait (n) times until ready before trying decryption.
    private func tryDeferInboundDuringContactBootstrap(
        message: InboundTaskMessage,
        error: RatchetError,
        job: JobModel,
        props: JobModel.UnwrappedProps,
        cache: SessionCache,
        session: PQSSession,
        symmetricKey: SymmetricKey
    ) async throws -> JobProcessingOutcome? {
        guard isFreshSessionRepairError(error)
            || error == .decryptionFailed
            || error == .stateUninitialized
            || isInboundSessionDesyncError(error)
        else {
            return nil
        }
        let failureClass: String
        if isInboundSessionDesyncError(error) {
            failureClass = inboundSessionDesyncFailureClass(error)
        } else if error == .decryptionFailed {
            failureClass = "ratchet.decryptionFailed"
        } else if error == .stateUninitialized {
            failureClass = "ratchet.stateUninitialized"
        } else {
            failureClass = freshSessionFailureClass(error)
        }
        return try await tryDeferInboundUntilPeerRatchetReady(
            message: message,
            job: job,
            props: props,
            cache: cache,
            session: session,
            symmetricKey: symmetricKey,
            failureClass: failureClass)
    }

    /// Undecryptable inbound policy (orphan-resend):
    /// 1. Drop the frame and request a bounded resend.
    /// 2. Never open receive-side Automatic Session Reset / `peerRefresh` for these
    ///    classes — the **sender** inserts a new initiating session on orphanResend
    ///    when still encrypting with the orphaned SessionID.
    /// 3. Repeats of the same failure are suppressed (cooldown) while awaiting the
    ///    sender; when a *new* ciphertext for that sharedId still fails after a
    ///    transport-confirmed NACK, re-arm a bounded NACK (orphan replay did not prove).
    /// 4. Distinct ids keep requesting resend until the sender heals or reports unavailable.
    private func handleUndecryptableInboundResend(
        message: InboundTaskMessage,
        failureClass: String,
        job: JobModel,
        cache: SessionCache,
        session: PQSSession,
        diagnostic: String? = nil
    ) async throws -> JobProcessingOutcome {
        // Terminal tuples stay terminal: once this sharedId was surfaced to the
        // host as unrecoverable, redelivered copies of the same poison frame
        // (offline queues redeliver un-ACKed frames on every reconnect) must
        // not reopen a NACK round or re-notify the host. A copy that *decrypts*
        // never reaches this failure path, so a late orphan replay still heals.
        if await session.isInboundContentUnrecoverable(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId,
            sharedId: message.sharedMessageId)
        {
            DecryptFailureAuditLog.log(
                "pqs.recovery.redeliveryDropped reason=terminalContentUnrecoverable failureClass=\(failureClass) sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId.uuidString)")
            try await cache.deleteJob(job)
            return .deleted
        }

        // New frame, same sharedId, prior NACK already on the wire, still undecryptable:
        // clear cooldown/suppress so sender orphanResend can be asked again (bounded).
        let rearmedAfterFailedReplay = await session.armPeerResendRetryAfterFailedReplay(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId,
            failedMessageId: message.sharedMessageId)
        if rearmedAfterFailedReplay {
            logger.log(
                level: .info,
                message: "pqs.recovery.orphanReplayStillUndecryptable failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) action=rearmNack")
        }

        // While another recovery episode is open (e.g. hard ratchet repair), coalesce.
        // Skip coalesce when we just re-armed after a failed orphan replay — that sharedId
        // still needs a sender NACK, not deferral.
        if !rearmedAfterFailedReplay,
           await session.hasOpenReestablishmentEpisode(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId)
        {
            auditInboundDecryptFailure(
                message: message,
                failureClass: failureClass,
                error: diagnostic,
                action: "coalescedPendingPeerRecovery",
                metadata: diagnostic.map { ["diagnostic": $0] } ?? [:])
            await session.deferPeerResendUntilReestablished(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId,
                failedMessageId: message.sharedMessageId,
                failureClass: failureClass)
            await session.markInboundFailure(message, failureClass: failureClass)
            logger.log(
                level: .info,
                message: "pqs.recovery.coalesced failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) reason=pendingPeerRefresh")
            try await cache.deleteJob(job)
            return .deleted
        }

        if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
            let submissionCount = await session.resendRequestSubmissionCount(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId,
                failedMessageId: message.sharedMessageId)
            if submissionCount >= PQSSessionConstants.peerResendRequestMaxSubmissions {
                // Lost-NACK safety while awaiting sender: close this sharedId only.
                await session.clearPendingResends(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId,
                    messageIds: [message.sharedMessageId])
                auditInboundDecryptFailure(
                    message: message,
                    failureClass: failureClass,
                    error: diagnostic,
                    action: "contentUnrecoverable",
                    suppressed: true,
                    metadata: diagnostic.map { ["diagnostic": $0] } ?? [:])
                let newlyTerminal = await session.markInboundContentUnrecoverable(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId,
                    sharedId: message.sharedMessageId)
                if newlyTerminal {
                    DecryptFailureAuditLog.log(
                        "pqs.recovery.contentUnrecoverable sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId.uuidString) reason=resendSubmissionCap attempts=\(submissionCount)")
                    await session.sessionDelegate?.inboundContentUnrecoverable(
                        senderSecretName: message.senderSecretName,
                        senderDeviceId: message.senderDeviceId,
                        sharedMessageId: message.sharedMessageId)
                }
                logger.log(
                    level: .warning,
                    message: "pqs.recovery.resendRequestExhausted failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) attempts=\(submissionCount)")
                try await cache.deleteJob(job)
                return .deleted
            }
            // Already requested resend for this tuple; wait for sender orphanResend /
            // replay. Do not mint a receive-side repair session.
            auditInboundDecryptFailure(
                message: message,
                failureClass: failureClass,
                error: diagnostic,
                action: "resendAwaitingSender",
                suppressed: true,
                metadata: diagnostic.map { ["diagnostic": $0] } ?? [:])
            logger.log(
                level: .info,
                message: "pqs.recovery.resendAwaitingSender failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId)")
            try await cache.deleteJob(job)
            return .deleted
        }

        // Transport may already be non-viable (VPN/core recycle). Park the inbound job
        // for resumeJobQueue on viability restore — do not delete or mark failure yet,
        // or the NACK is lost until another copy of the ciphertext arrives.
        if !session.isViable {
            auditInboundDecryptFailure(
                message: message,
                failureClass: failureClass,
                error: diagnostic,
                action: "resendParkedNonViable",
                metadata: diagnostic.map { ["diagnostic": $0] } ?? [:])
            logger.log(
                level: .info,
                message: "pqs.recovery.resendParkedNonViable failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId)")
            return .paused
        }

        let laneSaturated = await session.noteUndecryptableLaneFailure(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId,
            sharedId: message.sharedMessageId)
        // After saturation, once at least one NACK has reached the wire for this
        // peer-device, open the existing reestablishment episode so further distinct
        // sharedIds coalesce via deferPeerResendUntilReestablished. Sender orphanResend
        // still owns heal — this does not emit peerRefresh / receive ASR.
        if !rearmedAfterFailedReplay,
           laneSaturated,
           await session.hasTransportedPeerResendRequest(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId)
        {
            _ = await session.tryBeginReestablishmentEpisode(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId)
            DecryptFailureAuditLog.log(
                "pqs.recovery.undecryptableLaneSaturated sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId.uuidString) sharedId=\(message.sharedMessageId) awaitingSenderOrphanResend=true")
            auditInboundDecryptFailure(
                message: message,
                failureClass: failureClass,
                error: diagnostic,
                action: "coalescedPendingPeerRecovery",
                metadata: diagnostic.map { ["diagnostic": $0] } ?? [:])
            await session.deferPeerResendUntilReestablished(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId,
                failedMessageId: message.sharedMessageId,
                failureClass: failureClass)
            await session.markInboundFailure(message, failureClass: failureClass)
            logger.log(
                level: .info,
                message: "pqs.recovery.coalesced failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) reason=undecryptableLaneSaturated")
            try await cache.deleteJob(job)
            return .deleted
        }

        let didRequestResend = await requestPeerResendIfAllowed(
            message: message,
            failureClass: failureClass,
            session: session)
        var action = didRequestResend ? "resendRequested" : "resendSkipped"
        if laneSaturated {
            action = didRequestResend ? "resendRequested.lane" : "resendSkipped.lane"
            DecryptFailureAuditLog.log(
                "pqs.recovery.undecryptableLaneSaturated sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId.uuidString) sharedId=\(message.sharedMessageId) awaitingSenderOrphanResend=true")
        }
        auditInboundDecryptFailure(
            message: message,
            failureClass: failureClass,
            error: diagnostic,
            action: action,
            metadata: diagnostic.map { ["diagnostic": $0] } ?? [:])
        await session.markInboundFailure(message, failureClass: failureClass)
        try await cache.deleteJob(job)
        return .deleted
    }

    private func isConnectionNonViableError(_ error: Error) -> Bool {
        if let sessionError = error as? PQSSession.SessionErrors,
           sessionError == .connectionIsNonViable {
            return true
        }
        let description = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
        return description.localizedCaseInsensitiveContains("non-viable")
    }

    private func shouldLogOutboundTransportRetry(message: String) -> Bool {
        let now = Date()
        if message == lastOutboundTransportRetryLogMessage,
           now.timeIntervalSince(lastOutboundTransportRetryLogAt) < outboundTransportRetryLogCooldown {
            suppressedOutboundTransportRetryLogCount += 1
            return false
        }
        if suppressedOutboundTransportRetryLogCount > 0 {
            logger.log(
                level: .warning,
                message: "Deferred outbound transport retry suppressed=\(suppressedOutboundTransportRetryLogCount) priorDuplicates")
            suppressedOutboundTransportRetryLogCount = 0
        }
        lastOutboundTransportRetryLogAt = now
        lastOutboundTransportRetryLogMessage = message
        return true
    }

    private func deferPendingOutboundTransportRetry(
        job: JobModel,
        props: JobModel.UnwrappedProps,
        cache: SessionCache,
        session: PQSSession,
        symmetricKey: SymmetricKey,
        error: Error
    ) async throws -> JobProcessingOutcome {
        var updatedProps = props
        updatedProps.attempts += 1
        // Transport can throw non-viable while `session.isViable` is still true during
        // VPN/core recycle. Park for event-driven resumeJobQueue (IRC viability restored)
        // instead of short timer requeues that flood warnings.
        let parkForViability = !session.isViable || isConnectionNonViableError(error)
        if parkForViability {
            updatedProps.delayedUntil = nil
        } else {
            updatedProps.delayedUntil = Date().addingTimeInterval(min(0.10 * Double(updatedProps.attempts), 1.0))
        }
        _ = try await job.updateProps(symmetricKey: symmetricKey, props: updatedProps)
        try await cache.updateJob(job)
        if !parkForViability {
            try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
        }
        // A NACK that has not reached the wire must not leave its failed ids
        // suppressed: submission attempts are only counted on transported frames,
        // and the sender cannot orphan-resend until the request transports. Clear
        // the failure-class suppress so the tuple stays retryable; the armed
        // request cooldown still bounds duplicate NACKs while this job retries.
        if case .writeMessage(let outboundTask) = props.task.task,
           let pending = pendingOutboundTransportBySharedId[outboundTask.sharedId],
           case .requestMessageResend(let request) = pending.metadata.transportEvent {
            for failedId in request.failedSharedMessageIds {
                _ = await session.takeInboundFailureClasses(
                    sender: pending.metadata.secretName,
                    deviceId: pending.metadata.deviceId,
                    messageId: failedId)
            }
        }
        let logMessage: String
        if let recoveryLog = recoveryTransportSendFailureLog(
            props: props,
            attempt: updatedProps.attempts,
            error: error)
        {
            logMessage = recoveryLog
        } else {
            logMessage = "Deferred outbound transport retry for pending signed frame attempt=\(updatedProps.attempts): \(error)"
        }
        if shouldLogOutboundTransportRetry(message: logMessage) {
            logger.log(level: .warning, message: .init(stringLiteral: logMessage))
        }
        return .paused
    }

    private func recoveryTransportSendFailureLog(
        props: JobModel.UnwrappedProps,
        attempt: Int,
        error: Error
    ) -> String? {
        guard case .writeMessage(let outboundTask) = props.task.task,
              let transportEvent = pendingOutboundTransportBySharedId[outboundTask.sharedId]?.metadata.transportEvent
        else {
            return nil
        }

        switch transportEvent {
        case .sessionReestablishment(let envelope):
            return "pqs.recovery.reestablishmentSendFailed sharedId=\(outboundTask.sharedId) kind=\(envelope.kind.rawValue) response=\(envelope.isResponse) epoch=\(envelope.epoch) intent=\(envelope.intentId?.uuidString ?? "nil") retryAttempt=\(attempt) error=\(error)"
        case .requestMessageResend(let request):
            return "pqs.recovery.resendRequestSendFailed sharedId=\(outboundTask.sharedId) requestingDeviceId=\(request.requestingDeviceId) requestedCount=\(request.failedSharedMessageIds.count) ids=\(request.failedSharedMessageIds.joined(separator: ",")) retryAttempt=\(attempt) error=\(error)"
        case .linkedDeviceReprovisioning(let bundle):
            return "pqs.recovery.linkedDeviceReprovisioningSendFailed sharedId=\(outboundTask.sharedId) targetDeviceId=\(bundle.targetDeviceId) retryAttempt=\(attempt) error=\(error)"
        case .messageResendUnavailable(let notice):
            return "pqs.recovery.resendUnavailableSendFailed sharedId=\(outboundTask.sharedId) respondingDeviceId=\(notice.respondingDeviceId) unavailableCount=\(notice.unavailableSharedMessageIds.count) retryAttempt=\(attempt) error=\(error)"
        case .synchronizeOneTimeKeys, .refreshOneTimeKeys, .publishedOneTimeKeysReplenished:
            return nil
        }
    }

    /// Waits until outbound encrypt jobs drain so OTK notify completes before friendship send.
    func waitForOutboundJobDrain(
        cache: SessionCache,
        session: PQSSession,
        timeout: TimeInterval = 8.0
    ) async {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let jobs = (try? await cache.fetchJobs()) ?? []
            if jobs.isEmpty, !isRunning {
                try? await Task.sleep(nanoseconds: 100_000_000)
                let remaining = (try? await cache.fetchJobs()) ?? []
                if remaining.isEmpty, !isRunning {
                    return
                }
            }
            try? await Task.sleep(nanoseconds: 75_000_000)
        }
        logger.log(level: .info, message: "Timed out waiting for outbound job drain; continuing")
    }

    private func isFreshSessionRepairError(_ error: RatchetError) -> Bool {
        // Inbound: these are routed to orphan-resend (not receive-side ASR).
        // Outbound: still use handleFreshOutboundRepair to insert an initiating row.
        [
            .initialMessageNotReceived,
            .rootKeyIsNil,
            .missingCipherText,
            .sendingKeyIsNil
        ].contains(error)
    }

    private func isInboundSessionDesyncError(_ error: RatchetError) -> Bool {
        [
            .headerDecryptFailed,
            .receivingKeyIsNil,
            .receivingHeaderKeyIsNil
        ].contains(error)
    }

    private func freshSessionFailureClass(_ error: RatchetError) -> String {
        switch error {
        case .initialMessageNotReceived:
            return "ratchet.initialMessageNotReceived"
        case .rootKeyIsNil:
            return "ratchet.rootKeyIsNil"
        case .missingCipherText:
            return "ratchet.missingCipherText"
        case .sendingKeyIsNil:
            return "ratchet.sendingKeyIsNil"
        case .stateUninitialized:
            return "ratchet.stateUninitialized"
        default:
            return "ratchet.freshSessionRepair"
        }
    }

    private func inboundSessionDesyncFailureClass(_ error: RatchetError) -> String {
        switch error {
        case .headerDecryptFailed:
            return "ratchet.headerDecryptFailed"
        case .receivingKeyIsNil:
            return "ratchet.receivingKeyIsNil"
        case .receivingHeaderKeyIsNil:
            return "ratchet.receivingHeaderKeyIsNil"
        default:
            return "ratchet.sessionDesync"
        }
    }

    private func requestPeerResendIfAllowed(
        message: InboundTaskMessage,
        failureClass: String,
        session: PQSSession
    ) async -> Bool {
        guard session.isViable else {
            logger.log(
                level: .info,
                message: "pqs.recovery.resendRequestSkipped reason=nonViable failureClass=\(failureClass) sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId)")
            return false
        }
        let submissionCount = await session.resendRequestSubmissionCount(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId,
            failedMessageId: message.sharedMessageId)
        if submissionCount >= PQSSessionConstants.peerResendRequestMaxSubmissions {
            // Lost-NACK safety: the peer is expected to answer; when our NACK never
            // arrives, stop asking for this sharedId only. Never open receive ASR.
            await session.clearPendingResends(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId,
                messageIds: [message.sharedMessageId])
            logger.log(
                level: .warning,
                message: "pqs.recovery.resendRequestExhausted failureClass=\(failureClass) sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) attempts=\(submissionCount)")
            let newlyTerminal = await session.markInboundContentUnrecoverable(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId,
                sharedId: message.sharedMessageId)
            if newlyTerminal {
                DecryptFailureAuditLog.log(
                    "pqs.recovery.contentUnrecoverable sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId.uuidString) reason=resendSubmissionCap attempts=\(submissionCount)")
                await session.sessionDelegate?.inboundContentUnrecoverable(
                    senderSecretName: message.senderSecretName,
                    senderDeviceId: message.senderDeviceId,
                    sharedMessageId: message.sharedMessageId)
            }
            return false
        }

        guard await session.canSendPeerResendRequest(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId,
            failedMessageId: message.sharedMessageId)
        else {
            logger.log(
                level: .info,
                message: "pqs.recovery.resendRequestSkipped reason=cooldown failureClass=\(failureClass) sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId)")
            return false
        }

        do {
            try await session.requestMessageResend(
                sharedMessageId: message.sharedMessageId,
                senderName: message.senderSecretName,
                senderDeviceId: message.senderDeviceId)
            await session.markPeerResendRequestSent(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId,
                failedMessageId: message.sharedMessageId)
            logger.log(
                level: .info,
                message: "pqs.recovery.resendRequestSubmitted failureClass=\(failureClass) sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId)")
            return true
        } catch {
            logger.log(
                level: .warning,
                message: "pqs.recovery.resendRequestFailed failureClass=\(failureClass) sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) error=\(error)")
            return false
        }
    }

    private func handleInvalidSignature(
        message: InboundTaskMessage,
        job: JobModel,
        cache: SessionCache,
        session: PQSSession
    ) async throws -> JobProcessingOutcome {
        let failureClass = "signature.invalidSignature"
        if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
            auditInboundDecryptFailure(
                message: message,
                failureClass: failureClass,
                action: "invalidSignatureRecovery",
                suppressed: true)
            logger.log(level: .info, message: "Suppressing repeated \(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
            try await cache.deleteJob(job)
            return .deleted
        }

        auditInboundDecryptFailure(
            message: message,
            failureClass: failureClass,
            action: "invalidSignatureRecovery")
        await session.markInboundFailure(message, failureClass: failureClass)

        guard let context = await session.sessionContext else {
            logger.log(level: .error, message: "invalidSignature for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId); dropping without recovery because session context is unavailable")
            try await cache.deleteJob(job)
            return .deleted
        }

        let isSelf = message.senderSecretName == context.sessionUser.secretName
        if isSelf {
            logger.log(
                level: .error,
                message: "invalidSignature from same-account deviceId=\(message.senderDeviceId); treating as linked-device compromise observation")

            let currentDevice = try? context.activeUserConfiguration
                .getVerifiedDevices()
                .first(where: { $0.deviceId == context.sessionUser.deviceId })

            if currentDevice?.isMasterDevice == true {
                await session.sessionDelegate?.linkedDeviceReportedPotentialCompromise(
                    deviceId: message.senderDeviceId,
                    intentId: nil)
            } else {
                do {
                    _ = try await session.emitSessionReestablishment(
                        kind: .linkedDeviceCompromiseObserved,
                        recipient: .personalMessage,
                        scope: .personal)
                } catch {
                    logger.log(level: .warning, message: "Failed to send linked-device compromise observation after \(failureClass): \(error)")
                }
            }

            try await cache.deleteJob(job)
            return .deleted
        }

        logger.log(
            level: .error,
            message: "invalidSignature for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId); discarding message and requesting bounded resend")

        let didRequestResend = await requestPeerResendIfAllowed(
            message: message,
            failureClass: failureClass,
            session: session)

        if !didRequestResend {
            await session.deferPeerResendUntilReestablished(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId,
                failedMessageId: message.sharedMessageId,
                failureClass: failureClass)
            // Same single-flight treatment as fresh-session repair: only the episode
            // leader emits (forced past the cooldown, since the episode is the gate),
            // and a suppressed emit must not close the episode.
            let isEpisodeLeader = await session.tryBeginReestablishmentEpisode(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId)
            if !isEpisodeLeader {
                logger.log(
                    level: .info,
                    message: "pqs.recovery.coalesced failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) reason=pendingPeerRefresh")
                try await cache.deleteJob(job)
                return .deleted
            }
            do {
                let emitted = try await session.emitSessionReestablishment(
                    kind: .peerRefresh,
                    recipient: .nickname(message.senderSecretName),
                    scope: .peerDevice(
                        secretName: message.senderSecretName,
                        deviceId: message.senderDeviceId),
                    forceReemit: true)
                if !emitted {
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.reestablishmentSuppressed reason=coalescedPending failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId)")
                }
            } catch let sessionError as PQSSession.SessionErrors where sessionError == .peerSigningKeyOutOfSync {
                await reportPeerSigningKeyOutOfSync(message: message, session: session)
            } catch {
                await session.markRecoveryEmitBlocked(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId)
                await session.endReestablishmentEpisode(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId)
                logger.log(level: .warning, message: "Failed to emit peerRefresh after \(failureClass): \(error)")
            }
        }

        try await cache.deleteJob(job)
        return .deleted
    }

    // Receive-side Automatic Session Reset for decrypt-failure classes was removed
    // (orphan-resend). Documented product ASR remains only on missingOneTimeKey
    // bootstrap (`replaceOTKBatchThenPeerRefresh`) and invalidSignature handling.

    private func handlePeerSigningKeyOutOfSync(
        message: InboundTaskMessage,
        job: JobModel,
        cache: SessionCache,
        session: PQSSession
    ) async throws -> JobProcessingOutcome {
        await reportPeerSigningKeyOutOfSync(message: message, session: session)
        try await cache.deleteJob(job)
        return .deleted
    }

    /// Trust-blocked recovery: the peer's pinned signing key no longer matches the
    /// advertised bundle, so no lane reset or peerRefresh may proceed until the user
    /// reverifies the contact. Clears the recovery episode and deferred resends for
    /// this device lane so recovery does not stay open against a blocked identity.
    private func reportPeerSigningKeyOutOfSync(
        message: InboundTaskMessage,
        session: PQSSession
    ) async {
        let failureClass = "identity.peerSigningKeyOutOfSync"
        auditInboundDecryptFailure(
            message: message,
            failureClass: failureClass,
            action: "notifyPeerAccountIdentityChanged")
        logger.log(
            level: .error,
            message: "pqs.recovery.blocked.trust failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) action=notifyPeerAccountIdentityChanged")

        _ = await session.takePendingResendsAfterReestablishment(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId)
        await session.endReestablishmentEpisode(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId)
        await session.markInboundFailure(message, failureClass: failureClass)
        await session.quarantineInboundFailure(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId,
            messageId: message.sharedMessageId)
        await session.sessionDelegate?.peerAccountIdentityChanged(
            secretName: message.senderSecretName,
            deviceId: message.senderDeviceId,
            failedSharedMessageId: message.sharedMessageId)
    }

    private func handleFreshOutboundRepair(
        message: OutboundTaskMessage,
        error: RatchetError,
        job: JobModel,
        cache: SessionCache,
        session: PQSSession,
        symmetricKey: SymmetricKey
    ) async throws -> JobProcessingOutcome {
        guard let props = await message.recipientIdentity.props(symmetricKey: symmetricKey) else {
            logger.log(level: .error, message: "Fresh outbound repair failed: missing recipient props for \(error)")
            await noteResendReplayDropped(sharedId: message.sharedId, reason: "outboundRepairMissingProps")
            try await cache.deleteJob(job)
            return .deleted
        }

        // Encrypt on the active session; on orphaned/broken outbound state,
        // insert a fresh initiating (state-less) row and retry. An open peerRefresh
        // episode must not drop user ciphertext — peerRefresh itself does not wipe
        // the lane, and silent delete was parking "sent" messages forever.
        let isRecoveryCriticalControl = isRecoveryCriticalControlMessage(message.message)

        logger.log(
            level: .warning,
            message: "\(freshSessionFailureClass(error)) while sending to \(props.secretName) deviceId=\(props.deviceId); resetting SessionIdentity and retrying once")

        let isPendingResendReplay = pendingResendReplayBySharedId[message.sharedId] != nil
        if isPendingResendReplay {
            // Orphan-resend replays must not be deleted by the outbound repair
            // cooldown — that drops the orphan-resend recovery wave with no wire frame.
            await session.clearOutboundReconciliationCooldown(
                secretName: props.secretName,
                deviceId: props.deviceId)
        }
        let canAttempt = await session.canAttemptReconciliation(
            sender: props.secretName,
            deviceId: props.deviceId,
            flow: .outbound)
        let canBypassCooldown = isRecoveryCriticalControl && consumeOutboundControlRepairBypass(sharedId: message.sharedId)

        guard canAttempt || canBypassCooldown else {
            if isRecoveryCriticalControl {
                await session.endReestablishmentEpisode(
                    sender: props.secretName,
                    deviceId: props.deviceId)
                logger.log(
                    level: .warning,
                    message: "pqs.recovery.criticalControlRepairExhausted failureClass=\(freshSessionFailureClass(error)) recipient=\(props.secretName) deviceId=\(props.deviceId) sharedId=\(message.sharedId) action=closeEpisode")
            }
            logger.log(level: .warning, message: "Suppressing repeated fresh outbound repair for \(props.secretName) (\(props.deviceId))")
            // Failed repair must not leave a state-less preferred zombie (dogfood poison).
            try? await session.demoteZombieStateLessActives(
                secretName: props.secretName,
                deviceId: props.deviceId)
            await noteResendReplayDropped(sharedId: message.sharedId, reason: "outboundRepairSuppressed")
            try await cache.deleteJob(job)
            return .deleted
        }

        if !canAttempt, canBypassCooldown {
            logger.log(
                level: .info,
                message: "Allowing one cooldown-bypassed outbound repair for recovery control sharedId=\(message.sharedId) to \(props.secretName) (\(props.deviceId))")
        }

        do {
            // Prefer the orphan-resend initiating session when replaying; a second
            // `outboundRepair` reset would mint yet another SessionID mid-wave.
            let replacement: SessionIdentity
            if let protectedId = await session.orphanResendInitiatingSessionId(
                secretName: props.secretName,
                deviceId: props.deviceId
            ),
               let existing = try await cache.fetchSessionIdentities().first(where: { $0.id == protectedId }),
               let existingProps = await existing.props(symmetricKey: symmetricKey),
               existingProps.secretName == props.secretName,
               existingProps.deviceId == props.deviceId,
               !existingProps.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            {
                replacement = existing
                logger.log(
                    level: .info,
                    message: "pqs.recovery.outboundRepairReusedOrphanResend recipient=\(props.secretName) deviceId=\(props.deviceId) sessionId=\(existing.id)")
            } else {
                // Outbound repair only needs a fresh state-less row. Consuming an OTK
                // here races with inbound recovery and depletes the peer's pool.
                replacement = try await session.resetSessionIdentityForFreshSession(
                    secretName: props.secretName,
                    deviceId: props.deviceId,
                    sendOneTimeIdentities: false,
                    reason: "outboundRepair")
                if isPendingResendReplay {
                    await session.markOrphanResendInitiatingSession(
                        secretName: props.secretName,
                        deviceId: props.deviceId,
                        sessionId: replacement.id)
                }
            }
            await session.markReconciliationAttempt(
                sender: props.secretName,
                deviceId: props.deviceId,
                flow: .outbound)

            let retry = EncryptableTask(
                task: .writeMessage(OutboundTaskMessage(
                    message: message.message,
                    recipientIdentity: replacement,
                    localId: message.localId,
                    sharedId: message.sharedId,
                    isPersistedOutbound: message.isPersistedOutbound
                )),
                priority: .urgent)

            try await cache.deleteJob(job)
            try await feedTask(retry, session: session)
            return .deleted
        } catch {
            if isRecoveryCriticalControl {
                await session.endReestablishmentEpisode(
                    sender: props.secretName,
                    deviceId: props.deviceId)
            }
            logger.log(level: .error, message: "Fresh outbound repair failed for \(props.secretName) (\(props.deviceId)): \(error)")
            try? await session.demoteZombieStateLessActives(
                secretName: props.secretName,
                deviceId: props.deviceId)
            await noteResendReplayDropped(sharedId: message.sharedId, reason: "outboundRepairFailed")
            try await cache.deleteJob(job)
            return .deleted
        }
    }

    private func isRecoveryCriticalControlMessage(_ message: CryptoMessage) -> Bool {
        guard let transportInfo = message.transportInfo,
              let event = try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo)
        else {
            return false
        }

        switch event {
        case .sessionReestablishment, .requestMessageResend:
            return true
        // The unavailable notice is what terminates the requester's resend loop;
        // dropping it during an open episode would keep the peer looping.
        case .messageResendUnavailable:
            return true
        // OTK handshake is the gate for delete→re-add. A single failed encrypt must
        // not burn the outbound repair cooldown and leave bootstrap stranded.
        case .synchronizeOneTimeKeys:
            return true
        case .linkedDeviceReprovisioning, .refreshOneTimeKeys, .publishedOneTimeKeysReplenished:
            return false
        }
    }

    private func consumeOutboundControlRepairBypass(sharedId: String, now: Date = Date()) -> Bool {
        let cutoff = now.addingTimeInterval(-outboundControlRepairBypassTTL)
        outboundControlRepairBypassAtBySharedId = outboundControlRepairBypassAtBySharedId.filter { _, createdAt in
            createdAt > cutoff
        }

        guard outboundControlRepairBypassAtBySharedId[sharedId] == nil else {
            return false
        }

        outboundControlRepairBypassAtBySharedId[sharedId] = now
        return true
    }
    
}


/// A protocol that defines the interface for custom task execution delegates.
///
/// This protocol allows for custom implementation of task processing logic,
/// primarily used for testing purposes but can also be used for specialized
/// task handling in production environments.
///
/// - Note: This protocol is `Sendable` to ensure thread safety when used
///   across concurrent contexts. Implementations must be thread-safe.
///
/// - Important: The default implementation in `TaskProcessor` handles most
///   production use cases. Custom delegates are typically only needed for:
///   - Unit testing and mocking
///   - Specialized task processing requirements
///   - Debugging and instrumentation
///
/// - Example Usage:
///   ```swift
///   class CustomTaskDelegate: TaskSequenceDelegate {
///       func performRatchet(task: TaskType, session: PQSSession) async throws {
///           // Custom task processing logic
///           switch task {
///           case .writeMessage(let writeTask):
///               // Handle write message task
///               try await session.writeMessage(writeTask)
///           case .streamMessage(let streamTask):
///               // Handle stream message task
///               try await session.streamMessage(streamTask)
///           }
///       }
///   }
///   ```
///
/// - Thread Safety: Implementations must be thread-safe as this protocol
///   may be called from concurrent contexts within the `TaskProcessor`.
protocol TaskSequenceDelegate: Sendable {
    
    /// Performs the ratchet operation for a given task within the session context.
    ///
    /// This method is responsible for executing the actual cryptographic ratchet
    /// operation associated with the task. The implementation should handle all
    /// necessary cryptographic operations, error handling, and session state
    /// management for the specific task type.
    ///
    /// - Parameters:
    ///   - task: The `TaskType` to be processed. This can be a write message task,
    ///     stream message task, or other task types defined in the system.
    ///   - session: The `PQSSession` context providing access to cryptographic
    ///     operations, identity management, and session state.
    ///
    /// - Throws: Any error that occurs during task execution, including but not
    ///   limited to:
    ///   - Cryptographic errors (encryption/decryption failures)
    ///   - Network errors (connection issues, timeouts)
    ///   - Session errors (invalid session state, missing identities)
    ///   - Task-specific errors (invalid message format, recipient not found)
    ///
    /// - Note: This method is called asynchronously and should not block the
    ///   calling thread. Long-running operations should be properly awaited.
    ///
    /// - Important: Implementations should ensure proper error propagation
    ///   to allow the `TaskProcessor` to handle failures appropriately.
    ///   Errors thrown from this method will be caught and handled by the
    ///   task processing loop.
    ///
    /// - Example Implementation:
    ///   ```swift
    ///   func performRatchet(task: TaskType, session: PQSSession) async throws {
    ///       switch task {
    ///       case .writeMessage(let writeTask):
    ///           // Validate the task
    ///           guard let recipient = writeTask.recipientIdentity else {
    ///               throw TaskProcessor.JobProcessorErrors.missingIdentity
    ///           }
    ///
    ///           // Perform the ratchet operation
    ///           try await session.writeMessage(writeTask)
    ///
    ///       case .streamMessage(let streamTask):
    ///           // Handle stream message processing
    ///           try await session.streamMessage(streamTask)
    ///       }
    ///   }
    ///   ```
    func performRatchet(
        task: TaskType,
        session: PQSSession
    ) async throws
}

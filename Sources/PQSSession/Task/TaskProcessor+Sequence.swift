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
            for job in try await cache.fetchJobs() {
                try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
            }
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
    
    private func loadFromCache(
        cache: SessionCache,
        symmetricKey: SymmetricKey
    ) async throws {
        for job in try await cache.fetchJobs() {
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
                let failureClass = "ratchet.maxSkippedHeadersExceeded"

                // Never retry the same failed ciphertext locally. Preserve the
                // still-shared outbound ratchet for the peerRefresh request; reset only
                // after its correlated response has been transported.
                return try await handleFreshSessionRepair(
                    message: message,
                    failureClass: failureClass,
                    job: job,
                    cache: cache,
                    session: session,
                    diagnostic: "compromiseRotation=false")
            case .writeMessage(let message):
                logger.log(level: .error, message: "MaxSkippedHeadersExceeded for writeMessage to recipient: \(message.message.recipient)")
                try await cache.deleteJob(job)
            }
            
        } catch let ratchetError as RatchetError where isFreshSessionRepairError(ratchetError) {
            switch props.task.task {
            case .streamMessage(let message):
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
                return try await handleFreshSessionRepair(
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
                let failureClass = "ratchet.decryptionFailed"
                if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
                    return try await handleFreshSessionRepair(
                        message: message,
                        failureClass: "ratchet.decryptionFailed.repeated",
                        job: job,
                        cache: cache,
                        session: session,
                        diagnostic: "repeatFailureClass=\(failureClass)")
                }

                let didRequestResend = await requestPeerResendIfAllowed(
                    message: message,
                    failureClass: failureClass,
                    session: session)
                auditInboundDecryptFailure(
                    message: message,
                    failureClass: failureClass,
                    action: didRequestResend ? "resendRequested" : "resendSkipped")
                await session.markInboundFailure(message, failureClass: failureClass)
                try await cache.deleteJob(job)
                return .deleted
            case .writeMessage(let message):
                logger.log(level: .error, message: "decryptionFailed for writeMessage to recipient: \(message.message.recipient)")
                try await cache.deleteJob(job)
            }

        } catch let ratchetError as RatchetError where isInboundSessionDesyncError(ratchetError) {
            switch props.task.task {
            case .streamMessage(let message):
                return try await handleFreshSessionRepair(
                    message: message,
                    failureClass: inboundSessionDesyncFailureClass(ratchetError),
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                logger.log(level: .error, message: "\(ratchetError) for writeMessage to recipient: \(message.message.recipient)")
                try await cache.deleteJob(job)
            }

        } catch let ratchetError as RatchetError where ratchetError == .expiredKey {
            switch props.task.task {
            case .streamMessage(let message):
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
                try await cache.deleteJob(job)
            }

        } catch let ratchetError as RatchetError where ratchetError == .missingOneTimeKey {
            switch props.task.task {
            case .streamMessage(let message):
                let failureClass = "ratchet.missingOneTimeKey"
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
                if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
                    auditInboundDecryptFailure(
                        message: message,
                        failureClass: failureClass,
                        suppressed: true)
                    logger.log(level: .info, message: "Suppressing repeated \(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
                    try await cache.deleteJob(job)
                    return .deleted
                }

                // Pending replay IDs outlive the single-flight episode. Only a live
                // episode (or an active responder bootstrap hold, which owns the lane)
                // may suppress a new event-driven repair attempt.
                let hasOpenOTKEpisode = await session.hasOpenReestablishmentEpisode(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId)
                let hasOTKResponderHold = await session.hasRecentInboundPeerRefreshBootstrap(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId)
                if hasOpenOTKEpisode || hasOTKResponderHold {
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
                        message: "pqs.recovery.coalesced failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) reason=\(hasOpenOTKEpisode ? "pendingPeerRefresh" : "responderBootstrapHold")")
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
                Task {
                    let curveReplaced = await session.refreshOneTimeKeysTask(policy: .replacePublishedBatch)
                    let mlKEMReplaced = await session.refreshMLKEMOneTimeKeysTask(policy: .replacePublishedBatch)
                    guard curveReplaced && mlKEMReplaced else {
                        logger.log(
                            level: .error,
                            message: "pqs.recovery.failed failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) reason=otkBatchReplacementFailed")
                        await session.endReestablishmentEpisode(
                            sender: message.senderSecretName,
                            deviceId: message.senderDeviceId)
                        return
                    }

                    let mySecretName = await session.sessionContext?.sessionUser.secretName
                    let isSelf = message.senderSecretName == mySecretName

                    do {
                        _ = try await session.emitSessionReestablishment(
                            kind: .peerRefresh,
                            recipient: isSelf ? .personalMessage : .nickname(message.senderSecretName),
                            scope: isSelf
                                ? .personalDevice(deviceId: message.senderDeviceId)
                                : .peerDevice(
                                    secretName: message.senderSecretName,
                                    deviceId: message.senderDeviceId),
                            forceReemit: true)
                        logger.log(
                            level: .info,
                            message: "pqs.recovery.reestablishmentQueued kind=peerRefresh failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId)")
                    } catch let sessionError as PQSSession.SessionErrors where sessionError == .peerSigningKeyOutOfSync {
                        await self.reportPeerSigningKeyOutOfSync(message: message, session: session)
                    } catch {
                        logger.log(
                            level: .warning,
                            message: "pqs.recovery.reestablishmentFailed kind=peerRefresh failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) error=\(error)")
                    }
                }

                try await cache.deleteJob(job)
                return .deleted
            case .writeMessage(let message):
                logger.log(level: .error, message: "missingOneTimeKey for writeMessage to recipient: \(message.message.recipient)")
                try await cache.deleteJob(job)
            }
        } catch let cryptoError as CryptoKitError {
            switch props.task.task {
            case .streamMessage(let message):
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
                // Same as maxSkipped: unilateral reset cannot decrypt the failed
                // ciphertext; always fall through to peerRefresh + deferred resend.
                return try await handleFreshSessionRepair(
                    message: message,
                    failureClass: "crypto.bodyDecryptionFailed",
                    job: job,
                    cache: cache,
                    session: session,
                    diagnostic: "error=\(cryptoError)")
            case .writeMessage(let message):
                logger.log(level: .error, message: "CryptoKitError for writeMessage to recipient: \(message.message.recipient) — \(cryptoError)")
                try await cache.deleteJob(job)
            }
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .sessionDecryptionError {
            switch props.task.task {
            case .streamMessage(let message):
                let failureClass = "payload.sessionDecryptionError"
                if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
                    auditInboundDecryptFailure(
                        message: message,
                        failureClass: failureClass,
                        suppressed: true)
                    logger.log(level: .info, message: "Suppressing repeated \(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
                    try await cache.deleteJob(job)
                    return .deleted
                }

                let didRequestResend = await requestPeerResendIfAllowed(
                    message: message,
                    failureClass: failureClass,
                    session: session)
                auditInboundDecryptFailure(
                    message: message,
                    failureClass: failureClass,
                    action: didRequestResend ? "resendRequested" : "resendSkipped")
                if didRequestResend {
                    await session.markInboundFailure(message, failureClass: failureClass)
                }
                try await cache.deleteJob(job)
                return .deleted
            case .writeMessage(let message):
                logger.log(level: .error, message: "sessionDecryptionError for writeMessage to recipient: \(message.message.recipient)")
                try await cache.deleteJob(job)
            }
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .peerSigningKeyOutOfSync {
            switch props.task.task {
            case .streamMessage(let message):
                return try await handlePeerSigningKeyOutOfSync(
                    message: message,
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                logger.log(
                    level: .error,
                    message: "peerSigningKeyOutOfSync for writeMessage to recipient: \(message.message.recipient); dropping until peer identity is reverified")
            }
            try await cache.deleteJob(job)
            return .deleted
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .signingKeyOutOfSync {
            logger.log(level: .error, message: "signingKeyOutOfSync during job processing; child device likely needs reprovisioning from master")
            switch props.task.task {
            case .streamMessage:
                do {
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
                return try await handleInvalidSignature(
                    message: message,
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                logger.log(level: .error, message: "invalidSignature for writeMessage to recipient: \(message.message.recipient)")
                try await cache.deleteJob(job)
            }
        } catch {
            if case .writeMessage(let message) = props.task.task,
               pendingOutboundTransportBySharedId[message.sharedId] != nil {
                return try await deferPendingOutboundTransportRetry(
                    job: job,
                    props: props,
                    cache: cache,
                    symmetricKey: symmetricKey,
                    error: error)
            }
            logger.log(level: .error, message: "Unhandled error during job processing: \(error)")
            try await cache.deleteJob(job)
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
        guard await session.isAwaitingInboundPeerRatchetHandshake(
            secretName: message.senderSecretName,
            deviceId: message.senderDeviceId) else {
            return nil
        }

        let maxAttempts = 24
        guard props.attempts < maxAttempts else { return nil }

        logger.log(
            level: .info,
            message: "Re-queueing inbound message until peer OTK handshake completes for \(message.senderSecretName) deviceId=\(message.senderDeviceId) failureClass=\(failureClass) pass=\(props.attempts + 1)/\(maxAttempts)")

        var updatedProps = props
        updatedProps.attempts += 1
        _ = try await job.updateProps(symmetricKey: symmetricKey, props: updatedProps)
        try await cache.updateJob(job)
        if await !jobConsumer.deque.isEmpty {
            await jobConsumer.feedConsumer(job, priority: .background)
            return .deferredToBack
        }
        return .paused
    }

    private func tryDeferInboundDuringContactBootstrap(
        message: InboundTaskMessage,
        error: RatchetError,
        job: JobModel,
        props: JobModel.UnwrappedProps,
        cache: SessionCache,
        session: PQSSession,
        symmetricKey: SymmetricKey
    ) async throws -> JobProcessingOutcome? {
        guard isFreshSessionRepairError(error) || error == .decryptionFailed else { return nil }
        return try await tryDeferInboundUntilPeerRatchetReady(
            message: message,
            job: job,
            props: props,
            cache: cache,
            session: session,
            symmetricKey: symmetricKey,
            failureClass: freshSessionFailureClass(error))
    }

    private func deferPendingOutboundTransportRetry(
        job: JobModel,
        props: JobModel.UnwrappedProps,
        cache: SessionCache,
        symmetricKey: SymmetricKey,
        error: Error
    ) async throws -> JobProcessingOutcome {
        var updatedProps = props
        updatedProps.attempts += 1
        updatedProps.delayedUntil = Date().addingTimeInterval(min(0.10 * Double(updatedProps.attempts), 1.0))
        _ = try await job.updateProps(symmetricKey: symmetricKey, props: updatedProps)
        try await cache.updateJob(job)
        try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
        if let recoveryLog = recoveryTransportSendFailureLog(
            props: props,
            attempt: updatedProps.attempts,
            error: error)
        {
            logger.log(level: .warning, message: .init(stringLiteral: recoveryLog))
        } else {
            logger.log(
                level: .warning,
                message: "Deferred outbound transport retry for pending signed frame attempt=\(updatedProps.attempts): \(error)")
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
        [
            .initialMessageNotReceived,
            .rootKeyIsNil,
            .missingCipherText,
            .sendingKeyIsNil,
            .stateUninitialized
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
            let hasResponderBootstrapHold = await session.hasRecentInboundPeerRefreshBootstrap(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId)
            if hasResponderBootstrapHold {
                logger.log(
                    level: .info,
                    message: "pqs.recovery.coalesced failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) reason=responderBootstrapHold")
                try await cache.deleteJob(job)
                return .deleted
            }
            _ = await session.tryBeginReestablishmentEpisode(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId)
            do {
                _ = try await session.emitSessionReestablishment(
                    kind: .peerRefresh,
                    recipient: .nickname(message.senderSecretName),
                    scope: .peerDevice(
                        secretName: message.senderSecretName,
                        deviceId: message.senderDeviceId))
            } catch let sessionError as PQSSession.SessionErrors where sessionError == .peerSigningKeyOutOfSync {
                await reportPeerSigningKeyOutOfSync(message: message, session: session)
            } catch {
                logger.log(level: .warning, message: "Failed to emit peerRefresh after \(failureClass): \(error)")
            }
        }

        try await cache.deleteJob(job)
        return .deleted
    }

    private func handleFreshSessionRepair(
        message: InboundTaskMessage,
        failureClass: String,
        job: JobModel,
        cache: SessionCache,
        session: PQSSession,
        diagnostic: String? = nil
    ) async throws -> JobProcessingOutcome {
        if await session.shouldSuppressInboundRecoveryFromSender(message.senderSecretName) {
            auditInboundDecryptFailure(
                message: message,
                failureClass: failureClass,
                error: diagnostic,
                action: "dropDeletedPeer",
                suppressed: true,
                metadata: diagnostic.map { ["diagnostic": $0] } ?? [:])
            logger.log(
                level: .info,
                message: "Dropping \(failureClass) for deleted peer \(message.senderSecretName); skipping fresh-session repair")
            try await cache.deleteJob(job)
            return .deleted
        }
        // Pending replay IDs are work to drain after recovery, not a recovery lock.
        // Once the concrete peer-device episode expires, the next failure event must
        // be allowed to establish a fresh session and emit another peerRefresh.
        let hasOpenEpisode = await session.hasOpenReestablishmentEpisode(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId)
        // While this device is the responder of a peer-coordinated bootstrap, a local
        // reset would clobber the lane the peer just prepared and reopen divergence.
        // Failures here are stale ciphertext from before that repair; defer them so
        // the responder-completion drain requests their resend on the healthy lane.
        let hasResponderBootstrapHold = await session.hasRecentInboundPeerRefreshBootstrap(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId)
        if hasOpenEpisode || hasResponderBootstrapHold {
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
                message: "pqs.recovery.coalesced failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) reason=\(hasOpenEpisode ? "pendingPeerRefresh" : "responderBootstrapHold")")
            try await cache.deleteJob(job)
            return .deleted
        }
        if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
            auditInboundDecryptFailure(
                message: message,
                failureClass: failureClass,
                error: diagnostic,
                action: "freshSessionRepairThenDeferredResend",
                suppressed: true,
                metadata: diagnostic.map { ["diagnostic": $0] } ?? [:])
            logger.log(level: .info, message: "Suppressing repeated \(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
            try await cache.deleteJob(job)
            return .deleted
        }

        let diagnosticSuffix = diagnostic.map { " \($0)" } ?? ""
        auditInboundDecryptFailure(
            message: message,
            failureClass: failureClass,
            error: diagnostic,
            action: "freshSessionRepairThenDeferredResend",
            metadata: diagnostic.map { ["diagnostic": $0] } ?? [:])
        logger.log(
            level: .warning,
            message: "pqs.recovery.started failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) action=freshSessionRepairThenDeferredResend\(diagnosticSuffix)")

        // Single-flight: only one peerRefresh leader per peer-device episode.
        let isEpisodeLeader = await session.tryBeginReestablishmentEpisode(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId)
        if !isEpisodeLeader {
            logger.log(
                level: .info,
                message: "Skipping duplicate peerRefresh leader for \(message.senderSecretName) (\(message.senderDeviceId)); reestablishment episode already open")
        }

        let mySecretName = await session.sessionContext?.sessionUser.secretName
        let isSelf = message.senderSecretName == mySecretName
        let recipient: MessageRecipient = isSelf ? .personalMessage : .nickname(message.senderSecretName)
        let scope: ControlEventScope = isSelf
            ? .personalDevice(deviceId: message.senderDeviceId)
            : .peerDevice(
                secretName: message.senderSecretName,
                deviceId: message.senderDeviceId)
        let hadPendingRecovery = await session.hasPendingResendAfterReestablishment(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId)

        await session.deferPeerResendUntilReestablished(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId,
            failedMessageId: message.sharedMessageId,
            failureClass: failureClass)
        await session.markInboundFailure(message, failureClass: failureClass)
        logger.log(
            level: .info,
            message: "pqs.recovery.deferred failureClass=\(failureClass) sharedId=\(message.sharedMessageId) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) waitingFor=peerRefresh")

        do {
            let emitted = try await session.emitSessionReestablishment(
                kind: .peerRefresh,
                recipient: recipient,
                scope: scope,
                forceReemit: !hadPendingRecovery)
            if !emitted {
                logger.log(
                    level: .info,
                    message: "pqs.recovery.reestablishmentSuppressed reason=coalescedPending failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId)")
            } else {
                logger.log(
                    level: .info,
                    message: "pqs.recovery.reestablishmentQueued kind=peerRefresh failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId)")
            }
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .peerSigningKeyOutOfSync {
            await reportPeerSigningKeyOutOfSync(message: message, session: session)
        } catch {
            logger.log(
                level: .warning,
                message: "pqs.recovery.reestablishmentFailed kind=peerRefresh failureClass=\(failureClass) sender=\(message.senderSecretName) deviceId=\(message.senderDeviceId) sharedId=\(message.sharedMessageId) error=\(error)")
        }

        try await cache.deleteJob(job)
        return .deleted
    }

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
            try await cache.deleteJob(job)
            return .deleted
        }

        // A coordinated peerRefresh exchange owns this lane: either we emitted a
        // device-scoped request (open episode) or the peer bootstrapped us as the
        // responder. Resetting here would clobber that freshly coordinated state and
        // every subsequent ciphertext from the peer, restarting the divergence loop.
        // Drop the job; the exchange repairs the lane and deferred resends drain it.
        let hasOpenEpisode = await session.hasOpenReestablishmentEpisode(
            sender: props.secretName,
            deviceId: props.deviceId)
        let hasResponderBootstrapHold = await session.hasRecentInboundPeerRefreshBootstrap(
            sender: props.secretName,
            deviceId: props.deviceId)
        if hasOpenEpisode || hasResponderBootstrapHold {
            logger.log(
                level: .warning,
                message: "pqs.recovery.outboundRepairSkipped failureClass=\(freshSessionFailureClass(error)) recipient=\(props.secretName) deviceId=\(props.deviceId) sharedId=\(message.sharedId) reason=\(hasOpenEpisode ? "openReestablishmentEpisode" : "responderBootstrapHold")")
            try await cache.deleteJob(job)
            return .deleted
        }

        logger.log(
            level: .warning,
            message: "\(freshSessionFailureClass(error)) while sending to \(props.secretName) deviceId=\(props.deviceId); resetting SessionIdentity and retrying once")

        let canAttempt = await session.canAttemptReconciliation(
            sender: props.secretName,
            deviceId: props.deviceId,
            flow: .outbound)
        let isRecoveryCriticalControl = isRecoveryCriticalControlMessage(message.message)
        let canBypassCooldown = isRecoveryCriticalControl && consumeOutboundControlRepairBypass(sharedId: message.sharedId)

        guard canAttempt || canBypassCooldown else {
            logger.log(level: .warning, message: "Suppressing repeated fresh outbound repair for \(props.secretName) (\(props.deviceId))")
            try await cache.deleteJob(job)
            return .deleted
        }

        if !canAttempt, canBypassCooldown {
            logger.log(
                level: .info,
                message: "Allowing one cooldown-bypassed outbound repair for recovery control sharedId=\(message.sharedId) to \(props.secretName) (\(props.deviceId))")
        }

        do {
            // Outbound repair only needs a fresh state-less row. Consuming an OTK
            // here races with inbound recovery and depletes the peer's pool.
            let replacement = try await session.resetSessionIdentityForFreshSession(
                secretName: props.secretName,
                deviceId: props.deviceId,
                sendOneTimeIdentities: false)
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
            logger.log(level: .error, message: "Fresh outbound repair failed for \(props.secretName) (\(props.deviceId)): \(error)")
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

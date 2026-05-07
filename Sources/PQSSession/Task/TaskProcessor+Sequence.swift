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
            let sleep = delayedUntil.timeIntervalSinceNow
            do {
                try await Task.sleep(nanoseconds: UInt64(sleep * 1_000_000_000))
            } catch {
                // If the task was cancelled while sleeping, just pause and let a future resume reload from cache.
                return .paused
            }
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

                logger.log(
                    level: .warning,
                    message: "\(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId); using fresh SessionIdentity repair without compromise rotation")
                return try await handleFreshSessionRepair(
                    message: message,
                    failureClass: failureClass,
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                logger.log(level: .error, message: "MaxSkippedHeadersExceeded for writeMessage to recipient: \(message.message.recipient)")
                try await cache.deleteJob(job)
            }
            
        } catch let ratchetError as RatchetError where isFreshSessionRepairError(ratchetError) {
            switch props.task.task {
            case .streamMessage(let message):
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

        } catch let ratchetError as RatchetError where ratchetError == .missingOneTimeKey {
            switch props.task.task {
            case .streamMessage(let message):
                let failureClass = "ratchet.missingOneTimeKey"
                if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
                    logger.log(level: .info, message: "Suppressing repeated \(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
                    try await cache.deleteJob(job)
                    return .deleted
                }

                logger.log(level: .warning, message: "missingOneTimeKey for sender \(message.senderSecretName) — replacing OTK batch and notifying peer to refresh")
                let curveReplaced = await session.refreshOneTimeKeysTask(policy: .replaceCurrentDeviceBatch)
                let mlKEMReplaced = await session.refreshMLKEMOneTimeKeysTask(policy: .replaceCurrentDeviceBatch)
                if !curveReplaced || !mlKEMReplaced {
                    logger.log(level: .error, message: "OTK batch replacement failed; cannot recover from missingOneTimeKey")
                }

                let mySecretName = await session.sessionContext?.sessionUser.secretName
                let isSelf = message.senderSecretName == mySecretName

                await session.markInboundFailure(message, failureClass: failureClass)
                await session.deferPeerResendUntilReestablished(
                    sender: message.senderSecretName,
                    deviceId: message.senderDeviceId,
                    failedMessageId: message.sharedMessageId,
                    failureClass: failureClass)
                logger.log(
                    level: .info,
                    message: "Deferred resend request for sharedMessageId=\(message.sharedMessageId) until peerRefresh completes for \(message.senderSecretName) deviceId=\(message.senderDeviceId)")

                do {
                    _ = try await session.emitSessionReestablishment(
                        kind: .peerRefresh,
                        recipient: isSelf ? .personalMessage : .nickname(message.senderSecretName),
                        scope: isSelf ? .personal : .peer(secretName: message.senderSecretName),
                        forceReemit: true)
                } catch {
                    logger.log(level: .warning, message: "Failed to emit peerRefresh after \(failureClass): \(error)")
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
                logger.log(level: .error, message: "Decryption failure (\(cryptoError)) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId) — preparing fresh peer session and deferring resend until reestablishment")
                return try await handleFreshSessionRepair(
                    message: message,
                    failureClass: "crypto.bodyDecryptionFailed",
                    job: job,
                    cache: cache,
                    session: session)
            case .writeMessage(let message):
                logger.log(level: .error, message: "CryptoKitError for writeMessage to recipient: \(message.message.recipient) — \(cryptoError)")
                try await cache.deleteJob(job)
            }
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .sessionDecryptionError {
            switch props.task.task {
            case .streamMessage(let message):
                let failureClass = "payload.sessionDecryptionError"
                if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
                    logger.log(level: .info, message: "Suppressing repeated \(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
                    try await cache.deleteJob(job)
                    return .deleted
                }

                let didRequestResend = await requestPeerResendIfAllowed(
                    message: message,
                    failureClass: failureClass,
                    session: session)
                if didRequestResend {
                    await session.markInboundFailure(message, failureClass: failureClass)
                }
                try await cache.deleteJob(job)
                return .deleted
            case .writeMessage(let message):
                logger.log(level: .error, message: "sessionDecryptionError for writeMessage to recipient: \(message.message.recipient)")
                try await cache.deleteJob(job)
            }
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

    private func isFreshSessionRepairError(_ error: RatchetError) -> Bool {
        [
            .initialMessageNotReceived,
            .rootKeyIsNil,
            .missingCipherText,
            .sendingKeyIsNil,
            .stateUninitialized
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
                message: "Skipping resend request after \(failureClass); cooldown active sharedMessageId=\(message.sharedMessageId)")
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
            return true
        } catch {
            logger.log(
                level: .warning,
                message: "Failed to request resend after \(failureClass) for sharedMessageId=\(message.sharedMessageId): \(error)")
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
            logger.log(level: .info, message: "Suppressing repeated \(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
            try await cache.deleteJob(job)
            return .deleted
        }

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
            do {
                _ = try await session.emitSessionReestablishment(
                    kind: .peerRefresh,
                    recipient: .nickname(message.senderSecretName),
                    scope: .peer(secretName: message.senderSecretName))
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
        retryOriginalAfterReset: Bool = true
    ) async throws -> JobProcessingOutcome {
        if await session.shouldSuppressInboundFailure(message, failureClass: failureClass) {
            logger.log(level: .info, message: "Suppressing repeated \(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
            try await cache.deleteJob(job)
            return .deleted
        }

        logger.log(
            level: .warning,
            message: "\(failureClass) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId); repairing peer SessionIdentity")

        let canReset = await session.canAttemptReconciliation(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId,
            flow: .inbound)
        var resetSucceeded = false
        if canReset {
            await session.markReconciliationAttempt(
                sender: message.senderSecretName,
                deviceId: message.senderDeviceId,
                flow: .inbound)
            do {
                _ = try await session.resetSessionIdentityForFreshSession(
                    secretName: message.senderSecretName,
                    deviceId: message.senderDeviceId,
                    sendOneTimeIdentities: true)
                resetSucceeded = true
            } catch {
                logger.log(level: .warning, message: "Fresh session reset failed for \(message.senderSecretName) (\(message.senderDeviceId)): \(error)")
            }
        } else {
            logger.log(level: .info, message: "Skipping inbound SessionIdentity reset for \(message.senderSecretName) (\(message.senderDeviceId)); reconciliation cooldown is active")
        }

        if resetSucceeded && retryOriginalAfterReset {
            logger.log(level: .info, message: "Retrying inbound message after fresh SessionIdentity reset for \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
            try await cache.deleteJob(job)
            try await feedTask(
                EncryptableTask(
                    task: .streamMessage(message),
                    priority: .urgent),
                session: session)
            return .deleted
        }

        if resetSucceeded {
            logger.log(level: .info, message: "Prepared fresh SessionIdentity for repair controls to \(message.senderSecretName) deviceId=\(message.senderDeviceId)")
        }

        await session.markInboundFailure(message, failureClass: failureClass)

        let mySecretName = await session.sessionContext?.sessionUser.secretName
        let isSelf = message.senderSecretName == mySecretName
        let recipient: MessageRecipient = isSelf ? .personalMessage : .nickname(message.senderSecretName)
        let scope: ControlEventScope = isSelf ? .personal : .peer(secretName: message.senderSecretName)

        await session.deferPeerResendUntilReestablished(
            sender: message.senderSecretName,
            deviceId: message.senderDeviceId,
            failedMessageId: message.sharedMessageId,
            failureClass: failureClass)
        logger.log(
            level: .info,
            message: "Deferred resend request for sharedMessageId=\(message.sharedMessageId) until peerRefresh completes for \(message.senderSecretName) deviceId=\(message.senderDeviceId)")

        do {
            _ = try await session.emitSessionReestablishment(
                kind: .peerRefresh,
                recipient: recipient,
                scope: scope,
                freshOutboundRepair: resetSucceeded ? nil : (
                    secretName: message.senderSecretName,
                    deviceId: message.senderDeviceId,
                    failureClass: failureClass))
        } catch {
            logger.log(level: .warning, message: "Failed to emit peerRefresh after \(failureClass): \(error)")
        }

        try await cache.deleteJob(job)
        return .deleted
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
            let replacement = try await session.resetSessionIdentityForFreshSession(
                secretName: props.secretName,
                deviceId: props.deviceId,
                sendOneTimeIdentities: true)
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
        case .linkedDeviceReprovisioning, .synchronizeOneTimeKeys, .refreshOneTimeKeys:
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

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
            //This means that no where in our current session identity can we find the key on the ring for our permitted range. We could be at Index 4, we try up to 10, so that would be 4...14 with no key being able to decrypt our message. This could be an abuse and or a potential attack. So We must rotate our keys on compromise. This means that the master device must full rotate their sessionIdentity. We will keep an archived SessionIdentity temporarily for other messages that may not have been received yet that are still encrypted with the valid key ring. After a given period of time we will them delete the archived Session Identity; This will cause a different failure since we rotated the master's SessionIdentity already. At that point we will then need to request resend message with out a rotation so that the sender will get the latest Session Identities during the encryption flow.
            
            //If we are not a master device and hit this error me must tell the master device to rotate on compromise. Afterwards we also need to receive a message that tells us to rotate and then request resend message.
            
            //If we are the master device then we rotate on compromise, notify child devices that they need to rotate also which needs to be done after the master rotates so that we can sign the keys properly.
            
            switch props.task.task {
            case .streamMessage(let message):
                
                //1. Archive current SessionIdentity:
                try await session.createInactiveSessionSnapshot(for: message.senderSecretName, policy: .archive)
                
                //2. Rotate due to potential compromise
                guard let context = await session.sessionContext else { return .failed }
                
                guard let currentDevice = try context.activeUserConfiguration
                    .getVerifiedDevices()
                    .first(where: { $0.deviceId == context.sessionUser.deviceId }) else {
                    throw PQSSession.SessionErrors.invalidDeviceIdentity
                }
                
                if currentDevice.isMasterDevice {
                    try await session.rotateKeysOnPotentialCompromise()
                } else {
                    _ = try await session.emitSessionReestablishment(
                        kind: .linkedDeviceCompromiseObserved,
                        recipient: .personalMessage,
                        scope: .personal
                    )
                    do {
                        try await session.rotateCurrentDeviceKeys()
                    } catch let sessionError as PQSSession.SessionErrors where sessionError == .signingKeyOutOfSync {
                        logger.log(level: .warning, message: "signingKeyOutOfSync on child device during key rotation recovery; requesting reprovisioning from master")
                        _ = try await session.emitSessionReestablishment(
                            kind: .linkedDeviceCompromiseObserved,
                            recipient: .personalMessage,
                            scope: .personal
                        )
                        try await cache.deleteJob(job)
                        return .deleted
                    }
                }
                try await session.requestMessageResend(
                    sharedMessageId: message.sharedMessageId,
                    senderName: message.senderSecretName,
                    senderDeviceId: message.senderDeviceId)
                try await cache.deleteJob(job)
                return .deleted
            case .writeMessage(let message):
                logger.log(level: .error, message: "MaxSkippedHeadersExceeded for writeMessage to recipient: \(message.message.recipient)")
                try await cache.deleteJob(job)
            }
            
        } catch let ratchetError as RatchetError where ratchetError == .missingOneTimeKey {
            switch props.task.task {
            case .streamMessage(let message):
                logger.log(level: .warning, message: "missingOneTimeKey for sender \(message.senderSecretName) — replacing OTK batch and notifying peer to refresh")
                let curveReplaced = await session.refreshOneTimeKeysTask(policy: .replaceCurrentDeviceBatch)
                let mlKEMReplaced = await session.refreshMLKEMOneTimeKeysTask(policy: .replaceCurrentDeviceBatch)
                if !curveReplaced || !mlKEMReplaced {
                    logger.log(level: .error, message: "OTK batch replacement failed; cannot recover from missingOneTimeKey")
                }
                _ = try await session.emitSessionReestablishment(
                    kind: .peerRefresh,
                    recipient: .nickname(message.senderSecretName),
                    scope: .peer(secretName: message.senderSecretName)
                )
                try await cache.deleteJob(job)
                return .deleted
            case .writeMessage(let message):
                logger.log(level: .error, message: "missingOneTimeKey for writeMessage to recipient: \(message.message.recipient)")
                try await cache.deleteJob(job)
            }
        } catch let cryptoError as CryptoKitError {
            switch props.task.task {
            case .streamMessage(let message):
                logger.log(level: .error, message: "Decryption failure (\(cryptoError)) for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId) — notifying peer to refresh")
                let mySecretName = await session.sessionContext?.sessionUser.secretName
                let isSelf = message.senderSecretName == mySecretName
                let recipient: MessageRecipient = isSelf ? .personalMessage : .nickname(message.senderSecretName)
                let scope: ControlEventScope = isSelf ? .personal : .peer(secretName: message.senderSecretName)
                _ = try await session.emitSessionReestablishment(
                    kind: .peerRefresh,
                    recipient: recipient,
                    scope: scope
                )
                try await cache.deleteJob(job)
                return .deleted
            case .writeMessage(let message):
                logger.log(level: .error, message: "CryptoKitError for writeMessage to recipient: \(message.message.recipient) — \(cryptoError)")
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
                logger.log(level: .error, message: "invalidSignature for sender \(message.senderSecretName) deviceId=\(message.senderDeviceId) — notifying peer to refresh keys")
                let mySecretName = await session.sessionContext?.sessionUser.secretName
                let isSelf = message.senderSecretName == mySecretName
                let recipient: MessageRecipient = isSelf ? .personalMessage : .nickname(message.senderSecretName)
                let scope: ControlEventScope = isSelf ? .personal : .peer(secretName: message.senderSecretName)
                _ = try await session.emitSessionReestablishment(
                    kind: .peerRefresh,
                    recipient: recipient,
                    scope: scope
                )
                try await cache.deleteJob(job)
                return .deleted
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


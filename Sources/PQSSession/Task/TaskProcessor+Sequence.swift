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
            
        } catch let jobError as JobProcessorErrors where jobError == .missingIdentity {
            try await cache.deleteJob(job)
            return .deleted
            
        } catch let cryptoError as CryptoKitError where cryptoError == .authenticationFailure {
            try await cache.deleteJob(job)
            return .deleted
            
        } catch let sessionError as PQSSession.SessionErrors
                    where sessionError == .invalidKeyId || sessionError == .cannotFindOneTimeKey {
            try await cache.deleteJob(job)
            return .deleted
            
        } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
            try await cache.deleteJob(job)
            // Treat as a critical job failure, but do not crash the whole processor / bubble to callers.
            logger.log(level: .error, message: "Job ratchet error: \(ratchetError)")
            throw ratchetError
            
        } catch let ratchetError as RatchetError where ratchetError == .stateUninitialized {
            // Common right after key rotation / session reestablishment.
            // Instead of crashing the whole processor, reschedule the job with a small bounded backoff.
            //
            // This enables "no delay" post-rotation delivery in practice by allowing convergence as
            // identities/one-time keys propagate, while still bounding retries via `attempts`.
            guard var currentProps = await job.props(symmetricKey: symmetricKey) else {
                try await cache.deleteJob(job)
                return .deleted
            }
            
            currentProps.attempts += 1
            
            // Cap retries to avoid infinite loops.
            if currentProps.attempts >= 8 {
                try await cache.deleteJob(job)
                logger.log(level: .error, message: "Job ratchet error (exceeded retries): \(ratchetError)")
                return .deleted
            }
            
            // Exponential backoff (50ms, 100ms, 200ms, 250ms, ...), capped at 250ms.
            let base: TimeInterval = 0.05
            let maxDelay: TimeInterval = 0.25
            let delay = min(maxDelay, base * pow(2.0, Double(currentProps.attempts - 1)))
            currentProps.delayedUntil = Date().addingTimeInterval(delay)
            
            _ = try await job.updateProps(symmetricKey: symmetricKey, props: currentProps)
            try await cache.updateJob(job)
            
            logger.log(level: .warning, message: "Job ratchet error: \(ratchetError) (attempt \(currentProps.attempts)) - retrying after \(delay)s")
            return .failed
            
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
            try await cache.deleteJob(job)
            // Treat as a critical job failure, but do not crash the whole processor / bubble to callers.
            logger.log(level: .error, message: "Job session error: \(sessionError)")
            throw sessionError
            
        } catch {
            logger.log(level: .error, message: "Job error: \(error)")
            // Keep the job in cache for now (retry semantics are handled elsewhere / future improvements).
            return .failed
        }
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


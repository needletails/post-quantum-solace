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

extension TaskProcessor {
    /// Increments and returns the internal sequence identifier atomically.
    /// Since TaskProcessor is an actor, this is already thread-safe.
    ///
    /// - Returns: The next sequence ID as an `Int`.
    func incrementId() async -> Int {
        sequenceId += 1
        return sequenceId
    }
    
    /// Feeds an encryptable task into the session's job queue for processing.
    ///
    /// This method prepares a job by encrypting and caching it, then attempts to execute the sequence of tasks.
    /// Since TaskProcessor is an actor, all operations are automatically serialized.
    ///
    /// - Parameters:
    ///   - task: The task to be encrypted and queued.
    ///   - session: The `PQSSession` context for processing.
    /// - Throws: An error if the cache is unavailable or task setup fails.
    public func feedTask(
        _ task: EncryptableTask,
        session: PQSSession
    ) async throws {
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }

        let sequenceId = await incrementId()
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let job = try createJobModel(sequenceId: sequenceId, task: task, symmetricKey: symmetricKey)

        try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
        try await cache.createJob(job)
        
        // Start processing if not already running
        // This ensures jobs are processed even if the previous processor finished
        if !isRunning {
            try await attemptTaskSequence(session: session)
        }
    }

    /// Loads and optionally processes a job or all cached jobs using the provided session and symmetric key.
    ///
    /// - Parameters:
    ///   - job: An optional specific `JobModel` to load; if `nil`, all cached jobs will be loaded.
    ///   - cache: The session's job cache.
    ///   - symmetricKey: The symmetric key for decrypting job properties.
    ///   - session: The optional `PQSSession` used to process the jobs after loading.
    func loadTasks(
        _ job: JobModel? = nil,
        cache: SessionCache,
        symmetricKey: SymmetricKey,
        session: PQSSession? = nil
    ) async throws {
        if let job {
            try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
            if let session {
                try await attemptTaskSequence(session: session)
            }
        } else {
            // Load all jobs first, then start processing once
            for job in try await cache.fetchJobs() {
                try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
            }
            // Start processing after all jobs are loaded
            if let session {
                try await attemptTaskSequence(session: session)
            }
        }
    }

    /// Updates the task processor's internal running state.
    ///
    /// - Parameter isRunning: A boolean indicating if task processing is active.
    func setIsRunning(_ isRunning: Bool) async {
        self.isRunning = isRunning
    }
    
    /// Atomically checks if not running and sets running to true.
    /// Returns true if the operation was successful (was not running and now is running).
    /// Returns false if already running.
    func trySetRunning() async -> Bool {
        if !isRunning {
            isRunning = true
            return true
        }
        return false
    }
    
    /// Processes tasks from the job queue using a serial, cancellation-aware execution model.
    ///
    /// This function leverages `NeedleTailAsyncSequence` to manage job execution order and cancellation.
    /// It handles error cases such as missing identities and authentication failures, and removes corrupted or outdated jobs.
    ///
    /// - Parameter session: The `PQSSession` context for executing jobs.
    /// - Throws: Any error that occurs during task processing or session access.
    func attemptTaskSequence(session: PQSSession) async throws {
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }

        // Fix race condition: Use atomic check-and-set to prevent multiple concurrent job processors
        guard await trySetRunning() else {
            if await jobConsumer.deque.isEmpty {
                await jobConsumer.gracefulShutdown()
                await setIsRunning(false)
            }
            return
        }

        logger.log(level: .debug, message: "Starting job queue")
        let symmetricKey = try await session.getDatabaseSymmetricKey()

        for try await result in NeedleTailAsyncSequence(consumer: jobConsumer) {
            switch result {
            case let .success(job):
                guard let props = await job.props(symmetricKey: symmetricKey) else {
                    throw PQSSession.SessionErrors.propsError
                }

                logger.log(level: .debug, message: "Running job \(props.sequenceId)")

                // Check session viability before processing
                guard session.isViable else {
                    logger.log(level: .debug, message: "Skipping job \(props.sequenceId) as we are offline")
                    // Job remains in cache for later processing when session becomes viable
                    await jobConsumer.gracefulShutdown()
                    await setIsRunning(false)
                    return
                }

                if let delayedUntil = props.delayedUntil, delayedUntil >= Date() {
                    logger.log(level: .debug, message: "Task was delayed into the future")
                    // Job remains in cache for later processing when delay expires

                    if await jobConsumer.deque.isEmpty {
                        await jobConsumer.gracefulShutdown()
                        await setIsRunning(false)
                        return
                    }
                    break
                }

                do {
                    logger.log(level: .debug, message: "Executing Job \(props.sequenceId)")
                    // Custom task delegate may be used, but usually only for testing
                    if let taskDelegate {
                        try await taskDelegate.performRatchet(task: props.task.task, session: session)
                    } else {
                        try await performRatchet(task: props.task.task, session: session)
                    }
                    do {
                        try await cache.deleteJob(job)
                    } catch {
                        logger.log(level: .warning, message: "Failed to delete job after successful execution: \(error)")
                    }

                } catch let jobError as JobProcessorErrors where jobError == .missingIdentity {
                    logger.log(level: .error, message: "Removing Job due to: \(jobError)")
                    do {
                        try await cache.deleteJob(job)
                    } catch {
                        logger.log(level: .warning, message: "Failed to delete job after missing identity error: \(error)")
                    }

                } catch let cryptoError as CryptoKitError where cryptoError == .authenticationFailure {
                    logger.log(level: .error, message: "Removing Job due to: \(cryptoError)")
                    do {
                        try await cache.deleteJob(job)
                    } catch {
                        logger.log(level: .warning, message: "Failed to delete job after authentication failure: \(error)")
                    }

                } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidKeyId || sessionError == .cannotFindOneTimeKey {
                    // Note: If we are invalid due to a race condition between the server and client we can optionally resend
                    logger.log(level: .error, message: "Removing Job due to: \(sessionError)")
                    do {
                        try await cache.deleteJob(job)
                    } catch {
                        logger.log(level: .warning, message: "Failed to delete job after session error: \(error)")
                    }
                } catch {
                    
                    logger.log(level: .error, message: "Job error \(error)")

                    if await jobConsumer.deque.isEmpty || Task.isCancelled {
                        await jobConsumer.gracefulShutdown()
                        await setIsRunning(false)
                        return
                    }
                }

                if await jobConsumer.deque.isEmpty {
                    // Check if there are more jobs in cache that need to be loaded
                    let cachedJobs = try await cache.fetchJobs()
                    if !cachedJobs.isEmpty {
                        // Load remaining jobs from cache
                        for job in cachedJobs {
                            try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
                        }
                        // Continue processing - don't shut down yet
                    } else {
                        // No more jobs in cache or deque, safe to shut down
                        await jobConsumer.gracefulShutdown()
                        await setIsRunning(false)
                    }
                }

            case .consumed:
                await setIsRunning(false)
                try await loadTasks(nil, cache: cache, symmetricKey: symmetricKey, session: session)
            }
        }

        // After loop ends, check if there are more jobs to process
        if await jobConsumer.deque.isEmpty {
            let cachedJobs = try await cache.fetchJobs()
            if !cachedJobs.isEmpty {
                // Load remaining jobs from cache
                for job in cachedJobs {
                    try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
                }
                // Restart processing if we loaded jobs
                let dequeIsEmpty = await jobConsumer.deque.isEmpty
                if !dequeIsEmpty {
                    try await attemptTaskSequence(session: session)
                }
            } else {
                await jobConsumer.gracefulShutdown()
                await setIsRunning(false)
            }
        }
    }
    


    /// Errors specific to job processing operations.
    enum JobProcessorErrors: Error {
        /// Indicates that a job references a missing session identity.
        case missingIdentity
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


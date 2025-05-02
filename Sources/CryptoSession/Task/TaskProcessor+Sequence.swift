//
//  TaskProcessor+Sequence.swift
//  crypto-session
//
//  Created by Cole M on 4/8/25.
//

import Crypto
import Foundation
import NeedleTailAsyncSequence
import SessionModels

extension TaskProcessor {
    
    /// Feeds an encryptable task into the session's job queue for processing.
    ///
    /// This method prepares a job by encrypting and caching it, then attempts to execute the sequence of tasks.
    ///
    /// - Parameters:
    ///   - task: The task to be encrypted and queued.
    ///   - session: The `CryptoSession` context for processing.
    /// - Throws: An error if the cache is unavailable or task setup fails.
    public func feedTask(
        _ task: EncrytableTask,
        session: CryptoSession
    ) async throws {
        guard let cache = await session.cache else {
            throw CryptoSession.SessionErrors.databaseNotInitialized
        }
        
        let sequenceId = await incrementId()
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let job = try createJobModel(sequenceId: sequenceId, task: task, symmetricKey: symmetricKey)
        
        try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
        try await cache.createJob(job)
        try await attemptTaskSequence(session: session)
    }
    
    /// Loads and optionally processes a job or all cached jobs using the provided session and symmetric key.
    ///
    /// - Parameters:
    ///   - job: An optional specific `JobModel` to load; if `nil`, all cached jobs will be loaded.
    ///   - cache: The session's job cache.
    ///   - symmetricKey: The symmetric key for decrypting job properties.
    ///   - session: The optional `CryptoSession` used to process the jobs after loading.
    func loadTasks(
        _ job: JobModel? = nil,
        cache: SessionCache,
        symmetricKey: SymmetricKey,
        session: CryptoSession? = nil
    ) async throws {
        if let job = job {
            try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
            if let session = session {
                try await attemptTaskSequence(session: session)
            }
        } else {
            for job in try await cache.readJobs() {
                try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
                if let session = session {
                    try await attemptTaskSequence(session: session)
                }
            }
        }
    }
    
    /// Updates the task processor’s internal running state.
    ///
    /// - Parameter isRunning: A boolean indicating if task processing is active.
    func setIsRunning(_ isRunning: Bool) async {
        self.isRunning = isRunning
    }
    
    /// Increments and returns the internal sequence identifier.
    ///
    /// - Returns: The next sequence ID as an `Int`.
    func incrementId() async -> Int {
        sequenceId += 1
        return sequenceId
    }
    
    /// Processes tasks from the job queue using a serial, cancellation-aware execution model.
    ///
    /// This function leverages `NeedleTailAsyncSequence` to manage job execution order and cancellation.
    /// It handles error cases such as missing identities and authentication failures, and removes corrupted or outdated jobs.
    ///
    /// - Parameter session: The `CryptoSession` context for executing jobs.
    /// - Throws: Any error that occurs during task processing or session access.
    func attemptTaskSequence(session: CryptoSession) async throws {
        guard let cache = await session.cache else {
            throw CryptoSession.SessionErrors.databaseNotInitialized
        }
        
        guard !isRunning else {
            if await jobConsumer.deque.isEmpty {
                await jobConsumer.gracefulShutdown()
                await setIsRunning(false)
            }
            return
        }
        
        logger.log(level: .debug, message: "Starting job queue")
        await setIsRunning(true)
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        
        for try await result in NeedleTailAsyncSequence(consumer: jobConsumer) {
            switch result {
            case .success(let job):
                guard let props = await job.props(symmetricKey: symmetricKey) else {
                    throw CryptoSession.SessionErrors.propsError
                }
                
                logger.log(level: .debug, message: "Running job \(props.sequenceId)")
                
                guard session.isViable else {
                    logger.log(level: .debug, message: "Skipping job \(props.sequenceId) as we are offline")
                    await jobConsumer.gracefulShutdown()
                    await setIsRunning(false)
                    try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
                    return
                }
                
                if let delayedUntil = props.delayedUntil, delayedUntil >= Date() {
                    logger.log(level: .debug, message: "Task was delayed into the future")
                    try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
                    
                    if await jobConsumer.deque.isEmpty {
                        await jobConsumer.gracefulShutdown()
                        await setIsRunning(false)
                        return
                    }
                    break
                }
                
                do {
                    logger.log(level: .debug, message: "Executing Job \(props.sequenceId)")
                    try await performRatchet(task: props.task.task, session: session)
                    try await cache.removeJob(job)
                    
                } catch let jobError as JobProcessorErrors where jobError == .missingIdentity {
                    try await cache.removeJob(job)
                    
                } catch let cryptoError as CryptoKitError where cryptoError == .authenticationFailure {
                    try await cache.removeJob(job)
                    
                } catch {
                    logger.log(level: .error, message: "Job error \(error)")
                    
                    if await jobConsumer.deque.isEmpty || Task.isCancelled {
                        await jobConsumer.gracefulShutdown()
                        await setIsRunning(false)
                        return
                    }
                }
                
                if await jobConsumer.deque.isEmpty {
                    await jobConsumer.gracefulShutdown()
                    await setIsRunning(false)
                }
                
            case .consumed:
                await setIsRunning(false)
                try await loadTasks(nil, cache: cache, symmetricKey: symmetricKey)
            }
        }
        
        if await jobConsumer.deque.isEmpty {
            await jobConsumer.gracefulShutdown()
            await setIsRunning(false)
        }
    }
    
    /// Errors specific to job processing operations.
    enum JobProcessorErrors: Error {
        /// Indicates that a job references a missing session identity.
        case missingIdentity
    }
}

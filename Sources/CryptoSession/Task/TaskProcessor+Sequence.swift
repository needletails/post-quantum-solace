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
    
    public func feedTask(_
                          task: EncrytableTask,
                          session: CryptoSession) async throws {
        guard let cache = await session.cache else {
            throw CryptoSession.SessionErrors.databaseNotInitialized
        }
        let sequenceId = await incrementId()
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let job = try createJobModel(
            sequenceId: sequenceId,
            task: task,
            symmetricKey: symmetricKey)
        try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
        try await cache.createJob(job)
        try await attemptTaskSequence(session: session)
    }
    
    func loadTasks(_
                  job: JobModel? = nil,
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
    
    func setIsRunning(_ isRunning: Bool) async {
        self.isRunning = isRunning
    }
    
    func incrementId() async -> Int {
        sequenceId += 1
        return sequenceId
    }
    
    /// This method processes each job via an AsyncSequence that has been arrange per queue requirements. Rather than spinning off an unstructured Task at the root of the call and then a detached task to run jobs. we use 1 child task from the current task running this actor. This allows us to keep track and control of task cancellation. It also helps us to reason about task execution serialization more easily.
    func attemptTaskSequence(session: CryptoSession) async throws {
        guard let cache = await session.cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        if !isRunning {
            self.logger.log(level: .debug, message: "Starting job queue")
            await setIsRunning(true)
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            for try await result in NeedleTailAsyncSequence(consumer: jobConsumer) {
                switch result {
                case .success(let job):
                    
                    guard let props = await job.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
                    self.logger.log(level: .debug, message: "Running job \(props.sequenceId)")
                    
                    if session.isViable == false {
                        self.logger.log(level: .debug, message: "Skipping job \(props.sequenceId) as we are offline")
                        await jobConsumer.gracefulShutdown()
                        await setIsRunning(false)
                        try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
                        return
                    }
                    
                    if let delayedUntil = props.delayedUntil, delayedUntil >= Date() {
                        self.logger.log(level: .debug, message: "Task was delayed into the future")
                        
                        //This is urgent, We want to try this job first always until the designated time arrives. we sort via sequenceId. so old messages are always done first.
                        try await jobConsumer.loadAndOrganizeTasks(job, symmetricKey: symmetricKey)
                        if await jobConsumer.deque.count == 0 {
                            await jobConsumer.gracefulShutdown()
                            await setIsRunning(false)
                            return
                        }
                        break
                    }
                    
                    do {
                        self.logger.log(level: .debug, message: "Executing Job \(props.sequenceId)")
                        
                        try await performRatchet(
                            task: props.task.task,
                            session: session)
                        
                        try await cache.removeJob(job)
                    } catch let jobError as JobProcessorErrors {
                        //If we are a missing identity at this point it means we have an old job with an identity that never sent to an old device. Just delete the job.
                        
                        if jobError == .missingIdentity {
                            try await cache.removeJob(job)
                        }
                    } catch let cryptoError as CryptoKitError {
                        
                        //Could have been corrupted, just remove
                        if cryptoError == .authenticationFailure {
                            try await cache.removeJob(job)
                        }
                    } catch {
                        self.logger.log(level: .error, message: "Job error \(error)")
                        
                        //TODO: Work in delay logic on fail
                        
                        if await jobConsumer.deque.count == 0 || Task.isCancelled {
                            await jobConsumer.gracefulShutdown()
                            await setIsRunning(false)
                            return
                        }
                    }
                    
                    if await jobConsumer.deque.count == 0 {
                        await jobConsumer.gracefulShutdown()
                        await setIsRunning(false)
//                        try await loadTasks(nil, cache: cache, symmetricKey: symmetricKey)
                    }
                case .consumed:
                    await setIsRunning(false)
                    try await loadTasks(nil, cache: cache, symmetricKey: symmetricKey)
                }
            }
        }
        if await jobConsumer.deque.count == 0 {
            await jobConsumer.gracefulShutdown()
            await setIsRunning(false)
        }
    }
    
    enum JobProcessorErrors: Error {
        case missingIdentity
    }
    
}

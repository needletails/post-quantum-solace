//
//  NeedleTailAsyncConsumer+Extension.swift
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
//  This file contains extensions to NeedleTailAsyncConsumer for task management
//  and sequence-based job organization in the Post-Quantum Solace session system.
//  It provides functionality for loading, organizing, and inserting tasks with
//  proper sequence ordering based on cryptographic properties.
//

import NeedleTailAsyncSequence
import SessionModels
#if os(Android) || os(Linux)
@preconcurrency import Crypto
#else
import Crypto
#endif

/// Extension to NeedleTailAsyncConsumer providing task management capabilities
/// for the Post-Quantum Solace session system.
///
/// This extension adds functionality for:
/// - Loading and organizing tasks with proper sequence ordering
/// - Inserting tasks into the consumer's deque based on sequence IDs
/// - Maintaining cryptographic integrity during task processing
extension NeedleTailAsyncConsumer {
    
    /// Loads and organizes a job into the consumer's task queue with proper sequence ordering.
    ///
    /// This method determines whether to feed the job directly to the consumer or insert it
    /// into the existing queue based on the current state and the job's sequence properties.
    /// To ensure FIFO ordering and prevent race conditions, this method always uses
    /// sequence-based insertion, even when the deque appears empty.
    ///
    /// - Parameters:
    ///   - job: The `JobModel` to be loaded and organized. Must conform to the generic type `T`.
    ///   - symmetricKey: The `SymmetricKey` used for decrypting job properties and determining
    ///     sequence ordering.
    ///
    /// - Throws:
    ///   - `PQSSession.SessionErrors.propsError`: When the job's properties cannot be decrypted
    ///     or are invalid.
    ///   - Any errors thrown by the underlying `insertSequence` method.
    ///
    /// - Note: This method is asynchronous and should be called from an async context.
    ///   The job will be processed with standard priority.
    ///
    /// - Example:
    ///   ```swift
    ///   let consumer = NeedleTailAsyncConsumer<JobModel>()
    ///   let job = JobModel(...)
    ///   let key = SymmetricKey(size: .bits256)
    ///   try await consumer.loadAndOrganizeTasks(job, symmetricKey: key)
    ///   ```
    func loadAndOrganizeTasks(_ job: JobModel, symmetricKey: SymmetricKey) async throws {
        guard let props = await job.props(symmetricKey: symmetricKey) else {
            throw PQSSession.SessionErrors.propsError
        }

        guard let typedJob = job as? T else {
            throw PQSSession.SessionErrors.propsError
        }
        
        let taskJob = TaskJob(item: typedJob, priority: .standard)
        
        // Always use sequence-based insertion to ensure FIFO ordering and prevent race conditions
        await insertSequence(
            taskJob,
            sequenceId: props.sequenceId,
            symmetricKey: symmetricKey
        )
    }

    /// Inserts a task job into the deque at the appropriate position based on sequence ordering.
    ///
    /// This private method maintains the integrity of the task sequence by inserting new jobs
    /// at the correct position based on their sequence ID. Jobs are ordered from lowest to
    /// highest sequence ID to ensure proper processing order.
    ///
    /// - Parameters:
    ///   - taskJob: The `TaskJob<T>` to be inserted into the deque.
    ///   - sequenceId: The sequence identifier used to determine the insertion position.
    ///     Lower sequence IDs are processed before higher ones.
    ///   - symmetricKey: The `SymmetricKey` used for decrypting existing job properties
    ///     to determine their sequence IDs for comparison.
    ///
    /// - Note: This method is asynchronous and performs cryptographic operations to
    ///   decrypt job properties for sequence comparison. The insertion maintains the
    ///   deque's ordered state based on sequence IDs.
    ///
    /// - Implementation Details:
    ///   - Searches for the first job with a sequence ID greater than or equal to the new job
    ///   - If no such job is found, the new job is inserted at the end of the deque
    ///   - Uses `firstAsyncIndex(where:)` for efficient async searching
    ///   - Maintains the deque's internal consistency during insertion
    ///   - The entire operation is atomic to prevent race conditions
    private func insertSequence(_ taskJob: TaskJob<T>, sequenceId: Int, symmetricKey: SymmetricKey) async {
        // Since NeedleTailAsyncConsumer is an actor, all operations are atomic
        // Find the index where the new job should be inserted
        let index = await deque.firstAsyncIndex(where: {
            guard let jobModel = $0.item as? JobModel,
                  let props = await jobModel.props(symmetricKey: symmetricKey) else {
                return false
            }
            let currentJobSequenceId = props.sequenceId
            return currentJobSequenceId >= sequenceId // Find the first job with a sequence ID greater than or equal to the new job
        }) ?? deque.count // If no such index is found, use the end of the deque

        // Insert the new job at the found index
        // This operation is atomic since NeedleTailAsyncConsumer is an actor
        deque.insert(taskJob, at: index)
    }
    
    /// Gracefully shuts down the consumer by clearing the deque and stopping processing.
    ///
    /// This method is called when the task processor needs to stop processing jobs,
    /// such as during session shutdown or when transitioning to an offline state.
    /// It ensures that the consumer's internal state is properly cleaned up.
    ///
    /// - Note: This method is asynchronous and should be called from an async context.
    ///   After calling this method, the consumer should not be used for new tasks
    ///   until it is properly reinitialized.
    func gracefulShutdown() async {
        // Clear the deque to stop processing
        deque.removeAll()
    }
}

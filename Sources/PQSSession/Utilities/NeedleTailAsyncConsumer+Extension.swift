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
import Crypto
import NeedleTailAsyncSequence
import SessionModels

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
    /// When the deque is empty, the job is fed directly. Otherwise, it's inserted at the
    /// appropriate position based on its sequence ID to maintain proper ordering.
    ///
    /// - Parameters:
    ///   - job: The `JobModel` to be loaded and organized. Must conform to the generic type `T`.
    ///   - symmetricKey: The `SymmetricKey` used for decrypting job properties and determining
    ///     sequence ordering.
    ///
    /// - Throws:
    ///   - `PQSSession.SessionErrors.propsError`: When the job's properties cannot be decrypted
    ///     or are invalid.
    ///   - Any errors thrown by the underlying `feedConsumer` or `insertSequence` methods.
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

        // We are an empty deque and are not a background or delayed task
        if deque.isEmpty {
            await feedConsumer(job as! T, priority: .standard)
        } else {
            let taskJob = TaskJob(item: job as! T, priority: .standard)
            await insertSequence(
                taskJob,
                sequenceId: props.sequenceId,
                symmetricKey: symmetricKey
            )
        }
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
    private func insertSequence(_ taskJob: TaskJob<T>, sequenceId: Int, symmetricKey: SymmetricKey) async {
        // Find the index where the new job should be inserted
        let index = await deque.firstAsyncIndex(where: {
            let currentJobSequenceId = await ($0.item as! JobModel).props(symmetricKey: symmetricKey)!.sequenceId
            return currentJobSequenceId >= sequenceId // Find the first job with a sequence ID greater than or equal to the new job
        }) ?? deque.count // If no such index is found, use the end of the deque

        // Insert the new job at the found index
        deque.insert(taskJob, at: index)
    }
}

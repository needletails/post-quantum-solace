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
import Crypto

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

        // Enqueue dedupe: a persisted job can be offered from more than one path
        // at once (direct `feedTask` racing a reconnect bulk reload). The deque
        // check here is atomic within the consumer actor, so the same JobModel
        // can never sit in the deque twice — a duplicate enqueue would run the
        // job twice and send the same frame twice.
        if deque.contains(where: { ($0.item as? JobModel)?.id == job.id }) {
            return
        }

        // Honor EncryptableTask.priority so user ciphertext (.urgent) is not
        // head-of-line blocked behind repair/control (.background) work.
        await feedConsumer(typedJob, priority: props.task.priority)
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

//
//  CryptoExecutor.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-04-19.
//
//  Copyright (c) 2025 NeedleTail Organization. All rights reserved.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//
//  The CryptoExecutor is responsible for executing cryptographic operations
//  on a dedicated dispatch queue to ensure thread safety and performance
//  isolation for sensitive cryptographic computations.
//

import Dispatch
import NeedleTailAsyncSequence

/**
 * A thread-safe executor for cryptographic operations that provides
 * both task-based and serial execution modes.
 *
 * The `CryptoExecutor` ensures that all cryptographic operations are
 * performed on a dedicated dispatch queue, preventing interference
 * with other system operations and maintaining consistent performance
 * characteristics for security-critical computations.
 *
 * ## Usage
 *
 * ```swift
 * // Create a dedicated queue for crypto operations
 * let cryptoQueue = DispatchQueue(label: "com.needletail.crypto", qos: .userInitiated)
 * let executor = CryptoExecutor(queue: cryptoQueue)
 *
 * // Execute a cryptographic job
 * executor.enqueue {
 *     // Perform cryptographic operations here
 *     let encrypted = try encrypt(data: messageData, with: key)
 *     return encrypted
 * }
 * ```
 *
 * ## Thread Safety
 *
 * All operations performed through this executor are guaranteed to run
 * on the specified dispatch queue. The executor provides isolation
 * checks to ensure operations are running on the correct queue.
 *
 * ## Performance Considerations
 *
 * - Use a dedicated queue with appropriate QoS level for crypto operations
 * - Consider using `.userInitiated` or `.userInteractive` QoS for real-time operations
 * - The executor supports both task-based and serial execution modes
 *
 * ## Security Notes
 *
 * - Never share the same executor instance across different security contexts
 * - Ensure the dispatch queue is not accessible from other parts of the application
 * - Consider using different executors for different types of cryptographic operations
 */
final class CryptoExecutor: AnyExecutor {
    /**
     * The dispatch queue on which all cryptographic operations are executed.
     *
     * This queue should be dedicated to cryptographic operations and should
     * not be shared with other parts of the application to maintain
     * security isolation.
     */
    let queue: DispatchQueue

    /**
     * Determines whether jobs should be executed as tasks or serial operations.
     *
     * When `true`, jobs are executed as Swift concurrency tasks, which provides
     * better integration with the Swift concurrency system. When `false`,
     * jobs are executed as serial operations on the dispatch queue.
     *
     * Default value is `true` for better performance and integration.
     */
    let shouldExecuteAsTask: Bool

    /**
     * Initializes a new crypto executor with the specified queue and execution mode.
     *
     * - Parameters:
     *   - queue: The dispatch queue on which cryptographic operations will be executed.
     *            Should be dedicated to crypto operations for security isolation.
     *   - shouldExecuteAsTask: Whether to execute jobs as Swift concurrency tasks.
     *                          Defaults to `true` for better performance.
     *
     * - Note: It's recommended to use a dedicated queue with appropriate QoS level
     *         (e.g., `.userInitiated`) for cryptographic operations.
     */
    init(queue: DispatchQueue, shouldExecuteAsTask: Bool = true) {
        self.queue = queue
        self.shouldExecuteAsTask = shouldExecuteAsTask
    }

    /**
     * Creates an unowned task executor for use with Swift concurrency.
     *
     * This method returns an `UnownedTaskExecutor` that can be used to
     * execute jobs as Swift concurrency tasks while maintaining the
     * thread safety guarantees of the crypto executor.
     *
     * - Returns: An unowned task executor that delegates to this crypto executor.
     */
    func asUnownedTaskExecutor() -> UnownedTaskExecutor {
        UnownedTaskExecutor(ordinary: self)
    }

    /**
     * Verifies that the current execution context is on the correct dispatch queue.
     *
     * This method performs a runtime check to ensure that the calling code
     * is executing on the queue associated with this crypto executor.
     * If the check fails, the application will crash with a precondition failure.
     *
     * Use this method to add explicit queue isolation checks in your code:
     *
     * ```swift
     * func performCryptoOperation() {
     *     cryptoExecutor.checkIsolated()
     *     // Safe to perform crypto operations here
     * }
     * ```
     *
     * - Important: This method will crash the application if called from
     *              the wrong queue. Only use it for debugging or when
     *              you need explicit queue verification.
     */
    func checkIsolated() {
        dispatchPrecondition(condition: .onQueue(queue))
    }

    /**
     * Enqueues a cryptographic job for execution on the dedicated queue.
     *
     * The job will be executed asynchronously on the crypto executor's queue.
     * The execution mode (task-based or serial) is determined by the
     * `shouldExecuteAsTask` property.
     *
     * - Parameter job: The cryptographic job to execute. This is a consuming
     *                  parameter that will be moved into the executor.
     *
     * ## Example
     *
     * ```swift
     * executor.enqueue {
     *     // This closure runs on the crypto queue
     *     let signature = try sign(data: messageData, with: privateKey)
     *     return signature
     * }
     * ```
     *
     * - Note: The job is executed asynchronously, so this method returns
     *         immediately. Use Swift concurrency or completion handlers
     *         to handle the result of the job.
     */
    func enqueue(_ job: consuming ExecutorJob) {
        let job = UnownedJob(job)
        queue.async { [weak self] in
            guard let self else { return }
            if shouldExecuteAsTask {
                job.runSynchronously(on: asUnownedTaskExecutor())
            } else {
                job.runSynchronously(on: asUnownedSerialExecutor())
            }
        }
    }

    /**
     * Creates an unowned serial executor for serial job execution.
     *
     * This method returns an `UnownedSerialExecutor` that can be used to
     * execute jobs serially on the crypto executor's queue. This is useful
     * when you need to ensure that jobs are executed one at a time in
     * the order they were enqueued.
     *
     * - Returns: An unowned serial executor that delegates to this crypto executor.
     */
    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(complexEquality: self)
    }
}

//
//  SessionWorkCoordinator.swift
//  post-quantum-solace
//
//  Bounded FIFO session-work coordinator: fixed worker + pending capacities with
//  async backpressure. Session-owned; enqueue/shutdown are awaited from `PQSSession`.
//

import Foundation

enum SessionLifecyclePhase: Sendable, Equatable {
    case idle
    case running
    case shuttingDown
    case shutDown
}

enum SessionWorkAdmission: Sendable, Equatable {
    case admitted
    case rejected
}

struct SessionWorkMetrics: Sendable, Equatable {
    var pendingCount = 0
    var inFlightCount = 0
    var maxPendingObserved = 0
    var maxInFlightObserved = 0
    var completedCount = 0
}

actor SessionWorkCoordinator {
    private let maxWorkers: Int
    private let maxPending: Int

    private var pending: [@Sendable () async -> Void] = []
    private var capacityWaiters: [CheckedContinuation<Void, Never>] = []
    private var workAvailableWaiters: [CheckedContinuation<Void, Never>] = []
    private var activeWorkers = 0
    private var admissionOpen = false
    private var workerRoot: Task<Void, Never>?
    private(set) var metrics = SessionWorkMetrics()

    init(maxWorkers: Int, maxPending: Int) {
        self.maxWorkers = max(1, maxWorkers)
        self.maxPending = max(1, maxPending)
    }

    func start() {
        guard workerRoot == nil else { return }
        admissionOpen = true
        workerRoot = Task { [weak self] in
            await self?.runWorkers()
        }
    }

    func currentMetrics() -> SessionWorkMetrics {
        metrics
    }

    /// Enqueue work. Suspends when the pending queue is at capacity until a slot
    /// frees or admission closes (rejected).
    func enqueue(_ operation: @escaping @Sendable () async -> Void) async -> SessionWorkAdmission {
        while true {
            guard admissionOpen else { return .rejected }
            if pending.count < maxPending {
                pending.append(operation)
                metrics.pendingCount = pending.count
                metrics.maxPendingObserved = max(metrics.maxPendingObserved, pending.count)
                wakeWorkAvailableWaiter()
                return .admitted
            }
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                capacityWaiters.append(continuation)
            }
        }
    }

    /// Close admission, reject parked producers, cancel workers, await exit.
    func shutdown() async {
        admissionOpen = false
        let capacity = capacityWaiters
        capacityWaiters.removeAll()
        for waiter in capacity {
            waiter.resume()
        }
        pending.removeAll()
        metrics.pendingCount = 0
        let workWaiters = workAvailableWaiters
        workAvailableWaiters.removeAll()
        for waiter in workWaiters {
            waiter.resume()
        }
        let root = workerRoot
        workerRoot = nil
        root?.cancel()
        await root?.value
        activeWorkers = 0
        metrics.inFlightCount = 0
    }

    private func runWorkers() async {
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<maxWorkers {
                group.addTask { [weak self] in
                    await self?.workerLoop()
                }
            }
            await group.waitForAll()
        }
    }

    private func workerLoop() async {
        while !Task.isCancelled {
            guard let work = await takeNext() else { return }
            activeWorkers += 1
            metrics.inFlightCount = activeWorkers
            metrics.maxInFlightObserved = max(metrics.maxInFlightObserved, activeWorkers)
            await work()
            activeWorkers = max(0, activeWorkers - 1)
            metrics.inFlightCount = activeWorkers
            metrics.completedCount += 1
            wakeCapacityWaiter()
        }
    }

    private func takeNext() async -> (@Sendable () async -> Void)? {
        while !Task.isCancelled {
            if !pending.isEmpty {
                let work = pending.removeFirst()
                metrics.pendingCount = pending.count
                wakeCapacityWaiter()
                return work
            }
            if !admissionOpen { return nil }
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                if !pending.isEmpty || !admissionOpen {
                    continuation.resume()
                } else {
                    workAvailableWaiters.append(continuation)
                }
            }
            if pending.isEmpty, !admissionOpen { return nil }
        }
        return nil
    }

    private func wakeWorkAvailableWaiter() {
        guard !workAvailableWaiters.isEmpty else { return }
        workAvailableWaiters.removeFirst().resume()
    }

    private func wakeCapacityWaiter() {
        guard !capacityWaiters.isEmpty else { return }
        capacityWaiters.removeFirst().resume()
    }
}

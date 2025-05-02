//
//  CryptoExecutor.swift
//  crypto-session
//
//  Created by Cole M on 4/19/25.
//
import Dispatch
import NeedleTailAsyncSequence

final class CryptoExecutor: AnyExecutor {
    
    let queue: DispatchQueue
    let shouldExecuteAsTask: Bool
    
    init(queue: DispatchQueue, shouldExecuteAsTask: Bool = true) {
        self.queue = queue
        self.shouldExecuteAsTask = shouldExecuteAsTask
    }
    
    func asUnownedTaskExecutor() -> UnownedTaskExecutor {
        UnownedTaskExecutor(ordinary: self)
    }
    
    func checkIsolated() {
        dispatchPrecondition(condition: .onQueue(queue))
    }
    
    func enqueue(_ job: consuming ExecutorJob) {
        let job = UnownedJob(job)
        self.queue.async { [weak self] in
            guard let self else { return }
            if self.shouldExecuteAsTask {
                job.runSynchronously(on: self.asUnownedTaskExecutor())
            } else {
                job.runSynchronously(on: self.asUnownedSerialExecutor())
            }
        }
    }
    
    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(complexEquality: self)
    }
}

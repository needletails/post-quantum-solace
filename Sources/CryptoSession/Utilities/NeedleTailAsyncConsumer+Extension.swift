//
//  NeedleTailAsyncConsumer+Extension.swift
//  post-quantum-solace
//
//  Created by Cole M on 4/8/25.
//
import NeedleTailAsyncSequence
import Crypto
import SessionModels

extension NeedleTailAsyncConsumer{
    
    func loadAndOrganizeTasks(_ job: JobModel, symmetricKey: SymmetricKey) async throws {
        guard let props = await job.props(symmetricKey: symmetricKey) else { throw CryptoSession.SessionErrors.propsError }
        // We are an empty deque and are not a background or delayed task
        if self.deque.isEmpty {
            await feedConsumer(job as! T, priority: .standard)
        } else {
            let taskJob = TaskJob(item: job as! T, priority: .standard)
            await insertSequence(
                taskJob,
                sequenceId: props.sequenceId,
                symmetricKey: symmetricKey)
        }
    }
    
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

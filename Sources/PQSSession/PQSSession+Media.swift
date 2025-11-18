//
//  PQSSession+Media.swift
//  post-quantum-solace
//
//  Created by Cole M on 11/8/25.
//
import DoubleRatchetKit
import Foundation

extension PQSSession {
    
    
    func createMediaTaskProcessor(_ ratchetConfiguration: RatchetConfiguration? = nil) async throws {
        let processor = TaskProcessor(logger: logger, ratchetConfiguration: ratchetConfiguration)
        
//        try await processor.ratchetManager.ratchetEncrypt(plainText: Data(), sessionId: <#T##UUID#>)
    }
    
    
    func writeMediaTask() async {
//        try await taskProcessor.outboundTask(
//            message: message,
//            cache: cache,
//            symmetricKey: symmetricKey,
//            session: session,
//            sender: mySecretName,
//            type: message.recipient,
//            shouldPersist: shouldPersist,
//            logger: logger)
    }
    
}

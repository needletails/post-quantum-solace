//
//  TaskProcessor+DecryptAudit.swift
//  post-quantum-solace
//

import Foundation
import NeedleTailLogger
import SessionModels

extension TaskProcessor {
    func auditInboundDecryptFailure(
        message: InboundTaskMessage,
        failureClass: String,
        error: String? = nil,
        action: String? = nil,
        suppressed: Bool = false,
        metadata: [String: String] = [:]
    ) {
        var parts = [
            "pqs.decryptFailure",
            "failureClass=\(failureClass)",
            "layer=pqsInbound",
            "sender=\(message.senderSecretName)",
            "deviceId=\(message.senderDeviceId.uuidString)",
            "sharedId=\(message.sharedMessageId)",
        ]

        if suppressed {
            parts.append("suppressed=true")
        }
        if let action, !action.isEmpty {
            parts.append("action=\(action)")
        }
        if let error, !error.isEmpty {
            parts.append("error=\(error)")
        }
        for (key, value) in metadata.sorted(by: { $0.key < $1.key }) {
            parts.append("\(key)=\(value)")
        }

        DecryptFailureAuditLog.log(parts.joined(separator: " "))
    }
}

//
//  DecryptFailureAuditLog.swift
//  post-quantum-solace
//
//  Deprecated compatibility shim for hosts that still reference the 3.2.x
//  audit surface. New code should use ``PQSAuditLog``.
//

import Foundation
import NeedleTailLogger

/// Deprecated alias of the recovery audit channel.
///
/// Prefer ``PQSAuditLog`` (`Channel.recovery`). Kept so a 3.2.x → 3.3.x bump
/// remains source-compatible for hosts that called this type directly.
@available(*, deprecated, message: "Use PQSAuditLog (.recovery) instead.")
public enum DecryptFailureAuditLog {
    public static var isEnabled: Bool {
        PQSAuditLog.isEnabled
    }

    public static func configure(isEnabled: Bool = true) {
        PQSAuditLog.configure(isEnabled: isEnabled)
    }

    public static func log(_ message: String, level: Level = .warning) {
        PQSAuditLog.log(.recovery, message, level: level)
    }
}

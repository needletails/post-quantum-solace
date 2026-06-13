//
//  DecryptFailureAuditLog.swift
//  post-quantum-solace
//

import Foundation
import NeedleTailLogger

public enum DecryptFailureAuditLog {
    private final class Storage: @unchecked Sendable {
        let lock = NSLock()
        var isEnabled = true
        var fileLogger: NeedleTailLogger?
    }

    private static let storage = Storage()

    /// Default file when using `NeedleTailLogger` file streaming:
    /// `~/Library/Logs/NeedleTailLogger/[DecryptFailureAudit]/logs.txt`
    public static var isEnabled: Bool {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        return storage.isEnabled
    }

    public static func configure(isEnabled: Bool = true) {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        storage.isEnabled = isEnabled
        if !isEnabled {
            storage.fileLogger = nil
        }
    }

    public static func log(_ message: String, level: Level = .warning) {
        storage.lock.lock()
        defer { storage.lock.unlock() }

        guard storage.isEnabled else { return }

        let logger = storage.fileLogger ?? {
            let logger = NeedleTailLogger(
                "[DecryptFailureAudit]",
                maxLines: 5_000,
                maxLineLength: 512,
                writeToFile: true)
            storage.fileLogger = logger
            return logger
        }()

        logger.log(level: level, message: Message(stringLiteral: message), displayIcons: false)
    }
}

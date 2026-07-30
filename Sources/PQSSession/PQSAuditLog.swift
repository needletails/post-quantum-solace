//
//  PQSAuditLog.swift
//  post-quantum-solace
//
//  Staging audit channel for PQS recovery and message-path trails.
//  Writes send / recv / recovery lines to separate NeedleTailLogger files.
//
//  Compile-time fence (same idea as PQSRTC_CRITICAL_BUG_LOGGING):
//  - On when `DEBUG` or `-D PQS_AUDIT_LOG`
//  - Package.swift defines `PQS_AUDIT_LOG` by default; production
//    builds export `PQS_STRIP_AUDIT_LOG=1` to omit it
//  - When the fence is off, `log` / `configure` are no-ops (no string build, no I/O)
//

import Foundation
import NeedleTailLogger

public enum PQSAuditLog {
    public enum Channel: String, Sendable, CaseIterable {
        case send
        case recv
        case recovery

        var loggerLabel: String { "[PQSAudit.\(rawValue)]" }
    }

    private final class Storage: @unchecked Sendable {
        let lock = NSLock()
        /// Meaningful only when `isCompileTimeEnabled`; defaults on for staging builds.
        var isEnabled = true
        var fileLoggers: [Channel: NeedleTailLogger] = [:]
    }

    private static let storage = Storage()

#if DEBUG || PQS_AUDIT_LOG
    private static let isCompileTimeEnabled = true
#else
    private static let isCompileTimeEnabled = false
#endif

    /// Default files when using `NeedleTailLogger` file streaming:
    /// `~/Library/Logs/NeedleTailLogger/[PQSAudit.send|recv|recovery]/logs.txt`
    public static var isEnabled: Bool {
        guard isCompileTimeEnabled else { return false }
        storage.lock.lock()
        defer { storage.lock.unlock() }
        return storage.isEnabled
    }

    /// Test helper to temporarily mute the sink when compile-time audit is on.
    /// No-op in production binaries built without the flag.
    public static func configure(isEnabled: Bool = true) {
        guard isCompileTimeEnabled else { return }
        storage.lock.lock()
        defer { storage.lock.unlock() }
        storage.isEnabled = isEnabled
        if !isEnabled {
            storage.fileLoggers.removeAll()
        }
    }

    /// Logs only when enabled. Message is an autoclosure so string build/file I/O
    /// are skipped entirely when the channel is off.
    public static func log(
        _ channel: Channel,
        _ message: @autoclosure () -> String,
        level: Level = .warning
    ) {
        guard isCompileTimeEnabled else { return }

        storage.lock.lock()
        let enabled = storage.isEnabled
        let existingLogger = storage.fileLoggers[channel]
        storage.lock.unlock()

        guard enabled else { return }

        let line = message()
        let logger: NeedleTailLogger
        if let existingLogger {
            logger = existingLogger
        } else {
            storage.lock.lock()
            defer { storage.lock.unlock() }
            if let again = storage.fileLoggers[channel] {
                logger = again
            } else {
                let created = NeedleTailLogger(
                    channel.loggerLabel,
                    maxLines: 5_000,
                    maxLineLength: 512,
                    writeToFile: true)
                storage.fileLoggers[channel] = created
                logger = created
            }
        }

        logger.log(level: level, message: Message(stringLiteral: line), displayIcons: false)
    }
}

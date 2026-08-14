//
//  PQSAuditLog.swift
//  post-quantum-solace
//
//  Staging audit channel for PQS recovery and message-path trails.
//  Writes send / recv / recovery lines to separate NeedleTailLogger files.
//
//  Compile-time fence:
//  - On when `DEBUG` or `-D PQS_AUDIT_LOG`
//  - Package.swift defines `PQS_AUDIT_LOG` via the `PQSAuditLog` trait
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
}

public protocol PQSAuditSink: Sendable {
    var isEnabled: Bool { get }
    func configure(isEnabled: Bool)
    func log(_ channel: PQSAuditLog.Channel, _ message: @autoclosure () -> String, level: Level)
}

public extension PQSAuditSink {
    func log(_ channel: PQSAuditLog.Channel, _ message: @autoclosure () -> String) {
        guard isEnabled else { return }
        log(channel, message(), level: .warning)
    }
}

/// File-backed audit sink. Each instance has independent enable/logger state so
/// two sessions in one process can inject different sinks.
public struct FilePQSAuditSink: PQSAuditSink {
    private final class Storage: @unchecked Sendable {
        let lock = NSLock()
        /// Meaningful only when `isCompileTimeEnabled`; defaults on for staging builds.
        var isEnabled = true
        var fileLoggers: [PQSAuditLog.Channel: NeedleTailLogger] = [:]
    }

    private let storage: Storage

#if DEBUG || PQS_AUDIT_LOG
    private static let isCompileTimeEnabled = true
#else
    private static let isCompileTimeEnabled = false
#endif

    public init() {
        self.storage = Storage()
    }

    public var isEnabled: Bool {
        guard Self.isCompileTimeEnabled else { return false }
        storage.lock.lock()
        defer { storage.lock.unlock() }
        return storage.isEnabled
    }

    public func configure(isEnabled: Bool) {
        guard Self.isCompileTimeEnabled else { return }
        storage.lock.lock()
        defer { storage.lock.unlock() }
        storage.isEnabled = isEnabled
        if !isEnabled {
            storage.fileLoggers.removeAll()
        }
    }

    public func log(
        _ channel: PQSAuditLog.Channel,
        _ message: @autoclosure () -> String,
        level: Level = .warning
    ) {
        guard Self.isCompileTimeEnabled else { return }

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

extension PQSAuditLog {
    /// Process-default sink used by the static facade (`configure` / `log`).
    public static let processDefault = FilePQSAuditSink()

    public static var isEnabled: Bool { processDefault.isEnabled }

    /// Test helper to temporarily mute the sink when compile-time audit is on.
    /// No-op in production binaries built without the flag.
    public static func configure(isEnabled: Bool = true) {
        processDefault.configure(isEnabled: isEnabled)
    }

    /// Logs only when enabled. Message is an autoclosure so string build/file I/O
    /// are skipped entirely when the channel is off.
    public static func log(
        _ channel: Channel,
        _ message: @autoclosure () -> String,
        level: Level = .warning
    ) {
        guard isEnabled else { return }
        processDefault.log(channel, message(), level: level)
    }
}

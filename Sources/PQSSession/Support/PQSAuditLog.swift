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

import Crypto
import Foundation
import NeedleTailLogger

/// Redacts peer identifiers from audit lines before they reach disk. Secret names
/// document themselves as "must not be logged"; the audit file still needs a
/// stable per-peer token to correlate lines, so each value becomes `h:<8 hex>`.
public enum PQSAuditRedaction {
    /// `key=value` fields whose value is a secret name (or a comma list of them).
    static let secretNameKeys: Set<String> = [
        "sender", "peer", "requester", "requesterName", "recipientSecret",
        "recipientSecretName", "secretName", "members", "senderSecretName", "recipient",
    ]

    public static func token(for secretName: String) -> String {
        let digest = SHA256.hash(data: Data(secretName.utf8))
        return "h:" + digest.prefix(4).map { String(format: "%02x", $0) }.joined()
    }

    /// Describes an error for an audit line. Foundation's errors carry messages and URLs
    /// (a failed key-rotation request names the account in its path), so they are reduced
    /// to domain and code. Swift errors print as they are: the ratchet and session errors
    /// name keys and counts, never accounts.
    public static func describe(_ error: Error) -> String {
        let bridged = error as NSError
        let foundationDomains: Set<String> = [
            NSURLErrorDomain, NSCocoaErrorDomain, NSPOSIXErrorDomain, NSOSStatusErrorDomain, NSMachErrorDomain,
        ]
        if foundationDomains.contains(bridged.domain) || error is DecodingError || error is EncodingError {
            return "\(bridged.domain):\(bridged.code)"
        }
        return String(describing: error)
    }

    public static func redact(_ line: String) -> String {
        line.split(separator: " ", omittingEmptySubsequences: false).map { field -> String in
            guard let equals = field.firstIndex(of: "=") else { return String(field) }
            let key = String(field[field.startIndex..<equals])
            guard secretNameKeys.contains(key) else { return String(field) }
            let value = field[field.index(after: equals)...]
            guard !value.isEmpty else { return String(field) }
            let redacted = value.split(separator: ",").map { item -> String in
                // `recipient=nickname:bob` style tags keep their kind prefix.
                if let colon = item.firstIndex(of: ":"), item[item.startIndex..<colon].allSatisfy(\.isLetter) {
                    return String(item[item.startIndex...colon]) + token(for: String(item[item.index(after: colon)...]))
                }
                return token(for: String(item))
            }.joined(separator: ",")
            return key + "=" + redacted
        }.joined(separator: " ")
    }
}

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

    /// The logger splits a longer line on spaces, and a continuation has no timestamp or
    /// event name, so a field past the wrap stops matching a grep for its line. This
    /// stays above the widest line one frame writes, not counting `attempts=`.
    static let maxLineLength = 1024

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

        let line = PQSAuditRedaction.redact(message())
        let storage = self.storage
        // File I/O (and the first-use logger construction, which reads the existing
        // file to count lines) runs off the caller: `log` is called from inside the
        // session actor and the crypto executor.
        Self.writeQueue.async {
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
                        maxLineLength: Self.maxLineLength,
                        writeToFile: true)
                    storage.fileLoggers[channel] = created
                    logger = created
                }
            }
            logger.log(level: level, message: Message(stringLiteral: line), displayIcons: false)
        }
    }

    private static let writeQueue = DispatchQueue(label: "com.needletails.pqs.audit", qos: .utility)
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

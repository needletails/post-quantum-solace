//
//  TypedIdentifiers.swift
//  post-quantum-solace
//

import Foundation

/// Unique MessageID of one encrypted envelope sent to one recipient device.
///
/// Replaced on every resend. Persist and put on the wire as `rawValue`.
public struct EnvelopeID: RawRepresentable, Hashable, Sendable, Codable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

/// Stable application / chat identity for a message across devices and resends.
public struct LogicalMessageID: RawRepresentable, Hashable, Sendable, Codable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

/// Canonical user identifier. Normalization runs in `init`.
public struct SecretName: RawRepresentable, Hashable, Sendable, Codable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = Self.normalized(rawValue)
    }

    public init(_ rawValue: String) {
        self.init(rawValue: rawValue)
    }

    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        rawValue = Self.normalized(raw)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    /// IRC-equivalent folding used by the transport layer.
    public static func normalized(_ raw: String) -> String {
        raw.lowercased()
            .replacingOccurrences(of: "[", with: "{")
            .replacingOccurrences(of: "]", with: "}")
            .replacingOccurrences(of: "\\", with: "|")
            .replacingOccurrences(of: "~", with: "^")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Identity comparison after the same fold `createContact` and transport lookups use.
    public static func areEqual(_ lhs: String, _ rhs: String) -> Bool {
        SecretName(lhs).rawValue == SecretName(rhs).rawValue
    }
}

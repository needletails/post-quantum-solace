//
//  ChannelStoredMetadata.swift
//  post-quantum-solace
//
//  Local UI state for channel communications (pin, read/unread) stored inside
//  encrypted communication metadata. `core` stays wire-compatible `ChannelInfo`;
//  `overlay` is client-local and must not be relied on by sync peers.
//

import Foundation

/// Per-device, never-synchronized UI overlay for a channel
/// communication.
///
/// `ChannelLocalOverlay` describes preferences that should *not* be
/// shared across devices or with peers: pin position, the user's
/// manual read marker, archived/hidden state, and a custom display
/// title. It is encoded into ``BaseCommunication``'s metadata blob
/// alongside ``ChannelInfo`` (see ``ChannelStoredMetadata``) so that
/// each device's UI state survives a relaunch without leaking through
/// channel synchronization payloads.
///
/// Defaults are conservative — `userMarkedRead` defaults to `true` so
/// freshly created or imported channels do not flag themselves as
/// unread; everything else defaults to `false` / `nil`.
public struct ChannelLocalOverlay: Codable, Sendable, Hashable {
    enum CodingKeys: String, CodingKey {
        case userMarkedPinned
        case userMarkedRead
        case useManualReadState
        case displayTitle
        case userMarkedArchived
        case userMarkedHidden
    }

    public var userMarkedPinned: Bool
    public var userMarkedRead: Bool
    public var useManualReadState: Bool
    /// Friendly title for lists; local-only (not sent in `ChannelMetadataCoding.syncMetadata`).
    public var displayTitle: String?
    public var userMarkedArchived: Bool
    public var userMarkedHidden: Bool

    public init(
        userMarkedPinned: Bool = false,
        userMarkedRead: Bool = true,
        useManualReadState: Bool = false,
        displayTitle: String? = nil,
        userMarkedArchived: Bool = false,
        userMarkedHidden: Bool = false
    ) {
        self.userMarkedPinned = userMarkedPinned
        self.userMarkedRead = userMarkedRead
        self.useManualReadState = useManualReadState
        self.displayTitle = displayTitle
        self.userMarkedArchived = userMarkedArchived
        self.userMarkedHidden = userMarkedHidden
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        userMarkedPinned = try c.decodeIfPresent(Bool.self, forKey: .userMarkedPinned) ?? false
        userMarkedRead = try c.decodeIfPresent(Bool.self, forKey: .userMarkedRead) ?? true
        useManualReadState = try c.decodeIfPresent(Bool.self, forKey: .useManualReadState) ?? false
        displayTitle = try c.decodeIfPresent(String.self, forKey: .displayTitle)
        userMarkedArchived = try c.decodeIfPresent(Bool.self, forKey: .userMarkedArchived) ?? false
        userMarkedHidden = try c.decodeIfPresent(Bool.self, forKey: .userMarkedHidden) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(userMarkedPinned, forKey: .userMarkedPinned)
        try c.encode(userMarkedRead, forKey: .userMarkedRead)
        try c.encode(useManualReadState, forKey: .useManualReadState)
        try c.encodeIfPresent(displayTitle, forKey: .displayTitle)
        try c.encode(userMarkedArchived, forKey: .userMarkedArchived)
        try c.encode(userMarkedHidden, forKey: .userMarkedHidden)
    }
}

/// On-disk container that pairs a synchronized ``ChannelInfo`` with an
/// optional per-device ``ChannelLocalOverlay``.
///
/// `ChannelStoredMetadata` is what the SDK actually serializes into
/// ``BaseCommunication/UnwrappedProps/metadata`` for channel
/// communications. The `core` field is wire-compatible with
/// `ChannelInfo` so legacy rows that stored only the bare info struct
/// continue to decode; the optional `overlay` is local-only and must
/// not be relied upon by remote peers.
public struct ChannelStoredMetadata: Codable, Sendable, Hashable {
    /// Synchronized channel descriptor (name, members, roles).
    public var core: ChannelInfo
    /// Per-device UI preferences. Always `nil` for legacy / un-overlaid
    /// channels.
    public var overlay: ChannelLocalOverlay?

    public init(core: ChannelInfo, overlay: ChannelLocalOverlay? = nil) {
        self.core = core
        self.overlay = overlay
    }
}

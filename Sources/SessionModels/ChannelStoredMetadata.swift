//
//  ChannelStoredMetadata.swift
//  post-quantum-solace
//
//  Local UI state for channel communications (pin, read/unread) stored inside
//  encrypted communication metadata. `core` stays wire-compatible `ChannelInfo`;
//  `overlay` is client-local and must not be relied on by sync peers.
//

import Foundation

/// Per-device channel list preferences (pin, manual read).
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

/// Wraps `ChannelInfo` with optional local overlay. Legacy rows store only `ChannelInfo` bytes.
public struct ChannelStoredMetadata: Codable, Sendable, Hashable {
    public var core: ChannelInfo
    public var overlay: ChannelLocalOverlay?

    public init(core: ChannelInfo, overlay: ChannelLocalOverlay? = nil) {
        self.core = core
        self.overlay = overlay
    }
}

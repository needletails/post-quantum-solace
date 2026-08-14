//
//  MessageMetadata.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-29.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//
//
import Foundation

/// A structure that represents metadata for a message in the post-quantum secure messaging system.
///
/// This struct contains information about user interactions with messages, specifically whether
/// a user has marked the message as pinned or read. It conforms to the `Sendable` and `Codable`
/// protocols, allowing it to be safely shared across concurrency domains and easily encoded/decoded
/// for data persistence or network transmission.
///
/// ## Properties
/// - `userMarkedPinned`: A Boolean value indicating whether the user has marked the message as pinned.
/// - `userMarkedRead`: A Boolean value indicating whether the user has marked the message as read.
///
/// ## Usage
/// This struct is typically used in conjunction with encrypted messages to track user interactions
/// and provide state management for message display and organization features. It can be stored
/// alongside message data or transmitted as part of message synchronization protocols.
///
/// ## Examples
/// ```swift
/// // Create metadata for a new message
/// let metadata = MessageMetadata(userMarkedPinned: false, userMarkedRead: false)
///
/// // Update metadata when user marks message as read
/// var updatedMetadata = metadata
/// updatedMetadata.userMarkedRead = true
///
/// // Check if message is pinned
/// if metadata.userMarkedPinned {
///     // Display pinned indicator
/// }
/// ```
///
/// ## Thread Safety
/// This struct is `Sendable`, making it safe to use across concurrent contexts such as Swift concurrency
/// (async/await) and multi-threaded environments.
///
/// ## Serialization
/// The `Codable` conformance allows this struct to be easily serialized for:
/// - Database storage
/// - Network transmission
/// - JSON/Binary encoding
/// - Message synchronization between devices
public struct MessageMetadata: Sendable, Codable {
    enum CodingKeys: String, CodingKey {
        case userMarkedPinned
        case userMarkedRead
        case userMarkedArchived
        case userMarkedHidden
        case unreadCount
    }

    /// A Boolean value indicating whether the user has marked the message as pinned.
    ///
    /// When `true`, this indicates that the user has explicitly pinned the message for easy access.
    /// Pinned messages are typically displayed prominently in the user interface and may be
    /// organized separately from regular messages.
    public var userMarkedPinned: Bool

    /// A Boolean value indicating whether the user has marked the message as read.
    ///
    /// When `true`, this indicates that the user has viewed or acknowledged the message content.
    /// This state is typically used to determine unread message counts and visual indicators
    /// in the user interface.
    public var userMarkedRead: Bool

    /// When `true`, the conversation is archived in the sidebar (local list UI only).
    public var userMarkedArchived: Bool

    /// When `true`, the conversation is hidden from the main list until the Hidden filter is shown and selected (local UI only).
    public var userMarkedHidden: Bool

    /// Stored unread for this conversation. Increment on inbound, clear on open.
    /// The home-screen icon is the sum of these counters; delivery receipts stay separate.
    public var unreadCount: Int

    /// Initializes a new instance of `MessageMetadata`.
    ///
    /// - Parameters:
    ///   - userMarkedPinned: A Boolean value indicating whether the user has marked the message as pinned.
    ///     Defaults to `false` for new messages.
    ///   - userMarkedRead: A Boolean value indicating whether the user has marked the message as read.
    ///     Defaults to `false` for new messages.
    ///   - userMarkedArchived: Archived sidebar state. Defaults to `false`.
    ///   - userMarkedHidden: Hidden sidebar state. Defaults to `false`.
    ///   - unreadCount: Conversation unread counter. Defaults to `0`.
    public init(
        userMarkedPinned: Bool = false,
        userMarkedRead: Bool = false,
        userMarkedArchived: Bool = false,
        userMarkedHidden: Bool = false,
        unreadCount: Int = 0
    ) {
        self.userMarkedPinned = userMarkedPinned
        self.userMarkedRead = userMarkedRead
        self.userMarkedArchived = userMarkedArchived
        self.userMarkedHidden = userMarkedHidden
        self.unreadCount = max(0, unreadCount)
    }

    /// Decodes a `MessageMetadata`, supplying defaults for fields that
    /// are missing from older on-disk records.
    ///
    /// `userMarkedRead`, `userMarkedArchived`, and `userMarkedHidden`
    /// were added in later schema revisions; legacy rows that predate
    /// those fields decode them as `false`. `userMarkedPinned` likewise
    /// defaults to `false` when absent.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        userMarkedPinned = try c.decodeIfPresent(Bool.self, forKey: .userMarkedPinned) ?? false
        userMarkedRead = try c.decodeIfPresent(Bool.self, forKey: .userMarkedRead) ?? false
        userMarkedArchived = try c.decodeIfPresent(Bool.self, forKey: .userMarkedArchived) ?? false
        userMarkedHidden = try c.decodeIfPresent(Bool.self, forKey: .userMarkedHidden) ?? false
        unreadCount = max(0, try c.decodeIfPresent(Int.self, forKey: .unreadCount) ?? 0)
    }

    /// Encodes every flag explicitly so on-disk rows always carry the
    /// full schema and downstream readers can rely on each key being
    /// present.
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(userMarkedPinned, forKey: .userMarkedPinned)
        try c.encode(userMarkedRead, forKey: .userMarkedRead)
        try c.encode(userMarkedArchived, forKey: .userMarkedArchived)
        try c.encode(userMarkedHidden, forKey: .userMarkedHidden)
        try c.encode(unreadCount, forKey: .unreadCount)
    }

    /// Creates a copy of the current metadata with updated pinned state.
    ///
    /// - Parameter isPinned: The new pinned state for the message.
    /// - Returns: A new `MessageMetadata` instance with the updated pinned state.
    public func updatingPinnedState(_ isPinned: Bool) -> MessageMetadata {
        MessageMetadata(
            userMarkedPinned: isPinned,
            userMarkedRead: userMarkedRead,
            userMarkedArchived: userMarkedArchived,
            userMarkedHidden: userMarkedHidden,
            unreadCount: unreadCount
        )
    }

    /// Creates a copy of the current metadata with updated read state.
    ///
    /// - Parameter isRead: The new read state for the message.
    /// - Returns: A new `MessageMetadata` instance with the updated read state.
    public func updatingReadState(_ isRead: Bool) -> MessageMetadata {
        MessageMetadata(
            userMarkedPinned: userMarkedPinned,
            userMarkedRead: isRead,
            userMarkedArchived: userMarkedArchived,
            userMarkedHidden: userMarkedHidden,
            unreadCount: isRead ? 0 : max(1, unreadCount)
        )
    }

    /// Creates a copy of the current metadata with updated archived state.
    ///
    /// - Parameter isArchived: The new archived state for the message.
    /// - Returns: A new `MessageMetadata` instance with the updated archived state.
    public func updatingArchivedState(_ isArchived: Bool) -> MessageMetadata {
        MessageMetadata(
            userMarkedPinned: userMarkedPinned,
            userMarkedRead: userMarkedRead,
            userMarkedArchived: isArchived,
            userMarkedHidden: userMarkedHidden,
            unreadCount: unreadCount
        )
    }

    /// Creates a copy of the current metadata with updated hidden state.
    ///
    /// - Parameter isHidden: The new hidden state for the message.
    /// - Returns: A new `MessageMetadata` instance with the updated hidden state.
    public func updatingHiddenState(_ isHidden: Bool) -> MessageMetadata {
        MessageMetadata(
            userMarkedPinned: userMarkedPinned,
            userMarkedRead: userMarkedRead,
            userMarkedArchived: userMarkedArchived,
            userMarkedHidden: isHidden,
            unreadCount: unreadCount
        )
    }

    /// +1 (or more) on an inbound message. Marks the conversation unread.
    public func incrementingUnread(by count: Int = 1) -> MessageMetadata {
        MessageMetadata(
            userMarkedPinned: userMarkedPinned,
            userMarkedRead: false,
            userMarkedArchived: userMarkedArchived,
            userMarkedHidden: userMarkedHidden,
            unreadCount: max(0, unreadCount + count)
        )
    }

    /// Open / mark read: clear the conversation counter.
    public func markingRead() -> MessageMetadata {
        updatingReadState(true)
    }

    /// Manual mark unread: keep an existing count, otherwise seed 1.
    public func markingUnread() -> MessageMetadata {
        updatingReadState(false)
    }
}

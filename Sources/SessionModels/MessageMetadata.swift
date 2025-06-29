//
//  MessageMetadata.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/29/24.
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
/// - JSON/BSON encoding
/// - Message synchronization between devices
public struct MessageMetadata: Sendable, Codable {
    
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
    
    /// Initializes a new instance of `MessageMetadata`.
    ///
    /// - Parameters:
    ///   - userMarkedPinned: A Boolean value indicating whether the user has marked the message as pinned.
    ///     Defaults to `false` for new messages.
    ///   - userMarkedRead: A Boolean value indicating whether the user has marked the message as read.
    ///     Defaults to `false` for new messages.
    public init(
        userMarkedPinned: Bool = false,
        userMarkedRead: Bool = false
    ) {
        self.userMarkedPinned = userMarkedPinned
        self.userMarkedRead = userMarkedRead
    }
    
    /// Creates a copy of the current metadata with updated pinned state.
    ///
    /// - Parameter isPinned: The new pinned state for the message.
    /// - Returns: A new `MessageMetadata` instance with the updated pinned state.
    public func updatingPinnedState(_ isPinned: Bool) -> MessageMetadata {
        return MessageMetadata(
            userMarkedPinned: isPinned,
            userMarkedRead: self.userMarkedRead
        )
    }
    
    /// Creates a copy of the current metadata with updated read state.
    ///
    /// - Parameter isRead: The new read state for the message.
    /// - Returns: A new `MessageMetadata` instance with the updated read state.
    public func updatingReadState(_ isRead: Bool) -> MessageMetadata {
        return MessageMetadata(
            userMarkedPinned: self.userMarkedPinned,
            userMarkedRead: isRead
        )
    }
}

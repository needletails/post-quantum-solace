//
//  DeliveryStateMetadata.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-04-19.
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

import Foundation

/// A struct representing metadata for the delivery state of a message.
///
/// This struct encapsulates information about the current delivery state of a message
/// along with a shared identifier that links it to the broader communication context.
/// It's designed to be used in secure messaging systems where message delivery status
/// needs to be tracked and synchronized across multiple devices.
///
/// ## Overview
/// `DeliveryStateMetadata` is used to track the lifecycle of messages from creation
/// through delivery confirmation. It works in conjunction with the `DeliveryState` enum
/// to provide a complete picture of message status.
///
/// ## Properties
/// - `state`: The current delivery state of the message, represented as a `DeliveryState`
/// - `sharedId`: A unique identifier shared across the communication context for message correlation
///
/// ## Usage Examples
///
/// ### Basic Initialization
/// ```swift
/// let metadata = DeliveryStateMetadata(
///     state: .delivered,
///     sharedId: "msg_12345"
/// )
/// ```
///
/// ### Tracking Message States
/// ```swift
/// // Message sent
/// let sentMetadata = DeliveryStateMetadata(
///     state: .sending,
///     sharedId: messageId
/// )
///
/// // Message delivered
/// let deliveredMetadata = DeliveryStateMetadata(
///     state: .delivered,
///     sharedId: messageId
/// )
///
/// // Message read
/// let readMetadata = DeliveryStateMetadata(
///     state: .read,
///     sharedId: messageId
/// )
/// ```
///
/// ### Error Handling
/// ```swift
/// let failedMetadata = DeliveryStateMetadata(
///     state: .failed("Network timeout"),
///     sharedId: messageId
/// )
/// ```
///
/// ## Thread Safety
/// This struct is marked as `Sendable` and can be safely used across different threads.
///
/// ## Conformance
/// - `Codable`: Can be encoded/decoded for persistence and network transmission
/// - `Sendable`: Thread-safe for concurrent access
public struct DeliveryStateMetadata: Codable, Sendable {
    /// The current delivery state of the message.
    ///
    /// This property indicates where the message is in its delivery lifecycle,
    /// from initial sending through final confirmation. The state can be updated
    /// as the message progresses through the delivery pipeline.
    public let state: DeliveryState

    /// A unique identifier shared across the communication context.
    ///
    /// This identifier is used to correlate the metadata with the actual message
    /// across different parts of the system. It should remain constant throughout
    /// the message's lifecycle and is typically derived from the message's unique ID.
    public let sharedId: String

    /// Initializes a new instance of `DeliveryStateMetadata`.
    ///
    /// - Parameters:
    ///   - state: The current delivery state of the message
    ///   - sharedId: A unique identifier shared across the communication context
    ///
    /// - Note: The `sharedId` should be consistent with the message it represents
    ///          and should not change during the message's lifecycle.
    public init(state: DeliveryState, sharedId: String) {
        self.state = state
        self.sharedId = sharedId
    }
}

/// A struct representing metadata for editing a message.
///
/// This struct encapsulates information required to edit an existing message,
/// including the new content, shared identifier for message correlation, and
/// sender information for audit trails. It uses generics to support different
/// content types while maintaining type safety.
///
/// ## Overview
/// `EditMessageMetadata` is used when a user wants to modify the content of a
/// previously sent message. The generic type parameter allows for flexible content
/// types while ensuring the content can be properly serialized and transmitted.
///
/// ## Generic Type Requirements
/// The generic type `T` must conform to:
/// - `Codable`: For serialization and network transmission
/// - `Sendable`: For thread-safe concurrent access
///
/// ## Properties
/// - `value`: The new content value for the message
/// - `sharedId`: A unique identifier shared across the communication context
/// - `sender`: The identifier of the sender who is editing the message
///
/// ## Usage Examples
///
/// ### Text Message Editing
/// ```swift
/// let editMetadata = EditMessageMetadata(
///     value: "Updated message content",
///     sharedId: "msg_12345",
///     sender: "user_abc123"
/// )
/// ```
///
/// ### Media Message Editing
/// ```swift
/// let mediaEditMetadata = EditMessageMetadata(
///     value: updatedImageData,
///     sharedId: "msg_67890",
///     sender: "user_abc123"
/// )
/// ```
///
/// ### Custom Content Types
/// ```swift
/// struct CustomMessageContent: Codable, Sendable {
///     let text: String
///     let attachments: [String]
///     let timestamp: Date
/// }
///
/// let customEditMetadata = EditMessageMetadata(
///     value: CustomMessageContent(
///         text: "Updated content",
///         attachments: ["file1.pdf", "file2.jpg"],
///         timestamp: Date()
///     ),
///     sharedId: "msg_11111",
///     sender: "user_abc123"
/// )
/// ```
///
/// ## Thread Safety
/// This struct is marked as `Sendable` and can be safely used across different threads.
///
/// ## Conformance
/// - `Codable`: Can be encoded/decoded for persistence and network transmission
/// - `Sendable`: Thread-safe for concurrent access
public struct EditMessageMetadata<T: Codable & Sendable>: Codable, Sendable {
    /// The new content value for the message.
    ///
    /// This property contains the updated content that will replace the original
    /// message content. The type is generic, allowing for flexible content types
    /// while maintaining type safety and serialization capabilities.
    public let value: T

    /// A unique identifier shared across the communication context.
    ///
    /// This identifier is used to correlate the edit operation with the original
    /// message. It should match the `sharedId` of the message being edited.
    public let sharedId: String

    /// The identifier of the sender who is editing the message.
    ///
    /// This property tracks who initiated the edit operation, providing an audit
    /// trail for message modifications. It's typically the user ID or device ID
    /// of the person making the edit.
    public let sender: String

    /// Initializes a new instance of `EditMessageMetadata`.
    ///
    /// - Parameters:
    ///   - value: The new content value for the message
    ///   - sharedId: A unique identifier shared across the communication context
    ///   - sender: The identifier of the sender who is editing the message
    ///
    /// - Note: The `sharedId` should match the original message's identifier
    ///          to ensure proper correlation of the edit operation.
    public init(value: T, sharedId: String, sender: String) {
        self.value = value
        self.sharedId = sharedId
        self.sender = sender
    }
}

/// A struct representing metadata for revoking a message.
///
/// This struct encapsulates the minimal information required to revoke a message,
/// using only the shared identifier to identify which message should be revoked.
/// Message revocation typically removes the message from all recipients' views.
///
/// ## Overview
/// `RevokeMessageMetadata` is used when a user wants to completely remove a
/// previously sent message from the conversation. This operation is typically
/// irreversible and affects all participants in the conversation.
///
/// ## Properties
/// - `sharedId`: A unique identifier shared across the communication context for the message being revoked
///
/// ## Usage Examples
///
/// ### Basic Message Revocation
/// ```swift
/// let revokeMetadata = RevokeMessageMetadata(
///     sharedId: "msg_12345"
/// )
/// ```
///
/// ### Batch Message Revocation
/// ```swift
/// let messageIds = ["msg_1", "msg_2", "msg_3"]
/// let revokeOperations = messageIds.map { RevokeMessageMetadata(sharedId: $0) }
/// ```
///
/// ### Conditional Revocation
/// ```swift
/// func revokeMessageIfAllowed(_ messageId: String, canRevoke: Bool) -> RevokeMessageMetadata? {
///     guard canRevoke else { return nil }
///     return RevokeMessageMetadata(sharedId: messageId)
/// }
/// ```
///
/// ## Thread Safety
/// This struct is marked as `Sendable` and can be safely used across different threads.
///
/// ## Conformance
/// - `Codable`: Can be encoded/decoded for persistence and network transmission
/// - `Sendable`: Thread-safe for concurrent access
///
/// ## Important Notes
/// - Message revocation is typically irreversible
/// - The operation affects all participants in the conversation
/// - Some systems may have time limits on message revocation
/// - Revoked messages may still be visible in audit logs for compliance purposes
public struct RevokeMessageMetadata: Codable, Sendable {
    /// A unique identifier shared across the communication context for the message being revoked.
    ///
    /// This identifier is used to identify the specific message that should be
    /// revoked. It should match the `sharedId` of the original message.
    public let sharedId: String

    /// Initializes a new instance of `RevokeMessageMetadata`.
    ///
    /// - Parameter sharedId: A unique identifier shared across the communication context
    ///
    /// - Note: The `sharedId` should match the original message's identifier
    ///          to ensure the correct message is revoked.
    /// - Important: Message revocation is typically irreversible and affects all
    ///              participants in the conversation.
    public init(sharedId: String) {
        self.sharedId = sharedId
    }
}

// MARK: - Type Aliases

/// Type alias for string-based message edits.
///
/// This provides a convenient way to create edit metadata for text messages
/// without specifying the generic type parameter.
public typealias StringEditMessageMetadata = EditMessageMetadata<String>

/// Type alias for data-based message edits.
///
/// This provides a convenient way to create edit metadata for binary content
/// such as images, documents, or other media files.
public typealias DataEditMessageMetadata = EditMessageMetadata<Data>

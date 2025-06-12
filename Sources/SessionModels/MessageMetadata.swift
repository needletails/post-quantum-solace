//
//  MessageMetadata.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/29/24.
//
import Foundation

/// A structure that represents metadata for a message.
///
/// This struct contains information about whether a user has marked the message as pinned
/// or read. It conforms to the `Sendable` and `Codable` protocols, allowing it to be safely
/// shared across concurrency domains and easily encoded/decoded for data persistence or
/// network transmission.
///
/// - Properties:
///   - `userMarkedPinned`: A Boolean value indicating whether the user has marked the message as pinned.
///   - `userMarkedRead`: A Boolean value indicating whether the user has marked the message as read.
///
/// - Important:
///   This struct is designed to be used in contexts where message metadata needs to be tracked
///   and shared, such as in messaging applications or notification systems.
public struct MessageMetadata: Sendable, Codable {
    
    /// A Boolean value indicating whether the user has marked the message as pinned.
    public var userMarkedPinned: Bool
    
    /// A Boolean value indicating whether the user has marked the message as read.
    public var userMarkedRead: Bool
    
    /// Initializes a new instance of `MessageMetadata`.
    ///
    /// - Parameters:
    ///   - userMarkedPinned: A Boolean value indicating whether the user has marked the message as pinned.
    ///   - userMarkedRead: A Boolean value indicating whether the user has marked the message as read.
    public init(
        userMarkedPinned: Bool,
        userMarkedRead: Bool
    ) {
        self.userMarkedPinned = userMarkedPinned
        self.userMarkedRead = userMarkedRead
    }
}

//
//  SessionTransport.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import DoubleRatchetKit

/// This metadata needs to be handle with care Ideally none of it should be sent over the wire. It should just be used to prepare the message for sending. 
public struct SignedRatchetMessageMetadata: Sendable {
    /// Recipient secretName
    public let secretName: String
    /// Recipient deviceIdentity
    public let deviceIdentity: UUID
    /// Push Notification Type
    public let pushType: PushNotificationType
    /// Shared Message Identifier
    public let sharedMessageIdentifier: String
    /// The message type
    public let messageType: MessageType
    /// A flag for the given message type
    public let messageFlags: MessageFlags
    /// The recipeint type
    public let recipient: MessageRecipient
}

// Define a protocol for session transport
public protocol SessionTransport: Sendable {
    
    /// Sends a message to the network.
    /// - Parameter message: The message to be sent.
    /// - Throws: An error if the message could not be sent.
    func sendMessage(_
                     message: SignedRatchetMessage,
                     metadata: SignedRatchetMessageMetadata) async throws
    
    /// Receives a message from the network.
    /// - Returns: The received message.
    /// - Throws: An error if the message could not be received.
    func receiveMessage() async throws -> String
    
    /// Finds the user configuration from the network.
    /// - Returns: The user configuration if found.
    /// - Throws: An error if the configuration could not be found.
    func findConfiguration(for secretName: String) async throws -> UserConfiguration
    
    /// Publishes the user configuration to the network.
    /// - Parameter configuration: The user configuration to be published.
    /// - Throws: An error if the configuration could not be published.
    func publishUser(configuration: UserConfiguration) async throws
    
    func publishAuxillary(configuration: UserDeviceConfiguration) async throws
}

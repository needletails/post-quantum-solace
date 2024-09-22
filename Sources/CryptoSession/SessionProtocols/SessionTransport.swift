//
//  SessionTransport.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import DoubleRatchetKit

// Define a protocol for session transport
public protocol SessionTransport: Sendable {
    
    /// Sends a message to the network.
    /// - Parameter message: The message to be sent.
    /// - Throws: An error if the message could not be sent.
    func sendMessage(_
                     message: SignedRatchetMessage,
                     to secretName: String,
                     with deviceIdentity: UUID,
                     pushType: PushNotificationType,
                     remoteId: String) async throws
    
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

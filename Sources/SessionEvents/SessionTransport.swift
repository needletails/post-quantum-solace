//
//  SessionTransport.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import DoubleRatchetKit
import BSON
import SessionModels
import Crypto

/// This metadata needs to be handle with care Ideally none of it should be sent over the wire. It should just be used to prepare the message for sending.
public struct SignedRatchetMessageMetadata: Sendable {
    /// Recipient secretName
    public let secretName: String
    /// Recipient deviceId
    public let deviceId: UUID
    /// The recipeint type
    public let recipient: MessageRecipient
    public let transportMetadata: Data?
    public let sharedMessageIdentifier: String
    
    public init(
        secretName: String,
        deviceId: UUID,
        recipient: MessageRecipient,
        transportMetadata: Data?,
        sharedMessageIdentifier: String
    ) {
        self.secretName = secretName
        self.deviceId = deviceId
        self.recipient = recipient
        self.transportMetadata = transportMetadata
        self.sharedMessageIdentifier = sharedMessageIdentifier
    }
}

// Define a protocol for session transport
public protocol SessionTransport: Sendable {

    /// Sends a message to the network.
    /// - Parameter message: The message to be sent.
    /// - Throws: An error if the message could not be sent.
    func sendMessage(_
                     message: SignedRatchetMessage,
                     metadata: SignedRatchetMessageMetadata) async throws
    
    /// Finds the user configuration from the network.
    /// - Returns: The user configuration if found.
    /// - Throws: An error if the configuration could not be found.
    func findConfiguration(for secretName: String) async throws -> UserConfiguration
    
    /// Publishes the user configuration to the network. We call this for the master device and updating its bundle with new devices
    /// - Parameter configuration: The user configuration to be published.
    /// - Throws: An error if the configuration could not be published.
    func publishUserConfiguration(_ configuration: UserConfiguration, recipient identity: UUID) async throws
    
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> OneTimeKeys
    func fetchOneTimeKeyIdentites(for secretName: String, deviceId: String, type: KeysType) async throws -> [UUID]
    func updateOneTimeKeys(for secretName: String, deviceId: String, keys: [UserConfiguration.SignedOneTimePublicKey]) async throws
    func updateOneTimeKyberKeys(for secretName: String, deviceId: String, keys: [UserConfiguration.SignedPQKemOneTimeKey]) async throws
    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws
    func deleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws
    func publishRotatedKeys(
        for secretName: String,
        deviceId: String,
        rotated keys: RotatedPublicKeys
    ) async throws
    func createUploadPacket(
        secretName: String,
        deviceId: UUID,
        recipient: MessageRecipient,
        metadata: Document
    ) async throws
    func notifyIdentityCreation(for secretName: String, keys: OneTimeKeys) async throws
}

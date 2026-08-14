//
//  SessionTransport.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-14.
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

import DoubleRatchetKit
import Foundation
import SessionModels
import Crypto

/// Metadata structure for signed ratchet messages that contains sensitive information
/// used to prepare messages for network transmission.
///
/// This metadata should be handled with care as it contains recipient information
/// and should not be sent over the wire. It is used internally to prepare and
/// route messages to the correct recipients.
///
/// ## Important Security Note
/// None of this metadata should be transmitted over the network. It is used
/// solely for internal message preparation and routing.
///
/// ## Properties
/// - `secretName`: The recipient's secret identifier for privacy-preserving communication
/// - `deviceId`: The unique identifier for the recipient's device
/// - `recipient`: The type of recipient (individual, group, etc.)
/// - `transportMetadata`: Optional additional metadata for transport layer processing
/// - `sharedMessageId`: A shared identifier for message correlation and tracking
public struct SignedRatchetMessageMetadata: Sendable {
    /// The recipient's secret name used for privacy-preserving identification.
    ///
    /// This identifier is used to route messages without exposing real user identities.
    /// It should be treated as sensitive information and not logged or exposed.
    public let secretName: String

    /// The unique identifier for the recipient's device.
    ///
    /// This UUID identifies the specific device that should receive the message.
    /// Multiple devices can be associated with the same user.
    public let deviceId: UUID

    /// The type of recipient for the message.
    ///
    /// Determines how the message should be processed and routed (e.g., individual user,
    /// group conversation, broadcast, etc.).
    public let recipient: MessageRecipient

    /// Optional metadata for transport layer processing.
    ///
    /// Contains additional information that may be needed by the transport layer
    /// for message delivery, but should not be included in the message payload.
    public let transportMetadata: Data?

    /// Logical / application shared identifier (chat, media, plaintext lookup).
    ///
    /// Stable across fan-out devices and orphan resends. Not the envelope MessageID.
    public let sharedMessageId: String

    /// §4.1 MessageID: unique per encrypted send to one recipient device.
    ///
    /// Replaced on every resend. Wire `MessagePacket.id` uses this value.
    public let envelopeMessageId: String

    /// An enum contains events that PQSSession needs to communicate with the transport
    ///
    public let transportEvent: TransportEvent?

    /// Whether the transport must request a server acceptance acknowledgment for this envelope.
    public let requiresServerAck: Bool

    /// Initializes a new instance of `SignedRatchetMessageMetadata`.
    ///
    /// - Parameters:
    ///   - secretName: The recipient's secret identifier for privacy-preserving communication
    ///   - deviceId: The unique identifier for the recipient's device
    ///   - recipient: The type of recipient for the message
    ///   - transportMetadata: Optional additional metadata for transport layer processing
    ///   - sharedMessageId: Logical shared identifier (stable across devices/resends)
    ///   - envelopeMessageId: Unique envelope MessageID for this encrypted envelope
    ///   - transportEvent: Optional transport event
    ///   - requiresServerAck: Whether the transport should request a server acceptance acknowledgment
    public init(
        secretName: String,
        deviceId: UUID,
        recipient: MessageRecipient,
        transportMetadata: Data?,
        sharedMessageId: String,
        envelopeMessageId: String,
        transportEvent: TransportEvent?,
        requiresServerAck: Bool = false
    ) {
        self.secretName = secretName
        self.deviceId = deviceId
        self.recipient = recipient
        self.transportMetadata = transportMetadata
        self.sharedMessageId = sharedMessageId
        self.envelopeMessageId = envelopeMessageId
        self.transportEvent = transportEvent
        self.requiresServerAck = requiresServerAck
    }
}

/// Ciphertext send path. Hosts typically also conform to ``PQSKeyDirectory`` and
/// ``PQSRecoveryTransport`` on the same type.
public protocol PQSTransport: Sendable {
    func sendMessage(_ message: SignedRatchetMessage,
                     metadata: SignedRatchetMessageMetadata) async throws

    func createUploadPacket(
        secretName: String,
        deviceId: UUID,
        recipient: MessageRecipient,
        metadata: Data
    ) async throws
}

/// Published configuration and one-time-key directory.
public protocol PQSKeyDirectory: Sendable {
    func findConfiguration(for secretName: String) async throws -> UserConfiguration

    func publishUserConfiguration(_ configuration: UserConfiguration, recipient secretName: String, recipient identity: UUID) async throws

    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> OneTimeKeys

    func fetchOneTimeKeyIdentities(for secretName: String, deviceId: String, type: KeyKind) async throws -> [UUID]

    func updateOneTimeKeys(for secretName: String, deviceId: String, keys: [UserConfiguration.SignedOneTimePublicKey]) async throws

    func updateOneTimeMLKEMKeys(for secretName: String, deviceId: String, keys: [UserConfiguration.SignedMLKEMOneTimeKey]) async throws

    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: KeyKind) async throws

    func deleteOneTimeKeys(for secretName: String, with id: String, type: KeyKind) async throws

    func publishRotatedKeys(
        for secretName: String,
        deviceId: String,
        rotated keys: RotatedPublicKeys
    ) async throws
}

/// Authenticated out-of-band resend. Hosts must implement these; there is no silent no-op.
public protocol PQSRecoveryTransport: Sendable {
    func sendOutOfBandResendRequest(
        failedEnvelopeMessageIds: [String],
        to secretName: String,
        deviceId: UUID,
        requestingDeviceId: UUID
    ) async throws

    func sendOutOfBandResendUnavailable(
        unavailableEnvelopeMessageIds: [String],
        to secretName: String,
        deviceId: UUID,
        respondingDeviceId: UUID
    ) async throws
}

/// Typical host transport: send + directory + OOB on one object.
public typealias PQSNetworkHost = PQSTransport & PQSKeyDirectory & PQSRecoveryTransport

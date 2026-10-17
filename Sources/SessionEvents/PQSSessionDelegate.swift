//
//  PQSSessionDelegate.swift
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
import class DoubleRatchetKit.SessionIdentity
import SessionModels

/// Typical host policy object: messaging + recovery on one type.
public typealias PQSHostDelegate = MessagingPolicy & RecoveryObserver

/// Application policy for persist, metadata, friendship, and delivery.
public protocol MessagingPolicy: Sendable {
    func synchronizeCommunication(
        recipient: MessageRecipient,
        sharedIdentifier: String,
        metadata: Data
    ) async throws

    func requestFriendshipStateChange(
        recipient: MessageRecipient,
        blockData: Data?,
        metadata: Data,
        currentState: FriendshipMetadata.State
    ) async throws

    func deliveryStateChanged(
        recipient: MessageRecipient,
        metadata: Data
    ) async throws

    func createdContact(
        recipient: MessageRecipient
    ) async throws

    func requestMetadata(
        recipient: MessageRecipient
    ) async throws

    func editMessage(
        recipient: MessageRecipient,
        metadata: Data
    ) async throws

    func shouldPersist(
        transportInfo: Data?
    ) -> Bool

    func shouldReplayNonPersistentOutbound(
        transportInfo: Data?
    ) -> Bool

    /// Whether a `.nickname` send is also encrypted to the sender's other linked
    /// devices. Defaults to `shouldPersist(transportInfo:)`; override to sync
    /// non-persisted controls (edits, reactions) without storing them as chat rows.
    func shouldSyncToSiblings(
        transportInfo: Data?
    ) -> Bool

    func retrieveUserInfo(
        _ transportInfo: Data?
    ) async -> (secretName: String, deviceId: String)?

    func updateCryptoMessageMetadata(
        _ message: CryptoMessage,
        sharedMessageId: String
    ) -> CryptoMessage

    func updateEncryptableMessageMetadata(
        _ message: SessionModels.EncryptedMessage,
        transportInfo: Data?,
        identity: SessionIdentity,
        recipient: MessageRecipient
    ) async -> SessionModels.EncryptedMessage

    func shouldFinishCommunicationSynchronization(
        _ transportInfo: Data?
    ) -> Bool

    func processMessage(
        _ message: CryptoMessage,
        senderSecretName: String,
        senderDeviceId: UUID
    ) async -> Bool

    func shouldSendAutomaticDeliveryReceipts() async -> Bool
}

public extension MessagingPolicy {
    func shouldSyncToSiblings(transportInfo: Data?) -> Bool {
        shouldPersist(transportInfo: transportInfo)
    }
}

/// Recovery, compromise, and identity-trust callbacks. Hosts must implement these.
public protocol RecoveryObserver: Sendable {
    func inboundRecoveryDeferred(
        senderSecretName: String,
        senderDeviceId: UUID,
        failedSharedMessageId: String,
        failureClass: String
    ) async

    func inboundMessagePendingRecovery(
        senderSecretName: String,
        senderDeviceId: UUID,
        sharedMessageId: String
    ) async

    func inboundCiphertextAccepted(sharedMessageId: String) async

    func inboundContentUnrecoverable(
        senderSecretName: String,
        senderDeviceId: UUID,
        sharedMessageId: String
    ) async

    func outboundMessageUnrecoverable(sharedMessageId: String, reason: String) async

    func reestablishmentEpisodeDidEnd(
        senderSecretName: String,
        senderDeviceId: UUID
    ) async

    func linkedDeviceReportedPotentialCompromise(deviceId: UUID, intentId: UUID?) async

    func peerAccountIdentityChanged(
        secretName: String,
        deviceId: UUID,
        failedSharedMessageId: String?
    ) async

    func shouldSuppressInboundRecoveryFromSender(_ senderSecretName: String) async -> Bool

    func preferredOnlinePeerDeviceId(for secretName: String) async -> UUID?

    /// The directory reports a per-device signing key for this master device that
    /// differs from the one it holds, and no rotation of ours is pending persistence.
    /// PQS no longer rotates the account key on its own in this state (a directory
    /// could otherwise force identity-change prompts on every contact at will); the
    /// host decides whether to call `rotateKeysOnPotentialCompromise()`.
    func accountSigningKeyMismatchRequiresAttention() async
}

public extension RecoveryObserver {
    func accountSigningKeyMismatchRequiresAttention() async {}
}

//
//  EventReceiver.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-18.
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

import SessionModels

/// Host callbacks for persisted message, contact, and conversation mutations.
///
/// Callback names use past-participle + noun (`createdMessage`, `createdContact`).
public protocol MessageStoreObserver: Sendable {
    func createdMessage(_ message: EncryptedMessage) async
    func updatedMessage(_ message: EncryptedMessage) async
    func deletedMessage(_ message: EncryptedMessage) async
    func createdContact(_ contact: Contact) async throws
    func removedCommunication(_ type: MessageRecipient) async throws
    func synchronize(
        contact: Contact,
        requestFriendship: Bool,
        notifyPeerOfCreation: Bool
    ) async throws
    func transportContactMetadata() async throws
    func pushContactMetadata(to secretName: String) async throws
    func updateContact(_ contact: Contact) async throws
    func contactMetadata(changed for: Contact) async
    func updatedCommunication(_ model: BaseCommunication, members: Set<String>) async
    func createdChannel(_ model: BaseCommunication) async
}

//
//  MessageNotifier.swift
//  needletail-crypto
//
//  Created by Cole M on 9/18/24.
//

import SessionModels

public protocol EventReceiver: Sendable {

    func createdMessage(_ message: EncryptedMessage) async
    func updatedMessage(_ message: EncryptedMessage) async
    func deletedMessage(_ message: EncryptedMessage) async
    func createdContact(_ contact: Contact) async throws
    func removedContact(_ secrectName: String) async throws
    func synchronize(contact: Contact, requestFriendship: Bool) async throws
    func transportContactMetadata() async throws
    func updateContact(_ contact: Contact) async throws
    func contactMetadata(changed for: Contact) async
    func updatedCommunication(_ model: BaseCommunication, members: Set<String>) async
}


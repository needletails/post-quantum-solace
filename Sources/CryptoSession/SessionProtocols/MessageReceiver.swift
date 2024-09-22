//
//  MessageNotifier.swift
//  needletail-crypto
//
//  Created by Cole M on 9/18/24.
//

import DoubleRatchetKit

public protocol NTMessageReceiver: Codable, Sendable {
    func createdMessage(_ message: MessageModel) async
    func updatedMessage(_ message: MessageModel) async
    func createContact(_ contact: Contact) async
    func contactMetadata(changed for: Contact) async
}

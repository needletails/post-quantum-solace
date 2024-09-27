//
//  MessageNotifier.swift
//  needletail-crypto
//
//  Created by Cole M on 9/18/24.
//

import DoubleRatchetKit

public protocol NTMessageReceiver: Sendable {
    func createdMessage(_ message: PrivateMessage) async
    func updatedMessage(_ message: PrivateMessage) async
    func createContact(_ contact: Contact) async
    func contactMetadata(changed for: Contact) async
}

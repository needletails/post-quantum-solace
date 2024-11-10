//
//  MessageNotifier.swift
//  needletail-crypto
//
//  Created by Cole M on 9/18/24.
//

import DoubleRatchetKit
import Crypto

public protocol NTMessageReceiver: Sendable {
    func receivedLocalNudge(_ message: CryptoMessage) async
    func createdMessage(_ message: PrivateMessage) async
    func updatedMessage(_ message: PrivateMessage) async
    func deletedMessage(_ message: PrivateMessage) async
    func createContact(_ contact: Contact, needsSynchronization: Bool) async throws
    func updateContact(_ contact: Contact) async throws
    func contactMetadata(changed for: Contact) async
    func newDeviceRequest(configuration: UserDeviceConfiguration) async
    func passDCCKey(_ key: SymmetricKey) async
}

//
//  CryptoSessionDelegate.swift
//  crypto-session
//
//  Created by Cole M on 4/19/25.
//

import Foundation
import SessionModels
import struct BSON.Document
import struct BSON.BSONDecoder
import class DoubleRatchetKit.SessionIdentity

public protocol CryptoSessionDelegate: Sendable {
    
    func communicationSynchonization(recipient: MessageRecipient, sharedIdentifier: String) async throws
    func blockUnblock(recipient: MessageRecipient, data: Data?, metadata: Document, myState: FriendshipMetadata.State) async throws
    func deliveryStateChanged(recipient: MessageRecipient, metadata: Document) async throws
    func contactCreated(recipient: MessageRecipient) async throws
    func requestMetadata(recipient: MessageRecipient) async throws
    func editMessage(recipient: MessageRecipient, metadata: Document) async throws
    func shouldPersist(transportInfo: Data?) -> Bool
    func getUserInfo(_ transportInfo: Data?) async throws -> (secretName: String, deviceId: String)?
    //Update the CryptoMessage Metadata Before Encryption
    func updateCryptoMessageMetadata(_ message: CryptoMessage, sharedMessageId: String) throws -> CryptoMessage
    //Update the Encrypted Metadata After Encryption and Before the message is fed to the transport
    func updateEncryptableMessageMetadata(_
                                            message: SessionModels.EncryptedMessage,
                                            transportInfo: Data?,
                                            identity: SessionIdentity,
                                            recipient: MessageRecipient
    ) async throws -> SessionModels.EncryptedMessage
    func shouldFinishCommunicationSynchronization(_ transportInfo: Data?) -> Bool
    func processUnpersistedMessage(_
                                   message: CryptoMessage,
                                   senderSecretName: String,
                                   senderDeviceId: UUID
    ) async throws
}

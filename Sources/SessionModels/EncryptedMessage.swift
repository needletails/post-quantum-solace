//
//  EncryptedMessage.swift
//  crypto-session
//
//  Created by Cole M on 4/18/25.
//
import Foundation
import DoubleRatchetKit
import NIOConcurrencyHelpers
import NeedleTailCrypto
import Crypto
import BSON

public struct _EncryptedMessage: Sendable, Codable, Equatable {
    public let id: UUID
    public var base: BaseCommunication
    public let sendDate: Date
    public let receiveDate: Date?
    public var deliveryState: DeliveryState
    public var message: CryptoMessage
    public let sendersSecretName: String
    public let sendersDeviceId: UUID
    
    public static func == (lhs: _EncryptedMessage, rhs: _EncryptedMessage) -> Bool {
        return lhs.id == rhs.id
    }
}

/// This model represents a message and provides an interface for working with encrypted data.
/// The public interface is for creating local models to be saved to the database as encrypted data.
public final class EncryptedMessage: SecureModelProtocol, @unchecked Sendable, Hashable {
    
    public let id: UUID
    public let communicationId: UUID
    public let sessionContextId: Int
    public let sharedId: String
    public let sequenceNumber: Int
    public var data: Data
    
    private let lock = NIOLock()
    private let crypto = NeedleTailCrypto()
    
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case id
        case communicationId = "a"
        case sessionContextId = "b"
        case sharedId = "c"
        case sequenceNumber = "d"
        case data = "e"
    }

    /// Asynchronously retrieves the decrypted properties, if available.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }

    /// Struct representing the unwrapped properties of the message.
    /// A struct representing the properties of a message in a communication, including its delivery state and timestamps.
    public struct UnwrappedProps: Codable, Sendable, CommunicationProtocol {
        /// The base object for all Communication Types
        public var base: BaseCommunication
        /// The date and time when the message was sent.
        public let sendDate: Date
        /// The date and time when the message was received.
        public let receiveDate: Date?
        /// The current delivery state of the message.
        public var deliveryState: DeliveryState
        /// The message content.
        public var message: CryptoMessage
        /// The sender's secret name, which may be used for privacy.
        public let sendersSecretName: String
        /// The unique identifier for the sender's identity.
        public let sendersDeviceId: UUID
        
        // MARK: - Coding Keys
        private enum CodingKeys: String, CodingKey, Codable, Sendable {
            case base = "a"
            case sendDate = "b"
            case receiveDate = "c"
            case deliveryState = "d"
            case message = "e"
            case sendersSecretName = "f"
            case sendersDeviceId = "g"
        }
        
        /// Initializes a new instance of `UnwrappedProps`.
        /// - Parameters:
        ///   - sendDate: The date and time when the message was sent.
        ///   - receiveDate: The date and time when the message was received.
        ///   - deliveryState: The current delivery state of the message.
        ///   - message: The content of the message.
        ///   - sendersSecretName: The sender's secret name.
        ///   - sendersDeviceId: The unique identifier for the sender's identity.
        public init(
            base: BaseCommunication,
            sendDate: Date,
            receiveDate: Date? = nil,
            deliveryState: DeliveryState,
            message: CryptoMessage,
            sendersSecretName: String,
            sendersDeviceId: UUID
        ) {
            self.base = base
            self.sendDate = sendDate
            self.receiveDate = receiveDate
            self.deliveryState = deliveryState
            self.message = message
            self.sendersSecretName = sendersSecretName
            self.sendersDeviceId = sendersDeviceId
        }
    }
    
    /// Initializes a new MessageModel instance.
    /// - Parameters:
    ///   - communicationIdentity: The ID of the communication.
    ///   - senderIdentity: The ID of the sender.
    ///   - sharedMessageIdentity: The remote ID associated with the message.
    ///   - sequenceId: The sequenceId of the message in the communication.
    ///   - props: The unwrapped properties of the message.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if encryption fails.
    public init(
        id: UUID,
        communicationId: UUID,
        sessionContextId: Int,
        sharedId: String,
        sequenceNumber: Int,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.id = id
        self.communicationId = communicationId
        self.sessionContextId = sessionContextId
        self.sharedId = sharedId
        self.sequenceNumber = sequenceNumber
        
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    public init(
        id: UUID,
        communicationId: UUID,
        sessionContextId: Int,
        sharedId: String,
        sequenceNumber: Int,
        data: Data
    ) throws {
        self.id = id
        self.communicationId = communicationId
        self.sessionContextId = sessionContextId
        self.sharedId = sharedId
        self.sequenceNumber = sequenceNumber
        self.data = data
    }
    
    
    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    /// - Throws: An error if decryption fails.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        lock.lock()
        defer {
            lock.unlock()
        }
        guard let decrypted = try crypto.decrypt(data: self.data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionFailed
        }
        return try BSONDecoder().decodeData(UnwrappedProps.self, from: decrypted)
    }
    
    /// Asynchronously updates the properties of the model.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - props: The new unwrapped properties to be set.
    /// - Returns: The updated decrypted properties.
    /// - Throws: An error if encryption fails.
    public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps? {
        lock.lock()
        do {
            let data = try BSONEncoder().encodeData(props)
            guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
                throw CryptoError.encryptionFailed
            }
            self.data = encryptedData
            lock.unlock()
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            lock.unlock()
            throw error
        }
    }
    
    public func updateMessage(with props: UnwrappedProps, symmetricKey: SymmetricKey) async throws -> EncryptedMessage {
        lock.lock()
        defer {
            lock.unlock()
        }
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return self
    }
    
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw CryptoError.propsError
        }
        return _EncryptedMessage(
            id: id,
            base: props.base,
            sendDate: props.sendDate,
            receiveDate: props.receiveDate,
            deliveryState: props.deliveryState,
            message: props.message,
            sendersSecretName: props.sendersSecretName,
            sendersDeviceId: props.sendersDeviceId) as! T
    }
    
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Data, with key: String) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.message.metadata[key] = metadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }
    
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Data, with key: String) async throws -> EncryptedMessage {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.message.metadata[key] = metadata
        return try await updateMessage(with: props, symmetricKey: symmetricKey)
    }
    
    public static func == (lhs: EncryptedMessage, rhs: EncryptedMessage) -> Bool {
        return lhs.id == rhs.id
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

/// An enumeration representing the delivery state of a message in a communication.
public enum DeliveryState: Codable, Sendable, Equatable {
    /// The message has been successfully delivered to the recipient.
    case delivered
    /// The message has been read by the recipient.
    case read
    /// The message has been received by the recipient's device but not yet read.
    case received
    /// The message is currently waiting to be delivered (e.g., due to network issues).
    case waitingDelivery
    /// The message has not been sent or is in an undefined state.
    case none
    /// The message has been blocked from being delivered (e.g., by the recipient's settings).
    case blocked
    /// The message failed to be delivered due to an error (e.g., network failure).
    case failed(String)
    /// The message is in the process of being sent but has not yet been delivered.
    case sending
    /// The message has been scheduled for delivery at a later time.
    case scheduled(Date)
}

public struct CryptoMessage: Codable, Sendable {
    public var text: String
    public var metadata: Document
    public var recipient: MessageRecipient
    public var transportInfo: Data?
    public let sentDate: Date
    public let destructionTime: TimeInterval?
    public var updatedDate: Date?
    
    private enum CodingKeys: String, CodingKey, Codable, Sendable {
        case text = "a"
        case metadata = "b"
        case recipient = "c"
        case transportInfo = "d"
        case sentDate = "e"
        case destructionTime = "f"
        case updatedDate = "g"
    }
    
    public init(
        text: String,
        metadata: Document,
        recipient: MessageRecipient,
        transportInfo: Data? = nil,
        sentDate: Date,
        destructionTime: TimeInterval?,
        updatedDate: Date? = nil
    ) {
        self.text = text
        self.metadata = metadata
        self.recipient = recipient
        self.transportInfo = transportInfo
        self.sentDate = sentDate
        self.destructionTime = destructionTime
        self.updatedDate = updatedDate
    }
}

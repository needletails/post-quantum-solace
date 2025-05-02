//
//  BaseCommunication.swift
//  crypto-session
//
//  Created by Cole M on 4/18/25.
//

//
import Foundation
import Crypto
import BSON
import NeedleTailCrypto
import DoubleRatchetKit

/// A protocol that defines the requirements for communication models.
/// Conforms to `Codable` and `Sendable` to ensure that implementations can be serialized and sent across threads.
public protocol CommunicationProtocol: Codable & Sendable {
    /// The base communication object associated with the communication model.
    var base: BaseCommunication { get }
}


/// A struct representing a communication model in a messaging system.
/// Conforms to `Sendable` and `Codable` for thread safety and serialization.
public struct Communication: Sendable & Codable {
    public let id: UUID
    public let sharedId: UUID?
    public var messageCount: Int
    public var administrator: String?
    public var operators: Set<String>?
    public var members: Set<String>
    public let blockedMembers: Set<String>
    public var metadata: Document
    public var communicationType: MessageRecipient
}


/// A base class for communication models that provides encryption and decryption capabilities.
/// Conforms to `Codable` and `@unchecked Sendable` for serialization and thread safety.
public final class BaseCommunication: Codable, @unchecked Sendable {
    public let id: UUID
    public var data: Data
    
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id, data = "a"
    }
    
    /// Asynchronously retrieves the decrypted properties of the communication model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties as `UnwrappedProps`.
    /// - Throws: An error if decryption fails.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }
    
    /// A struct representing the unwrapped properties of a communication model.
    public struct UnwrappedProps: Codable & Sendable {
        private enum CodingKeys: String, CodingKey, Codable, Sendable {
            case sharedId = "a"
            case messageCount = "b"
            case administrator = "c"
            case members = "d"
            case operators = "e"
            case blockedMembers = "f"
            case metadata = "g"
            case communicationType = "h"
        }
        
        public var sharedId: UUID?
        public var messageCount: Int
        public var administrator: String?
        public var operators: Set<String>?
        public var members: Set<String>
        public let blockedMembers: Set<String>
        public var metadata: Document
        public var communicationType: MessageRecipient
        
        /// Initializes a new instance of `UnwrappedProps`.
        public init(
            sharedId: UUID? = nil,
            messageCount: Int,
            administrator: String? = nil,
            operators: Set<String>? = nil,
            members: Set<String>,
            metadata: Document,
            blockedMembers: Set<String>,
            communicationType: MessageRecipient
        ) {
            self.sharedId = sharedId
            self.messageCount = messageCount
            self.administrator = administrator
            self.operators = operators
            self.members = members
            self.metadata = metadata
            self.blockedMembers = blockedMembers
            self.communicationType = communicationType
        }
    }
    
    /// Initializes a new instance of `BaseCommunication` with encrypted properties.
    /// - Parameters:
    ///   - id: The unique identifier for the communication.
    ///   - props: The unwrapped properties to be encrypted.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if encryption fails.
    public init(
        id: UUID,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.id = id
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    /// Initializes a new instance of `BaseCommunication` with existing encrypted data.
    /// - Parameters:
    ///   - id: The unique identifier for the communication.
    ///   - data: The encrypted data associated with the communication.
    public init(
        id: UUID,
        data: Data
    ) {
        self.id = id
        self.data = data
    }
    
    /// Asynchronously decrypts the properties of the communication model.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties as `UnwrappedProps`.
    /// - Throws: An error if decryption fails.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        let crypto = NeedleTailCrypto()
        guard let decrypted = try crypto.decrypt(data: self.data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionFailed
        }
        return try BSONDecoder().decodeData(UnwrappedProps.self, from: decrypted)
    }
    
    /// Asynchronously updates the properties of the communication model.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - props: The new unwrapped properties to be set.
    /// - Returns: The updated decrypted properties as `UnwrappedProps`.
    /// - Throws: An error if encryption fails.
    public func updateProps(symmetricKey: SymmetricKey, props: Codable & Sendable) async throws -> UnwrappedProps? {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return try await decryptProps(symmetricKey: symmetricKey)
    }
    
    /// Creates a decrypted model of the specified type from the communication properties.
    /// - Parameters:
    ///   - of: The type of the model to create, which must conform to `Sendable` and `Codable`.
    ///   - symmetricKey: The symmetric key used for decryption.
    /// - Returns: An instance of the specified type populated with the decrypted properties.
    /// - Throws: An error if decryption fails or if the properties cannot be converted to the specified type.
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw CryptoError.propsError
        }
        return Communication(
            id: id,
            sharedId: props.sharedId,
            messageCount: props.messageCount,
            members: props.members,
            blockedMembers: props.blockedMembers,
            metadata: props.metadata,
            communicationType: props.communicationType
        ) as! T
    }
}

/// An enumeration representing the different types of message recipients in a messaging network.
/// Conforms to `Codable`, `Sendable`, and `Equatable` for serialization, thread safety, and comparison.
public enum MessageRecipient: Codable, Sendable, Equatable {
    /// A personal message intended for the user, visible across all their devices and to others on the network.
    case personalMessage
    
    /// A recipient identified by a nickname.
    /// This case is used when sending a message to a user identified by their chosen nickname.
    case nickname(String)
    
    /// A recipient identified by a channel name.
    /// This case is used when sending a message to a specific channel where multiple users can participate.
    case channel(String)
    
    /// A recipient for broadcast messages sent to multiple users.
    /// This case is used for messages intended to be sent to all users in the network or a specific group.
    case broadcast
    
    /// Computed property to derive the nickname string if applicable.
    public var nicknameDescription: String {
        switch self {
        case .nickname(let name):
            return name
        default:
            fatalError("Invalid Recipient Type")
        }
    }
}

//
//  ContactModel.swift
//  crypto-session
//
//  Created by Cole M on 9/18/24.
//


import Foundation
import BSON
import NeedleTailCrypto
import DoubleRatchetKit
import Crypto
import NIOConcurrencyHelpers

/// A struct representing a contact in the messaging system.
/// Conforms to `Sendable`, `Codable`, and `Equatable` for thread safety, serialization, and comparison.
public struct Contact: Sendable, Codable, Equatable {
    /// The unique identifier for the contact.
    public let id: UUID
    
    /// The secret name associated with the contact, used for identification.
    public let secretName: String
    
    /// The user configuration settings for the contact.
    public var configuration: UserConfiguration
    
    /// Additional metadata associated with the contact.
    public var metadata: Document
    
    /// Initializes a new instance of `Contact`.
    /// - Parameters:
    ///   - id: The unique identifier for the contact.
    ///   - secretName: The secret name associated with the contact.
    ///   - configuration: The user configuration settings for the contact.
    ///   - metadata: Additional metadata associated with the contact.
    public init(id: UUID, secretName: String, configuration: UserConfiguration, metadata: Document) {
        self.id = id
        self.secretName = secretName
        self.configuration = configuration
        self.metadata = metadata
    }
}


/// A class representing a secure model for a contact in the messaging system.
/// Conforms to `SecureModelProtocol`, `Codable`, and `@unchecked Sendable` for serialization and thread safety.
public final class ContactModel: SecureModelProtocol, Codable, @unchecked Sendable {
    
    /// The unique identifier for the contact model.
    public let id: UUID
    
    /// The encrypted data associated with the contact model.
    public var data: Data
    
    /// A lock for synchronizing access to the model's properties.
    private let lock = NIOLock()
    
    /// An instance of the cryptographic utility used for encryption and decryption.
    private let crypto = NeedleTailCrypto()
    
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id = "a"
        case data = "b"
    }
    
    /// Asynchronously retrieves the decrypted properties of the contact model, if available.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties as `UnwrappedProps`, or `nil` if decryption fails.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }
    
    /// A struct representing the unwrapped properties of a contact model.
    public struct UnwrappedProps: Codable, Sendable {
        private enum CodingKeys: String, CodingKey, Sendable {
            case secretName = "a"
            case configuration = "b"
            case metadata = "c"
        }
        
        /// The secret name associated with the contact.
        public let secretName: String
        
        /// The user configuration settings for the contact.
        public var configuration: UserConfiguration
        
        /// Additional metadata associated with the contact.
        public var metadata: Document
        
        /// Initializes a new instance of `UnwrappedProps`.
        public init(
            secretName: String,
            configuration: UserConfiguration,
            metadata: Document
        ) {
            self.secretName = secretName
            self.configuration = configuration
            self.metadata = metadata
        }
    }
    
    /// Initializes a new instance of `ContactModel` with encrypted properties.
    /// - Parameters:
    ///   - id: The unique identifier for the contact model.
    ///   - props: The unwrapped properties to be encrypted.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if encryption fails.
    public init(
        id: UUID,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.id = id
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    /// Initializes a new instance of `ContactModel` with existing encrypted data.
    /// - Parameters:
    ///   - id: The unique identifier for the contact model.
    ///   - data: The encrypted data associated with the contact model.
    public init(
        id: UUID,
        data: Data
    ) {
        self.id = id
        self.data = data
    }
    
    /// Asynchronously decrypts the properties of the contact model.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties as `UnwrappedProps`.
    /// - Throws: An error if decryption fails.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        lock.lock()
        defer { lock.unlock() }
        guard let decrypted = try crypto.decrypt(data: self.data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionFailed
        }
        return try BSONDecoder().decodeData(UnwrappedProps.self, from: decrypted)
    }
    
    /// Asynchronously updates the properties of the contact model.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - props: The new unwrapped properties to be set.
    /// - Returns: The updated decrypted properties as `UnwrappedProps`.
    /// - Throws: An error if encryption fails.
    public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps? {
        lock.lock()
        let data = try BSONEncoder().encodeData(props)
        do {
            guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
                throw CryptoError.encryptionFailed
            }
            self.data = encryptedData
            lock.unlock()
            return try await self.decryptProps(symmetricKey: symmetricKey)
        } catch {
            lock.unlock()
            throw error
        }
    }
    
    /// Asynchronously updates the metadata of the contact model using the provided symmetric key.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - metadata: The new metadata to be set.
    ///   - key: The key under which the metadata will be stored.
    /// - Returns: The updated decrypted properties as `UnwrappedProps`.
    /// - Throws: An error if the update fails.
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Document, with key: String) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.metadata[key] = metadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }
    
    /// Asynchronously updates the metadata of the contact model using the provided symmetric key.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - metadata: The new metadata to be merged with the existing metadata.
    /// - Returns: The updated decrypted properties as `UnwrappedProps`.
    /// - Throws: An error if the update fails.
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Document) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        
        var newMetadata = props.metadata
        for key in metadata.keys {
            if let value = metadata[key] {
                newMetadata[key] = value
            }
        }
        props.metadata = newMetadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }
    
    /// Creates a decrypted model of the specified type from the contact properties.
    /// - Parameters:
    ///   - of: The type of the model to create, which must conform to `Sendable` and `Codable`.
    ///   - symmetricKey: The symmetric key used for decryption.
    /// - Returns: An instance of the specified type populated with the decrypted properties.
    /// - Throws: An error if decryption fails or if the properties cannot be converted to the specified type.
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw Errors.propsError
        }
        return Contact(
            id: id,
            secretName: props.secretName,
            configuration: props.configuration,
            metadata: props.metadata) as! T
    }
    
    /// Asynchronously updates the contact's metadata.
    /// - Parameters:
    ///   - metadata: The new contact metadata to be updated.
    ///   - symmetricKey: The symmetric key used for decryption.
    /// - Returns: The updated decrypted properties as `UnwrappedProps`.
    /// - Throws: An error if the update fails.
    public func updateContact(_ metadata: ContactMetadata, symmetricKey: SymmetricKey) async throws -> UnwrappedProps? {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw Errors.propsError
        }
        
        var contactMetadata: ContactMetadata
        if let metaDoc = props.metadata["contactMetadata"] as? Document, !metaDoc.isEmpty {
            // Decode the existing metadata
            contactMetadata = try props.metadata.decode(forKey: "contactMetadata")
            // Update properties only if they are not nil
            if let status = metadata.status {
                contactMetadata.status = status
            }
            if let nickname = metadata.nickname {
                contactMetadata.nickname = nickname
            }
            if let firstName = metadata.firstName {
                contactMetadata.firstName = firstName
            }
            if let lastName = metadata.lastName {
                contactMetadata.lastName = lastName
            }
            if let email = metadata.email {
                contactMetadata.email = email
            }
            if let image = metadata.image {
                contactMetadata.image = image
            }
        } else {
            contactMetadata = ContactMetadata(
                status: metadata.status,
                nickname: metadata.nickname,
                firstName: metadata.firstName,
                lastName: metadata.lastName,
                email: metadata.email,
                image: metadata.image)
        }
        
        let metadata = try BSONEncoder().encode(contactMetadata)
        // Encode the updated metadata
        return try await updatePropsMetadata(
            symmetricKey: symmetricKey,
            metadata: metadata,
            with: "contactMetadata")
    }
    
    /// An enumeration representing possible errors that can occur within the `ContactModel`.
    private enum Errors: Error {
        case propsError  // Indicates an error occurred while retrieving or updating properties.
    }
}





/// A structure representing metadata for a contact.
///
/// This struct conforms to the `Codable` and `Sendable` protocols, allowing it to be easily encoded and decoded
/// for data transfer and to be safely used across concurrent tasks.
///
/// ## Properties
/// - `status`: An optional string representing the contact's status (e.g., online, offline).
/// - `nickname`: An optional string representing the contact's nickname.
/// - `firstName`: An optional string representing the contact's first name.
/// - `lastName`: An optional string representing the contact's last name.
/// - `email`: An optional string representing the contact's email address.
/// - `phone`: An optional string representing the contact's phone number.
/// - `image`: An optional `Data` object representing the contact's image.
///
/// ## Methods
/// - `init(status:nickname:firstName:lastName:email:phone:image:)`: Initializes a new instance of `ContactMetadata`
///   with the provided values. All parameters are optional and default to `nil`.
/// - `updating(status:)`: Returns a new `ContactMetadata` instance with the updated status.
/// - `updating(nickname:)`: Returns a new `ContactMetadata` instance with the updated nickname.
/// - `updating(firstName:)`: Returns a new `ContactMetadata` instance with the updated first name.
/// - `updating(lastName:)`: Returns a new `ContactMetadata` instance with the updated last name.
/// - `updating(email:)`: Returns a new `ContactMetadata` instance with the updated email address.
/// - `updating(phone:)`: Returns a new `ContactMetadata` instance with the updated phone number.
/// - `updating(image:)`: Returns a new `ContactMetadata` instance with the updated image data.
public struct ContactMetadata: Codable, Sendable {
    public var status: String?
    public var nickname: String?
    public var firstName: String?
    public var lastName: String?
    public var email: String?
    public var phone: String?
    public var image: Data?
    
    public init(status: String? = nil, nickname: String? = nil, firstName: String? = nil, lastName: String? = nil, email: String? = nil, phone: String? = nil, image: Data? = nil) {
        self.status = status
        self.nickname = nickname
        self.firstName = firstName
        self.lastName = lastName
        self.email = email
        self.phone = phone
        self.image = image
    }
    
    public func updating(status: String) -> ContactMetadata {
        return ContactMetadata(
            status: status,
            nickname: self.nickname,
            firstName: self.firstName,
            lastName: self.lastName,
            email: self.email,
            phone: self.phone,
            image: self.image
        )
    }
    
    public func updating(nickname: String) -> ContactMetadata {
        return ContactMetadata(
            status: self.status,
            nickname: nickname,
            firstName: self.firstName,
            lastName: self.lastName,
            email: self.email,
            phone: self.phone,
            image: self.image
        )
    }
    
    public func updating(firstName: String) -> ContactMetadata {
        return ContactMetadata(
            status: self.status,
            nickname: self.nickname,
            firstName: firstName,
            lastName: self.lastName,
            email: self.email,
            phone: self.phone,
            image: self.image
        )
    }
    
    public func updating(lastName: String) -> ContactMetadata {
        return ContactMetadata(
            status: self.status,
            nickname: self.nickname,
            firstName: self.firstName,
            lastName: lastName,
            email: self.email,
            phone: self.phone,
            image: self.image
        )
    }
    
    public func updating(email: String) -> ContactMetadata {
        return ContactMetadata(
            status: self.status,
            nickname: self.nickname,
            firstName: self.firstName,
            lastName: self.lastName,
            email: email,
            phone: self.phone,
            image: self.image
        )
    }
    
    public func updating(phone: String) -> ContactMetadata {
        return ContactMetadata(
            status: self.status,
            nickname: self.nickname,
            firstName: self.firstName,
            lastName: self.lastName,
            email: self.email,
            phone: phone,
            image: self.image
        )
    }
    
    public func updating(image: Data) -> ContactMetadata {
        return ContactMetadata(
            status: self.status,
            nickname: self.nickname,
            firstName: self.firstName,
            lastName: self.lastName,
            email: self.email,
            phone: self.phone,
            image: image
        )
    }
}



/// A structure representing a data packet.
///
/// This struct conforms to the `Codable` and `Sendable` protocols, allowing it to be easily encoded and decoded
/// for data transfer and to be safely used across concurrent tasks.
///
/// ## Properties
/// - `id`: A unique identifier for the data packet, represented as a `UUID`.
/// - `data`: The actual data contained in the packet, represented as a `Data` object.
///
/// ## Initializer
/// - `init(id:data:)`: Initializes a new instance of `DataPacket` with the specified unique identifier and data.
public struct DataPacket: Codable, Sendable {
    public let id: UUID
    public var data: Data
    
    /// Initializes a new instance of `DataPacket`.
    ///
    /// - Parameters:
    ///   - id: A unique identifier for the data packet.
    ///   - data: The data to be contained in the packet.
    public init(id: UUID, data: Data) {
        self.id = id
        self.data = data
    }
}

/// A structure representing metadata for SDP (Session Description Protocol) negotiation.
///
/// This struct contains information about the offer and answer devices involved in the negotiation.
///
/// ## Properties
/// - `offerSecretName`: The secret name associated with the offer.
/// - `offerDeviceId`: The device ID of the participant making the offer.
/// - `answerDeviceId`: The device ID of the participant answering the offer.
///
/// ## Initializer
/// - `init(offerSecretName:offerDeviceId:answerDeviceId:)`: Initializes a new instance of `SDPNegotiationMetadata` with the specified values.
public struct SDPNegotiationMetadata: Codable, Sendable, Equatable {
    public let offerSecretName: String
    public let offerDeviceId: String
    public let answerDeviceId: String
    
    public init(
        offerSecretName: String,
        offerDeviceId: String,
        answerDeviceId: String
    ) {
        self.offerSecretName = offerSecretName
        self.offerDeviceId = offerDeviceId
        self.answerDeviceId = answerDeviceId
    }
}

/// A structure representing metadata for starting a call.
///
/// This struct contains information about the participants involved in the call and other relevant metadata.
///
/// ## Properties
/// - `offerParticipant`: The participant making the call offer.
/// - `answerParticipant`: The participant answering the call (optional).
/// - `sharedMessageId`: An optional identifier for a shared message related to the call.
/// - `communicationId`: A unique identifier for the communication session.
/// - `supportsVideo`: A boolean indicating whether video is supported for the call.
///
/// ## Initializer
/// - `init(offerParticipant:answerParticipant:sharedMessageId:communicationId:supportsVideo:)`: Initializes a new instance of `StartCallMetadata` with the specified values.
public struct StartCallMetadata: Codable, Sendable, Equatable {
    
    public let offerParticipant: Call.Participant
    public let answerParticipant: Call.Participant?
    public var sharedMessageId: String?
    public let communicationId: String
    public let supportsVideo: Bool
    
    public init(
        offerParticipant: Call.Participant,
        answerParticipant: Call.Participant? = nil,
        sharedMessageId: String? = nil,
        communicationId: String,
        supportsVideo: Bool
    ) {
        self.offerParticipant = offerParticipant
        self.answerParticipant = answerParticipant
        self.sharedMessageId = sharedMessageId
        self.communicationId = communicationId
        self.supportsVideo = supportsVideo
    }
}



/// A structure representing a call object.
///
/// A session can have many calls, including current, previous, and on-hold calls. Each call object can be encoded into data
/// and set on a base communication metadata. A call needs to contain an identifier for the base communication ID.
///
/// ## Properties
/// - `id`: A unique identifier for the call, represented as a `UUID`.
/// - `sharedMessageIdentifier`: An optional identifier for a shared message related to the call.
/// - `sharedCommunicationId`: A unique identifier for the shared communication session.
/// - `sender`: The participant who initiated the call.
/// - `recipients`: An array of participants who are receiving the call.
/// - `createdAt`: The date and time when the call was created.
/// - `updatedAt`: An optional date and time when the call was last updated.
/// - `endedAt`: An optional date and time when the call ended.
/// - `supportsVideo`: A boolean indicating whether the call supports video.
/// - `unanswered`: An optional boolean indicating whether the call was unanswered.
/// - `rejected`: An optional boolean indicating whether the call was rejected.
/// - `failed`: An optional boolean indicating whether the call failed.
/// - `isActive`: A boolean indicating whether the call is currently active.
/// - `metadata`: Additional metadata associated with the call, represented as a `Document`.
///
/// ## Initializer
/// - `init(id:sharedMessageIdentifier:sharedCommunicationId:sender:recipients:createdAt:updatedAt:endedAt:supportsVideo:unanswered:rejected:failed:isActive:metadata:)`: Initializes a new instance of `Call` with the specified values.
public struct Call: Sendable, Codable, Equatable {
    
    public struct Props: Sendable, Codable {
        public var id: UUID
        public var data: Data
        
        public init(id: UUID, data: Data) {
            self.id = id
            self.data = data
        }
    }
    
    public struct Participant: Sendable, Codable, Equatable {
        public let secretName: String
        public let nickname: String
        public var deviceId: String
        
        /// Initializes a new instance of `Participant`.
        ///
        /// - Parameters:
        ///   - secretName: The secret name of the participant.
        ///   - nickname: The nickname of the participant.
        ///   - deviceId: The device ID of the participant.
        public init(secretName: String, nickname: String, deviceId: String) {
            self.secretName = secretName
            self.nickname = nickname
            self.deviceId = deviceId
        }
    }
    
    public var id: UUID
    public var sharedMessageIdentifier: String?
    public var sharedCommunicationId: String
    public var sender: Participant
    public var recipients: [Participant]
    public var createdAt: Date
    public var updatedAt: Date?
    public var endedAt: Date?
    public var supportsVideo: Bool
    public var unanswered: Bool?
    public var rejected: Bool?
    public var failed: Bool?
    public var isActive: Bool
    public var metadata: Document
    
    /// Initializes a new instance of `Call`.
    ///
    /// - Parameters:
    ///   - id: A unique identifier for the call (defaults to a new UUID).
    ///   - sharedMessageIdentifier: An optional identifier for a shared message related to the call.
    ///   - sharedCommunicationId: A unique identifier for the shared communication session.
    ///   - sender: The participant who initiated the call.
    ///   - recipients: An array of participants who are receiving the call.
    ///   - createdAt: The date and time when the call was created (defaults to the current date).
    ///   - updatedAt: An optional date and time when the call was last updated.
    ///   - endedAt: An optional date and time when the call ended.
    ///   - supportsVideo: A boolean indicating whether the call supports video (defaults to false).
    ///   - unanswered: An optional boolean indicating whether the call was unanswered.
    ///   - rejected: An optional boolean indicating whether the call was rejected.
    ///   - failed: An optional boolean indicating whether the call failed.
    ///   - isActive: A boolean indicating whether the call is currently active (defaults to false).
    ///   - metadata: Additional metadata associated with the call (defaults to an empty document).
    public init(
        id: UUID = UUID(),
        sharedMessageIdentifier: String? = nil,
        sharedCommunicationId: String,
        sender: Participant,
        recipients: [Participant],
        createdAt: Date = Date(),
        updatedAt: Date? = nil,
        endedAt: Date? = nil,
        supportsVideo: Bool = false,
        unanswered: Bool? = nil,
        rejected: Bool? = nil,
        failed: Bool? = nil,
        isActive: Bool = false,
        metadata: Document = [:]
    ) {
        self.id = id
        self.sharedMessageIdentifier = sharedMessageIdentifier
        self.sharedCommunicationId = sharedCommunicationId
        self.sender = sender
        self.recipients = recipients
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.endedAt = endedAt
        self.supportsVideo = supportsVideo
        self.unanswered = unanswered
        self.rejected = rejected
        self.failed = failed
        self.isActive = isActive
        self.metadata = metadata
    }
}

extension Document {
    /// - Parameter key: document key to find and decode
    /// - Returns: the Codable object
    public func decode<T: Codable>(forKey key: String) throws -> T {
        guard let value = self[key] else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: [], debugDescription: "Key \(key) not found in document"))
        }
        guard let data = try BSONEncoder().encodePrimitive(value) else { throw Errors.primitiveIsNil }
        return try BSONDecoder().decode(T.self, fromPrimitive: data)
    }
    
    enum Errors: Error {
        case primitiveIsNil
    }
}

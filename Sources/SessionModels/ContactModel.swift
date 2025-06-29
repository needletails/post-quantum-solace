//
//  ContactModel.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/18/24.
//


import Foundation
import BSON
import NeedleTailCrypto
import DoubleRatchetKit
import Crypto
import NIOConcurrencyHelpers

/// A class representing a secure model for a contact in the messaging system.
/// 
/// This class provides encrypted storage for contact information, ensuring that sensitive contact data
/// is protected at rest. It implements the `SecureModelProtocol` to provide a consistent interface
/// for secure data models throughout the system.
///
/// ## Security Features
/// - All contact data is encrypted using symmetric key encryption
/// - Thread-safe operations with proper locking mechanisms
/// - Secure serialization and deserialization of contact properties
///
/// ## Usage
/// ```swift
/// let contactModel = try ContactModel(
///     id: UUID(),
///     props: ContactModel.UnwrappedProps(
///         secretName: "bob_secure",
///         configuration: UserConfiguration(),
///         metadata: ["trustLevel": "high"]
///     ),
///     symmetricKey: symmetricKey
/// )
/// ```
///
/// ## Thread Safety
/// This class uses `@unchecked Sendable` because it manages its own thread safety through
/// the `NIOLock` mechanism. All operations that modify the encrypted data are properly synchronized.
public final class ContactModel: SecureModelProtocol, Codable, @unchecked Sendable {
    
    /// The unique identifier for the contact model.
    /// This UUID serves as the primary key for the contact and is used for database operations.
    public let id: UUID
    
    /// The encrypted data associated with the contact model.
    /// Contains the serialized and encrypted contact properties. This data is opaque and
    /// requires the correct symmetric key for decryption.
    public var data: Data
    
    /// A lock for synchronizing access to the model's properties.
    /// Ensures thread-safe operations when reading or writing the encrypted data.
    private let lock = NIOLock()
    
    /// An instance of the cryptographic utility used for encryption and decryption.
    /// Provides the encryption/decryption capabilities for securing contact data.
    private let crypto = NeedleTailCrypto()
    
    /// Coding keys for serialization and deserialization.
    /// Uses abbreviated keys to minimize storage overhead while maintaining readability.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id = "a"
        case data = "b"
    }
    
    /// Asynchronously retrieves the decrypted properties of the contact model, if available.
    /// 
    /// This method attempts to decrypt the stored data using the provided symmetric key.
    /// If decryption fails, it returns `nil` instead of throwing an error, making it safe
    /// for scenarios where the key might be incorrect or the data corrupted.
    /// 
    /// - Parameter symmetricKey: The symmetric key used for decryption. Must be the same key
    ///   that was used for encryption.
    /// - Returns: The decrypted properties as `UnwrappedProps`, or `nil` if decryption fails.
    ///   The returned object contains all the contact's properties in a readable format.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }
    
    /// A struct representing the unwrapped properties of a contact model.
    /// 
    /// This struct contains the decrypted and deserialized contact data. It's used internally
    /// for working with contact properties in a readable format before re-encryption.
    ///
    /// ## Properties
    /// - `secretName`: The contact's secret name for identification
    /// - `configuration`: The contact's user configuration settings
    /// - `metadata`: Additional metadata stored as a BSON document
    public struct UnwrappedProps: Codable, Sendable {
        /// Coding keys for serialization and deserialization.
        /// Uses abbreviated keys to minimize storage overhead.
        private enum CodingKeys: String, CodingKey, Sendable {
            case secretName = "a"
            case configuration = "b"
            case metadata = "c"
        }
        
        /// The secret name associated with the contact.
        /// Used for secure identification in communications and database operations.
        public let secretName: String
        
        /// The user configuration settings for the contact.
        /// Contains preferences, security settings, and other configuration options.
        public var configuration: UserConfiguration
        
        /// Additional metadata associated with the contact.
        /// Flexible storage for contact-specific information using BSON document format.
        public var metadata: Document
        
        /// Initializes a new instance of `UnwrappedProps`.
        /// 
        /// Creates a new unwrapped properties object with the specified contact information.
        /// 
        /// - Parameters:
        ///   - secretName: The secret name for the contact
        ///   - configuration: The user configuration settings
        ///   - metadata: Additional metadata as a BSON document
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
    /// 
    /// Creates a new contact model by encrypting the provided properties using the specified
    /// symmetric key. The properties are serialized to BSON format before encryption.
    /// 
    /// - Parameters:
    ///   - id: The unique identifier for the contact model. Should be a valid UUID.
    ///   - props: The unwrapped properties to be encrypted. Contains all contact information.
    ///   - symmetricKey: The symmetric key used for encryption. Must be kept secure.
    /// - Throws: `CryptoError.encryptionFailed` if the encryption process fails.
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
    /// 
    /// Creates a contact model from pre-existing encrypted data. This is typically used
    /// when loading contact data from persistent storage.
    /// 
    /// - Parameters:
    ///   - id: The unique identifier for the contact model. Should match the original contact ID.
    ///   - data: The encrypted data associated with the contact model. Must be valid encrypted data.
    public init(
        id: UUID,
        data: Data
    ) {
        self.id = id
        self.data = data
    }
    
    /// Asynchronously decrypts the properties of the contact model.
    /// 
    /// Decrypts the stored data using the provided symmetric key and deserializes it into
    /// an `UnwrappedProps` object. This method is thread-safe and handles the decryption
    /// process internally.
    /// 
    /// - Parameter symmetricKey: The symmetric key used for decryption. Must be the same key
    ///   that was used for encryption.
    /// - Returns: The decrypted properties as `UnwrappedProps` containing all contact information.
    /// - Throws: `CryptoError.decryptionFailed` if decryption fails, or a decoding error if
    ///   the decrypted data cannot be deserialized.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        lock.lock()
        defer { lock.unlock() }
        guard let decrypted = try crypto.decrypt(data: self.data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionFailed
        }
        return try BSONDecoder().decodeData(UnwrappedProps.self, from: decrypted)
    }
    
    /// Asynchronously updates the properties of the contact model.
    /// 
    /// Updates the contact's properties by encrypting the new data and replacing the existing
    /// encrypted data. This operation is atomic and thread-safe.
    /// 
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption. Must be kept secure.
    ///   - props: The new unwrapped properties to be set. Replaces all existing properties.
    /// - Returns: The updated decrypted properties as `UnwrappedProps` for verification.
    /// - Throws: `CryptoError.encryptionFailed` if encryption fails, or other errors from
    ///   the serialization process.
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
    /// 
    /// Updates a specific metadata key with new data while preserving all other contact properties.
    /// This method is useful for updating individual pieces of metadata without affecting
    /// the rest of the contact information.
    /// 
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption and decryption.
    ///   - metadata: The new metadata to be set. Will replace the existing metadata for the specified key.
    ///   - key: The key under which the metadata will be stored. Must be a valid string.
    /// - Returns: The updated decrypted properties as `UnwrappedProps` for verification.
    /// - Throws: Various errors if decryption, encryption, or serialization fails.
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Document, with key: String) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.metadata[key] = metadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }
    
    /// Asynchronously updates the metadata of the contact model using the provided symmetric key.
    /// 
    /// Merges new metadata with existing metadata, updating only the keys that are present
    /// in the new metadata while preserving all other existing metadata.
    /// 
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption and decryption.
    ///   - metadata: The new metadata to be merged with the existing metadata. Only keys present
    ///     in this metadata will be updated.
    /// - Returns: The updated decrypted properties as `UnwrappedProps` for verification.
    /// - Throws: Various errors if decryption, encryption, or serialization fails.
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
    /// 
    /// This method creates a decrypted `Contact` object from the encrypted contact model.
    /// It's useful for converting the secure model back to a regular contact object for
    /// use in the application layer.
    /// 
    /// - Parameters:
    ///   - of: The type of the model to create, which must conform to `Sendable` and `Codable`.
    ///     Currently supports `Contact` type.
    ///   - symmetricKey: The symmetric key used for decryption.
    /// - Returns: An instance of the specified type populated with the decrypted properties.
    /// - Throws: `Errors.propsError` if decryption fails, or other errors from the conversion process.
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
    /// 
    /// Updates the contact's metadata with new information, merging it with existing metadata
    /// if present. This method specifically handles `ContactMetadata` objects and provides
    /// intelligent merging of properties.
    /// 
    /// - Parameters:
    ///   - metadata: The new contact metadata to be updated. Only non-nil properties will be updated.
    ///   - symmetricKey: The symmetric key used for encryption and decryption.
    /// - Returns: The updated decrypted properties as `UnwrappedProps` for verification.
    /// - Throws: `Errors.propsError` if decryption fails, or other errors from the update process.
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
    /// 
    /// Defines the specific error types that can be thrown by the contact model operations.
    private enum Errors: Error {
        /// Indicates an error occurred while retrieving or updating properties.
        /// This typically happens when decryption fails or properties cannot be accessed.
        case propsError
    }
}

/// A structure representing metadata for SDP (Session Description Protocol) negotiation.
///
/// This struct contains information about the participants involved in WebRTC session
/// negotiation, including the offer and answer devices. It's used for establishing
/// secure peer-to-peer connections for voice and video calls.
///
/// ## Usage
/// ```swift
/// let sdpMetadata = SDPNegotiationMetadata(
///     offerSecretName: "alice_secure",
///     offerDeviceId: "device_123",
///     answerDeviceId: "device_456"
/// )
/// ```
///
/// ## Properties
/// - `offerSecretName`: The secret name associated with the participant making the offer
/// - `offerDeviceId`: The device ID of the participant making the offer
/// - `answerDeviceId`: The device ID of the participant answering the offer
///
/// ## WebRTC Integration
/// This metadata is used in conjunction with WebRTC to establish secure peer-to-peer
/// connections for real-time communication features.
//public struct SDPNegotiationMetadata: Codable, Sendable, Equatable {
//    /// The secret name associated with the offer.
//    /// Used to identify the participant making the WebRTC offer.
//    public let offerSecretName: String
//    
//    /// The device ID of the participant making the offer.
//    /// Identifies the specific device initiating the connection.
//    public let offerDeviceId: String
//    
//    /// The device ID of the participant answering the offer.
//    /// Identifies the specific device accepting the connection.
//    public let answerDeviceId: String
//    
//    /// Initializes a new instance of `SDPNegotiationMetadata`.
//    /// 
//    /// Creates SDP negotiation metadata with the specified participant information.
//    /// 
//    /// - Parameters:
//    ///   - offerSecretName: The secret name of the participant making the offer
//    ///   - offerDeviceId: The device ID of the participant making the offer
//    ///   - answerDeviceId: The device ID of the participant answering the offer
//    public init(
//        offerSecretName: String,
//        offerDeviceId: String,
//        answerDeviceId: String
//    ) {
//        self.offerSecretName = offerSecretName
//        self.offerDeviceId = offerDeviceId
//        self.answerDeviceId = answerDeviceId
//    }
//}

/// A structure representing metadata for starting a call.
///
/// This struct contains comprehensive information about the participants involved in a call
/// and other relevant metadata needed to establish the communication session. It's used
/// for both voice and video calls.
///
/// ## Usage
/// ```swift
/// let callMetadata = StartCallMetadata(
///     offerParticipant: Call.Participant(
///         secretName: "alice_secure",
///         nickname: "Alice",
///         deviceId: "device_123"
///     ),
///     answerParticipant: Call.Participant(
///         secretName: "bob_secure",
///         nickname: "Bob",
///         deviceId: "device_456"
///     ),
///     sharedMessageId: "msg_789",
///     communicationId: "comm_123",
///     supportsVideo: true
/// )
/// ```
///
/// ## Properties
/// - `offerParticipant`: The participant making the call offer
/// - `answerParticipant`: The participant answering the call (optional for group calls)
/// - `sharedMessageId`: An optional identifier for a shared message related to the call
/// - `communicationId`: A unique identifier for the communication session
/// - `supportsVideo`: A boolean indicating whether video is supported for the call
//public struct StartCallMetadata: Codable, Sendable, Equatable {
//    
//    /// The participant making the call offer.
//    /// Contains the secret name, nickname, and device ID of the caller.
//    public let offerParticipant: Call.Participant
//    
//    /// The participant answering the call (optional).
//    /// For group calls, this may be nil as multiple participants can answer.
//    public let answerParticipant: Call.Participant?
//    
//    /// An optional identifier for a shared message related to the call.
//    /// Used to associate the call with a specific message or conversation thread.
//    public var sharedMessageId: String?
//    
//    /// A unique identifier for the communication session.
//    /// Used to track and manage the call throughout its lifecycle.
//    public let communicationId: String
//    
//    /// A boolean indicating whether video is supported for the call.
//    /// Determines if the call will be audio-only or include video capabilities.
//    public let supportsVideo: Bool
//    
//    /// Initializes a new instance of `StartCallMetadata`.
//    /// 
//    /// Creates call metadata with the specified participant information and call settings.
//    /// 
//    /// - Parameters:
//    ///   - offerParticipant: The participant making the call offer
//    ///   - answerParticipant: The participant answering the call (optional for group calls)
//    ///   - sharedMessageId: An optional identifier for a shared message related to the call
//    ///   - communicationId: A unique identifier for the communication session
//    ///   - supportsVideo: A boolean indicating whether video is supported for the call
//    public init(
//        offerParticipant: Call.Participant,
//        answerParticipant: Call.Participant? = nil,
//        sharedMessageId: String? = nil,
//        communicationId: String,
//        supportsVideo: Bool
//    ) {
//        self.offerParticipant = offerParticipant
//        self.answerParticipant = answerParticipant
//        self.sharedMessageId = sharedMessageId
//        self.communicationId = communicationId
//        self.supportsVideo = supportsVideo
//    }
//}



/// A structure representing a call object for voice and video communication.
///
/// A session can have many calls, including current, previous, and on-hold calls. Each call
/// object contains comprehensive information about the communication session, participants,
/// timing, and status. Calls can be encoded into data and stored in base communication metadata.
///
/// ## Usage
/// ```swift
/// let call = Call(
///     sharedCommunicationId: "comm_123",
///     sender: Call.Participant(
///         secretName: "alice_secure",
///         nickname: "Alice",
///         deviceId: "device_123"
///     ),
///     recipients: [
///         Call.Participant(
///             secretName: "bob_secure",
///             nickname: "Bob",
///             deviceId: "device_456"
///         )
///     ],
///     supportsVideo: true,
///     isActive: true
/// )
/// ```
///
/// ## Properties
/// - `id`: A unique identifier for the call, used for tracking and management
/// - `sharedMessageId`: An optional identifier for a shared message related to the call
/// - `sharedCommunicationId`: A unique identifier for the shared communication session
/// - `sender`: The participant who initiated the call
/// - `recipients`: An array of participants who are receiving the call
/// - `createdAt`: The date and time when the call was created
/// - `updatedAt`: An optional date and time when the call was last updated
/// - `endedAt`: An optional date and time when the call ended
/// - `supportsVideo`: A boolean indicating whether the call supports video
/// - `unanswered`: An optional boolean indicating whether the call was unanswered
/// - `rejected`: An optional boolean indicating whether the call was rejected
/// - `failed`: An optional boolean indicating whether the call failed
/// - `isActive`: A boolean indicating whether the call is currently active
/// - `metadata`: Additional metadata associated with the call, stored as a BSON document
///
/// ## Call States
/// The call can be in various states represented by the boolean flags:
/// - `isActive`: Currently ongoing
/// - `unanswered`: Call was not answered by recipients
/// - `rejected`: Call was explicitly rejected
/// - `failed`: Call failed due to technical issues
//public struct Call: Sendable, Codable, Equatable {
//    
//    /// A structure representing the properties of a call for secure storage.
//    /// 
//    /// This struct is used internally for encrypting and storing call data securely.
//    /// It contains the call's unique identifier and encrypted data.
//    public struct Props: Sendable, Codable {
//        /// The unique identifier for the call.
//        public var id: UUID
//        
//        /// The encrypted data containing the call information.
//        public var data: Data
//        
//        /// Initializes a new instance of `Props`.
//        /// 
//        /// - Parameters:
//        ///   - id: The unique identifier for the call
//        ///   - data: The encrypted data containing call information
//        public init(id: UUID, data: Data) {
//            self.id = id
//            self.data = data
//        }
//    }
//    
//    /// A structure representing a participant in a call.
//    /// 
//    /// Contains information about a participant including their secret name for identification,
//    /// nickname for display, and device ID for routing.
//    ///
//    /// ## Properties
//    /// - `secretName`: The secret name of the participant, used for secure identification
//    /// - `nickname`: The nickname of the participant, used for display purposes
//    /// - `deviceId`: The device ID of the participant, used for message routing
//    public struct Participant: Sendable, Codable, Equatable {
//        /// The secret name of the participant.
//        /// Used for secure identification in the communication system.
//        public let secretName: String
//        
//        /// The nickname of the participant.
//        /// Used for display purposes in the user interface.
//        public let nickname: String
//        
//        /// The device ID of the participant.
//        /// Used for routing messages and establishing connections.
//        public var deviceId: String
//        
//        /// Initializes a new instance of `Participant`.
//        ///
//        /// Creates a participant with the specified identification information.
//        ///
//        /// - Parameters:
//        ///   - secretName: The secret name of the participant for secure identification
//        ///   - nickname: The nickname of the participant for display purposes
//        ///   - deviceId: The device ID of the participant for message routing
//        public init(secretName: String, nickname: String, deviceId: String) {
//            self.secretName = secretName
//            self.nickname = nickname
//            self.deviceId = deviceId
//        }
//    }
//    
//    /// A unique identifier for the call.
//    /// Used for tracking, management, and correlation of call-related events.
//    public var id: UUID
//    
//    /// An optional identifier for a shared message related to the call.
//    /// Used to associate the call with a specific message or conversation thread.
//    public var sharedMessageId: String?
//    
//    /// A unique identifier for the shared communication session.
//    /// Used to group related calls and manage the overall communication session.
//    public var sharedCommunicationId: String
//    
//    /// The participant who initiated the call.
//    /// Contains the caller's identification and device information.
//    public var sender: Participant
//    
//    /// An array of participants who are receiving the call.
//    /// Can contain multiple participants for group calls.
//    public var recipients: [Participant]
//    
//    /// The date and time when the call was created.
//    /// Used for call history and timing calculations.
//    public var createdAt: Date
//    
//    /// An optional date and time when the call was last updated.
//    /// Used for tracking call state changes and modifications.
//    public var updatedAt: Date?
//    
//    /// An optional date and time when the call ended.
//    /// Used for call duration calculations and history.
//    public var endedAt: Date?
//    
//    /// A boolean indicating whether the call supports video.
//    /// Determines if the call is audio-only or includes video capabilities.
//    public var supportsVideo: Bool
//    
//    /// An optional boolean indicating whether the call was unanswered.
//    /// Set to true if no recipient answered the call.
//    public var unanswered: Bool?
//    
//    /// An optional boolean indicating whether the call was rejected.
//    /// Set to true if a recipient explicitly rejected the call.
//    public var rejected: Bool?
//    
//    /// An optional boolean indicating whether the call failed.
//    /// Set to true if the call failed due to technical issues.
//    public var failed: Bool?
//    
//    /// A boolean indicating whether the call is currently active.
//    /// Used to determine the current state of the call.
//    public var isActive: Bool
//    
//    /// Additional metadata associated with the call.
//    /// Stored as a BSON document for flexible storage of call-specific information.
//    public var metadata: Document
//    
//    /// Initializes a new instance of `Call`.
//    ///
//    /// Creates a call with the specified parameters. Many parameters have sensible defaults
//    /// to simplify call creation while maintaining flexibility.
//    ///
//    /// - Parameters:
//    ///   - id: A unique identifier for the call (defaults to a new UUID)
//    ///   - sharedMessageId: An optional identifier for a shared message related to the call
//    ///   - sharedCommunicationId: A unique identifier for the shared communication session
//    ///   - sender: The participant who initiated the call
//    ///   - recipients: An array of participants who are receiving the call
//    ///   - createdAt: The date and time when the call was created (defaults to the current date)
//    ///   - updatedAt: An optional date and time when the call was last updated
//    ///   - endedAt: An optional date and time when the call ended
//    ///   - supportsVideo: A boolean indicating whether the call supports video (defaults to false)
//    ///   - unanswered: An optional boolean indicating whether the call was unanswered
//    ///   - rejected: An optional boolean indicating whether the call was rejected
//    ///   - failed: An optional boolean indicating whether the call failed
//    ///   - isActive: A boolean indicating whether the call is currently active (defaults to false)
//    ///   - metadata: Additional metadata associated with the call (defaults to an empty document)
//    public init(
//        id: UUID = UUID(),
//        sharedMessageId: String? = nil,
//        sharedCommunicationId: String,
//        sender: Participant,
//        recipients: [Participant],
//        createdAt: Date = Date(),
//        updatedAt: Date? = nil,
//        endedAt: Date? = nil,
//        supportsVideo: Bool = false,
//        unanswered: Bool? = nil,
//        rejected: Bool? = nil,
//        failed: Bool? = nil,
//        isActive: Bool = false,
//        metadata: Document = [:]
//    ) {
//        self.id = id
//        self.sharedMessageId = sharedMessageId
//        self.sharedCommunicationId = sharedCommunicationId
//        self.sender = sender
//        self.recipients = recipients
//        self.createdAt = createdAt
//        self.updatedAt = updatedAt
//        self.endedAt = endedAt
//        self.supportsVideo = supportsVideo
//        self.unanswered = unanswered
//        self.rejected = rejected
//        self.failed = failed
//        self.isActive = isActive
//        self.metadata = metadata
//    }
//}

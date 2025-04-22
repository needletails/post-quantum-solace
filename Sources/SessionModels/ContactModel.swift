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

public struct Contact: Sendable, Codable, Equatable {
    public let id: UUID
    public let secretName: String
    public var configuration: UserConfiguration
    public var metadata: Document

    public init(id: UUID, secretName: String, configuration: UserConfiguration, metadata: Document) {
        self.id = id
        self.secretName = secretName
        self.configuration = configuration
        self.metadata = metadata
    }
}

public final class ContactModel: SecureModelProtocol, Codable, @unchecked Sendable {
    
    public let id: UUID
    public var data: Data
    private let lock = NIOLock()
    private let crypto = NeedleTailCrypto()
    
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id = "a"
        case data = "b"
    }
    
    /// Asynchronously retrieves the decrypted properties, if available.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }

    
    public struct UnwrappedProps: Codable, Sendable {
        private enum CodingKeys: String, CodingKey, Sendable {
            case secretName = "a"
            case configuration = "b"
            case metadata = "c"
        }
        public let secretName: String
        public var configuration: UserConfiguration
        public var metadata: Document
        
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
    
    public init(
        id: UUID,
        data: Data
    ) {
        self.id = id
        self.data = data
    }
    
    
    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    /// - Throws: An error if decryption fails.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        lock.lock()
        defer { lock.unlock() }
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
    ///
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
    
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Document, with key: String) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.metadata[key] = metadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }
    
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
    
    private enum Errors: Error {
        case propsError
    }
}


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


public struct DataPacket: Codable, Sendable {
    public let id: UUID
    public var data: Data
    
    public init(id: UUID, data: Data) {
        self.id = id
        self.data = data
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


/// This struct represents a call object. A session can have many calls potentially, meaning a currentCall, previousCall, and callOnHold. Each call object can be encoded into data and set on a BaseCommunication metadata. A call needs to contain an identifier for the base communication Id.
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


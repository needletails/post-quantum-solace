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
@preconcurrency import Crypto

public struct Contact: Sendable, Codable, Equatable {
    public let id: UUID
    public let secretName: String
    public var configuration: UserConfiguration
    public var metadata: Document
}

public final class ContactModel: SecureModelProtocol, Codable, @unchecked Sendable {
    
    public let id: UUID
    public var data: Data
    
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
    }
    
    init(
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
        let crypto = NeedleTailCrypto()
        guard let decrypted = try crypto.decrypt(data: self.data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionError
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
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return await self.props(symmetricKey: symmetricKey)
    }
    
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Document, with key: String) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.metadata[key] = metadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }
    
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw CryptoSession.SessionErrors.propsError
        }
        return Contact(
            id: id,
            secretName: props.secretName,
            configuration: props.configuration,
            metadata: props.metadata) as! T
    }
    
    public func updateContact(_ metadata: ContactMetadata, symmetricKey: SymmetricKey) async throws {
        guard var props = await props(symmetricKey: symmetricKey) else {
            throw CryptoSession.SessionErrors.propsError
        }
        
        // Decode the existing metadata
        var decoded: ContactMetadata = try props.metadata.decode(forKey: "contactMetadata")
        
        // Update properties only if they are not nil
        if let status = metadata.status {
            decoded.status = status
        }
        if let nickname = metadata.nickname {
            decoded.nickname = nickname
        }
        if let firstName = metadata.firstName {
            decoded.firstName = firstName
        }
        if let lastName = metadata.lastName {
            decoded.lastName = lastName
        }
        if let email = metadata.email {
            decoded.email = email
        }
        if let image = metadata.image {
            decoded.image = image
        }
        
        // Encode the updated metadata
        let encoded = try BSONEncoder().encode(decoded)
        props.metadata["contactMetadata"] = encoded
        
        // Update the properties
        _ = try await updateProps(symmetricKey: symmetricKey, props: props)
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
    /* EXAMPLE
     let doc1 = AnimalObject(animals: ["dog", "cat", "bird", "fish", "hedgehog"])
     let doc2 = NatureObject(types: ["pop", "water", "juice", "coffee", "tea"])
     let doc3 = DrinkObject(drinks: ["mountain", "river", "valley", "hill", "lake"])
     
     var combinedDocument: Document = [:]
     let encoded1: Document = try! BSONEncoder().encode(doc1)
     let encoded2: Document = try! BSONEncoder().encode(doc2)
     let encoded3: Document = try! BSONEncoder().encode(doc3)
     
     combinedDocument["animals"] = encoded1
     combinedDocument["types"] = encoded2
     combinedDocument["drinks"] = encoded3
     //Store CombinedDocument
     
     
     //Get desired Document
     let decoded: DrinkObject = try! combinedDocument.decode(forKey: "drinks")
     
     */
    /// - Parameter key: document key to find and decode
    /// - Returns: the Codable object
    public func decode<T: Codable>(forKey key: String) throws -> T {
        guard let value = self[key] else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: [], debugDescription: "Key \(key) not found in document"))
        }
        guard let data = try BSONEncoder().encodePrimitive(value) else { fatalError() }
        return try BSONDecoder().decode(T.self, fromPrimitive: data)
    }
}

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
    
    /// SymmetricKey can be updated.
    public var symmetricKey: SymmetricKey?
    
    /// Asynchronously retrieves the decrypted properties, if available.
    public var props: UnwrappedProps? {
        get async {
            do {
                guard let symmetricKey = symmetricKey else { return nil }
                return try await decryptProps(symmetricKey: symmetricKey)
            } catch {
                return nil
            }
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
        self.symmetricKey = symmetricKey
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
        return await self.props
    }
    
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Document) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.metadata = metadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }
    
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        self.symmetricKey = symmetricKey
        guard let props = await props else { throw CryptoSession.SessionErrors.propsError }
        return Contact(
            id: id,
            secretName: props.secretName,
            configuration: props.configuration,
            metadata: props.metadata) as! T
    }
    
    public func updateContactNickname(_ nick: String) async throws {
        guard let props = await props else { throw CryptoSession.SessionErrors.propsError }
        guard let symmetricKey = await symmetricKey else { throw CryptoSession.SessionErrors.missingKey }
        var decoded = try BSONDecoder().decode(ContactMetadata.self, from: props.metadata)
        decoded.nickname = nick
        let encoded = try BSONEncoder().encode(decoded)
        _ = try await updatePropsMetadata(symmetricKey: symmetricKey, metadata: encoded)
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

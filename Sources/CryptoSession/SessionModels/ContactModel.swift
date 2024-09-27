//
//  ContactModel.swift
//  needletail-crypto
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

public final class ContactModel: Codable, @unchecked Sendable {
    public let id = UUID()
    public var data: Data
    
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id = "a"
        case data = "b"
    }
    
    /// SymmetricKey can be updated.
    private var symmetricKey: SymmetricKey?
    
    /// Asynchronously retrieves the decrypted properties, if available.
    public var props: UnwrappedProps? {
        get async {
            do {
                guard let symmetricKey = symmetricKey else { return nil }
                return try await decryptProps(symmetricKey: symmetricKey)
            } catch {
                //TODO: Handle error appropriately (e.g., log it)
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
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.symmetricKey = symmetricKey
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    public init(data: Data) {
        self.data = data
    }
    
    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    /// - Throws: An error if decryption fails.
    func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
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
    func updateProps(symmetricKey: SymmetricKey, props: Codable & Sendable) async throws -> UnwrappedProps? {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return await self.props
    }
    
    func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Document) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.metadata = metadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
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
}


public struct DataPacket: Codable, Sendable {
    public let id: UUID
    public var data: Data
    
    public init(id: UUID, data: Data) {
        self.id = id
        self.data = data
    }
    
}

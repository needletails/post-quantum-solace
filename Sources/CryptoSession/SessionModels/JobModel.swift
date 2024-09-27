//
//  JobModel.swift
//  needletail-crypto
//
//  Created by Cole M on 9/15/24.
//
import Foundation
import BSON
import NeedleTailCrypto
import DoubleRatchetKit
@preconcurrency import Crypto

public final class JobModel: Codable, @unchecked Sendable {
    public let id = UUID()
    public var data: Data
    
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id = "a"
        case data = "b"
    }
    
    /// SymmetricKey can be updated.
    private var symmetricKey: SymmetricKey?
    
    /// Asynchronously retrieves the decrypted properties, if available.
    var props: UnwrappedProps? {
        get async {
            do {
                guard let symmetricKey = symmetricKey else { return nil }
                return try await setProps(symmetricKey: symmetricKey)
            } catch {
                //TODO: Handle error appropriately (e.g., log it)
                return nil
            }
        }
    }
    
    public struct UnwrappedProps: Codable & Sendable {
        private enum CodingKeys: String, CodingKey, Sendable {
            case sequenceId = "a"
            case task = "b"
            case isBackgroundTask = "c"
            case delayedUntil = "d"
            case scheduledAt = "e"
            case attempts = "f"
        }
        let sequenceId: Int
        var task: EncrytableTask
        let isBackgroundTask: Bool
        var delayedUntil: Date?
        var scheduledAt: Date
        var attempts: Int
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
    func setProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
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
}

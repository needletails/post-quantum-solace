//
//  UserConfiguration.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import BSON
import Crypto
import DoubleRatchetKit

/// A struct representing the configuration of a user, including the signing identity
/// and auxiliary devices.
public struct UserConfiguration: Codable, Sendable, Equatable {
    
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case publicSigningKey = "a"            // Key for the public signing key
        case signedDevices = "b"                // Key for the signed devices
        case signedPublicOneTimeKeys = "c"      // Key for the signed public one-time keys
        case signedPublicKyberOneTimeKeys = "d"      // Key for the signed public one-time keys
    }
    
    /// The public signing key used for signing device configurations.
    public let publicSigningKey: Data
    
    /// An array of signed device configurations associated with the user.
    public var signedDevices: [SignedDeviceConfiguration]
    
    /// An array of signed public one-time keys associated with the user.
    public var signedPublicOneTimeKeys: [SignedPublicOneTimeKey]
    
    /// An array of signed public one-time keys associated with the user.
    public var signedPublicKyberOneTimeKeys: [SignedKyberOneTimeKey]
    
    /// Initializes a new instance of `UserConfiguration`.
    ///
    /// - Parameters:
    ///   - publicSigningKey: The public signing key used for signing device configurations.
    ///   - signedDevices: An array of signed device configurations associated with the user.
    ///   - signedPublicOneTimeKeys: An array of signed public one-time keys associated with the user.
    public init(
        publicSigningKey: Data,
        signedDevices: [SignedDeviceConfiguration],
        signedPublicOneTimeKeys: [SignedPublicOneTimeKey],
        signedPublicKyberOneTimeKeys: [SignedKyberOneTimeKey]
    ) {
        self.publicSigningKey = publicSigningKey
        self.signedDevices = signedDevices
        self.signedPublicOneTimeKeys = signedPublicOneTimeKeys
        self.signedPublicKyberOneTimeKeys = signedPublicKyberOneTimeKeys
    }
    
    /// Retrieves verified devices from the signed device configurations.
    ///
    /// - Throws: An error if verification fails.
    /// - Returns: An array of verified `UserDeviceConfiguration` instances.
    public func getVerifiedDevices() throws -> [UserDeviceConfiguration] {
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicSigningKey)
        return try signedDevices.compactMap { try $0.verified(using: publicKey) }
    }
    
    /// Retrieves verified one-time keys for a specific device.
    ///
    /// - Parameter deviceId: The unique identifier of the device for which to retrieve keys.
    /// - Throws: An error if verification fails.
    /// - Returns: An array of verified `Curve25519PublicKeyRepresentable` instances.
    public func getVerifiedKeys(deviceId: UUID) throws -> [Curve25519PublicKeyRepresentable] {
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicSigningKey)
        let filteredKeys = signedPublicOneTimeKeys.filter { $0.deviceId == deviceId }
        return try filteredKeys.compactMap { try $0.verified(using: publicKey) }
    }
    
    public func getVerifiedKyberKeys(deviceId: UUID) throws -> [Kyber1024PublicKeyRepresentable] {
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicSigningKey)
        let filteredKeys = signedPublicKyberOneTimeKeys.filter { $0.deviceId == deviceId }
        return try filteredKeys.compactMap { try $0.kyberVerified(using: publicKey) }
    }
    
    /// A struct representing a signed device configuration.
    public struct SignedDeviceConfiguration: Codable, Sendable {
        /// The unique identifier for the device.
        public let id: UUID
        
        /// The encoded data for the device configuration.
        public let data: Data
        
        /// The generated signature for the device configuration.
        public let signature: Data
        
        enum CodingKeys: String, CodingKey, Codable, Sendable {
            case id = "a"
            case data = "b"
            case signature = "c"
        }
        
        /// Initializes a new `SignedDeviceConfiguration` instance.
        ///
        /// - Parameters:
        ///   - device: The `UserDeviceConfiguration` to be signed.
        ///   - signingKey: The private signing key used for signing.
        /// - Throws: An error if the signing process fails.
        public init(device: UserDeviceConfiguration, signingKey: Curve25519.Signing.PrivateKey) throws {
            let encoded = try BSONEncoder().encodeData(device)
            self.id = device.deviceId
            self.data = encoded
            self.signature = try signingKey.signature(for: encoded)
        }
        
        /// Verifies the signature of the device configuration data.
        ///
        /// - Parameter publicKey: The public signing key used for verification.
        /// - Returns: An optional `UserDeviceConfiguration` if verification is successful.
        /// - Throws: An error if verification fails.
        public func verified(using publicKey: Curve25519.Signing.PublicKey) throws -> UserDeviceConfiguration? {
            guard publicKey.isValidSignature(signature, for: data) else { return nil }
            return try BSONDecoder().decodeData(UserDeviceConfiguration.self, from: data)
        }
    }
    
    /// A struct representing a signed public one-time key.
    public struct SignedPublicOneTimeKey: Codable, Sendable {
        /// The unique identifier for the one-time key.
        public let id: UUID
        
        /// The unique identifier for the device associated with the key.
        public let deviceId: UUID
        
        /// The encoded data for the public one-time key.
        public let data: Data
        
        /// The generated signature for the public one-time key.
        public let signature: Data
        
        enum CodingKeys: String, CodingKey, Codable, Sendable {
            case id = "a"
            case deviceId = "b"
            case data = "c"
            case signature = "d"
        }
        
        /// Initializes a new `SignedPublicOneTimeKey` instance.
        ///
        /// - Parameters:
        ///   - key: The `Curve25519PublicKeyRepresentable` to be signed.
        ///   - deviceId: The unique identifier for the device associated with the key.
        ///   - signingKey: The private signing key used for signing.
        /// - Throws: An error if the signing process fails.
        public init(
            key: Curve25519PublicKeyRepresentable,
            deviceId: UUID,
            signingKey: Curve25519.Signing.PrivateKey
        ) throws {
            let encoded = try BSONEncoder().encodeData(key)
            self.id = key.id
            self.deviceId = deviceId
            self.data = encoded
            self.signature = try signingKey.signature(for: encoded)
        }
        
        /// Verifies the signature of the public one-time key data.
        ///
        /// - Parameter publicKey: The public signing key used for verification.
        /// - Returns: An optional `Curve25519PublicKeyRepresentable` if verification is successful.
        /// - Throws: An error if verification fails.
        public func verified(using publicKey: Curve25519.Signing.PublicKey) throws -> Curve25519PublicKeyRepresentable? {
            guard publicKey.isValidSignature(signature, for: data) else { return nil }
            return try BSONDecoder().decodeData(Curve25519PublicKeyRepresentable.self, from: data)
        }
    }
    
    
    /// A struct representing a signed public one-time key.
    public struct SignedKyberOneTimeKey: Codable, Sendable {
        /// The unique identifier for the one-time key.
        public let id: UUID
        
        /// The unique identifier for the device associated with the key.
        public let deviceId: UUID
        
        /// The encoded data for the public one-time key.
        public let data: Data
        
        /// The generated signature for the public one-time key.
        public let signature: Data
        
        enum CodingKeys: String, CodingKey, Codable, Sendable {
            case id = "a"
            case deviceId = "b"
            case data = "c"
            case signature = "d"
        }
        
        /// Initializes a new `SignedPublicOneTimeKey` instance.
        ///
        /// - Parameters:
        ///   - key: The `Curve25519PublicKeyRepresentable` to be signed.
        ///   - deviceId: The unique identifier for the device associated with the key.
        ///   - signingKey: The private signing key used for signing.
        /// - Throws: An error if the signing process fails.
        public init(
            key: Kyber1024PublicKeyRepresentable,
            deviceId: UUID,
            signingKey: Curve25519.Signing.PrivateKey
        ) throws {
            let encoded = try BSONEncoder().encodeData(key)
            self.id = key.id
            self.deviceId = deviceId
            self.data = encoded
            self.signature = try signingKey.signature(for: encoded)
        }
        
        /// Verifies the signature of the public one-time key data.
        ///
        /// - Parameter publicKey: The public signing key used for verification.
        /// - Returns: An optional `Curve25519PublicKeyRepresentable` if verification is successful.
        /// - Throws: An error if verification fails.
        public func verified(using publicKey: Curve25519.Signing.PublicKey) throws -> Curve25519PublicKeyRepresentable? {
            guard publicKey.isValidSignature(signature, for: data) else { return nil }
            return try BSONDecoder().decodeData(Curve25519PublicKeyRepresentable.self, from: data)
        }
        
        public func kyberVerified(using publicKey: Curve25519.Signing.PublicKey) throws -> Kyber1024PublicKeyRepresentable? {
            guard publicKey.isValidSignature(signature, for: data) else { return nil }
            return try BSONDecoder().decodeData(Kyber1024PublicKeyRepresentable.self, from: data)
        }
    }
    
    /// Compares two `UserConfiguration` instances for equality.
    ///
    /// - Parameters:
    ///   - lhs: The left-hand side `UserConfiguration` instance.
    ///   - rhs: The right-hand side `UserConfiguration` instance.
    /// - Returns: A boolean indicating whether the two instances are equal.
    public static func ==(lhs: UserConfiguration, rhs: UserConfiguration) -> Bool {
        return lhs.publicSigningKey == rhs.publicSigningKey
    }
}

public enum KeysType: Sendable {
    case curve, kyber
}

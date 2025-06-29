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
        case signingPublicKey = "a"            // Key for the public signing key
        case signedDevices = "b"                // Key for the signed devices
        case signedOneTimePublicKeys = "c"      // Key for the signed public one-time keys
        case signedPQKemOneTimePublicKeys = "d"      // Key for the signed public one-time keys
    }
    
    /// The public signing key used for signing device configurations.
    public var signingPublicKey: Data
    
    /// An array of signed device configurations associated with the user.
    public var signedDevices: [SignedDeviceConfiguration]
    
    /// An array of signed Curve25519 one-time public keys associated with the user.
    public var signedOneTimePublicKeys: [SignedOneTimePublicKey]
    
    /// An array of signed post-quantum KEM one-time public keys associated with the user.
    public var signedPQKemOneTimePublicKeys: [SignedPQKemOneTimeKey]
    
    /// Initializes a new instance of `UserConfiguration`.
    ///
    /// - Parameters:
    ///   - signingPublicKey: The public signing key used for signing device configurations.
    ///   - signedDevices: An array of signed device configurations associated with the user.
    ///   - signedOneTimePublicKeys: An array of signed Curve25519 one-time public keys associated with the user.
    ///   - signedPQKemOneTimePublicKeys: An array of signed post-quantum KEM one-time public keys associated with the user.
    public init(
        signingPublicKey: Data,
        signedDevices: [SignedDeviceConfiguration],
        signedOneTimePublicKeys: [SignedOneTimePublicKey],
        signedPQKemOneTimePublicKeys: [SignedPQKemOneTimeKey]
    ) {
        self.signingPublicKey = signingPublicKey
        self.signedDevices = signedDevices
        self.signedOneTimePublicKeys = signedOneTimePublicKeys
        self.signedPQKemOneTimePublicKeys = signedPQKemOneTimePublicKeys
    }
    
    /// Retrieves verified devices from the signed device configurations.
    ///
    /// - Throws: An error if verification fails.
    /// - Returns: An array of verified `UserDeviceConfiguration` instances.
    public func getVerifiedDevices() throws -> [UserDeviceConfiguration] {
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKey)
        return try signedDevices.compactMap { try $0.verified(using: publicKey) }
    }
    
    /// Retrieves verified Curve25519 one-time keys for a specific device.
    ///
    /// - Parameter deviceId: The unique identifier of the device for which to retrieve keys.
    /// - Throws: An error if verification fails.
    /// - Returns: An array of verified `CurvePublicKey` instances.
    public func getVerifiedCurveKeys(deviceId: UUID) throws -> [CurvePublicKey] {
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKey)
        let filteredKeys = signedOneTimePublicKeys.filter { $0.deviceId == deviceId }
        return try filteredKeys.compactMap { try $0.verified(using: publicKey) }
    }
    
    /// Retrieves verified post-quantum KEM one-time keys for a specific device.
    ///
    /// - Parameter deviceId: The unique identifier of the device for which to retrieve keys.
    /// - Throws: An error if verification fails.
    /// - Returns: An array of verified `PQKemPublicKey` instances.
    public func getVerifiedPQKemKeys(deviceId: UUID) throws -> [PQKemPublicKey] {
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKey)
        let filteredKeys = signedPQKemOneTimePublicKeys.filter { $0.deviceId == deviceId }
        return try filteredKeys.compactMap { try $0.verified(using: publicKey) }
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
    
    /// A struct representing a signed Curve25519 one-time public key.
    public struct SignedOneTimePublicKey: Codable, Sendable {
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
        
        /// Initializes a new `SignedOneTimePublicKey` instance.
        ///
        /// - Parameters:
        ///   - key: The `CurvePublicKey` to be signed.
        ///   - deviceId: The unique identifier for the device associated with the key.
        ///   - signingKey: The private signing key used for signing.
        /// - Throws: An error if the signing process fails.
        public init(
            key: CurvePublicKey,
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
        /// - Returns: An optional `CurvePublicKey` if verification is successful.
        /// - Throws: An error if verification fails.
        public func verified(using publicKey: Curve25519.Signing.PublicKey) throws -> CurvePublicKey? {
            guard publicKey.isValidSignature(signature, for: data) else { return nil }
            return try BSONDecoder().decodeData(CurvePublicKey.self, from: data)
        }
    }
    
    
    /// A struct representing a signed post-quantum KEM one-time public key.
    public struct SignedPQKemOneTimeKey: Codable, Sendable {
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
        
        /// Initializes a new `SignedPQKemOneTimeKey` instance.
        ///
        /// - Parameters:
        ///   - key: The `PQKemPublicKey` to be signed.
        ///   - deviceId: The unique identifier for the device associated with the key.
        ///   - signingKey: The private signing key used for signing.
        /// - Throws: An error if the signing process fails.
        public init(
            key: PQKemPublicKey,
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
        /// - Returns: An optional `PQKemPublicKey` if verification is successful.
        /// - Throws: An error if verification fails.
        public func verified(using publicKey: Curve25519.Signing.PublicKey) throws -> PQKemPublicKey? {
            guard publicKey.isValidSignature(signature, for: data) else { return nil }
            return try BSONDecoder().decodeData(PQKemPublicKey.self, from: data)
        }
    }
    
    /// Compares two `UserConfiguration` instances for equality.
    ///
    /// - Parameters:
    ///   - lhs: The left-hand side `UserConfiguration` instance.
    ///   - rhs: The right-hand side `UserConfiguration` instance.
    /// - Returns: A boolean indicating whether the two instances are equal.
    public static func ==(lhs: UserConfiguration, rhs: UserConfiguration) -> Bool {
        return lhs.signingPublicKey == rhs.signingPublicKey
    }
}

/// An enum representing the different types of cryptographic keys supported by the system.
/// This enum is used to distinguish between key types when working with various cryptographic operations.
public enum KeysType: Sendable {
    /// Curve25519 elliptic curve keys for classical cryptography.
    case curve
    /// Post-quantum KEM keys for quantum-resistant cryptography.
    case kyber
}

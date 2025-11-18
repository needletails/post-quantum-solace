//
//  UserConfiguration.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-14.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//
//

import DoubleRatchetKit
import Foundation
import Crypto

/// A struct representing the configuration of a user, including the signing identity
/// and auxiliary devices.
public struct UserConfiguration: Codable, Sendable, Equatable {
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case signingPublicKey = "a" // Key for the public signing key
        case signedDevices = "b" // Key for the signed devices
        case signedOneTimePublicKeys = "c" // Key for the signed public one-time keys
        case signedMLKEMOneTimePublicKeys = "d" // Key for the signed public one-time keys
    }

    /// The public signing key used for signing device configurations.
    public var signingPublicKey: Data

    /// An array of signed device configurations associated with the user.
    public var signedDevices: [SignedDeviceConfiguration]

    /// An array of signed Curve25519 one-time public keys associated with the user.
    public var signedOneTimePublicKeys: [SignedOneTimePublicKey]

    /// An array of signed post-quantum KEM one-time public keys associated with the user.
    public var signedMLKEMOneTimePublicKeys: [SignedMLKEMOneTimeKey]

    /// Initializes a new instance of `UserConfiguration`.
    ///
    /// - Parameters:
    ///   - signingPublicKey: The public signing key used for signing device configurations.
    ///   - signedDevices: An array of signed device configurations associated with the user.
    ///   - signedOneTimePublicKeys: An array of signed Curve25519 one-time public keys associated with the user.
    ///   - signedMLKEMOneTimePublicKeys: An array of signed post-quantum KEM one-time public keys associated with the user.
    public init(
        signingPublicKey: Data,
        signedDevices: [SignedDeviceConfiguration],
        signedOneTimePublicKeys: [SignedOneTimePublicKey],
        signedMLKEMOneTimePublicKeys: [SignedMLKEMOneTimeKey]
    ) {
        self.signingPublicKey = signingPublicKey
        self.signedDevices = signedDevices
        self.signedOneTimePublicKeys = signedOneTimePublicKeys
        self.signedMLKEMOneTimePublicKeys = signedMLKEMOneTimePublicKeys
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
    /// - Returns: An array of verified `MLKEMPublicKey` instances.
    public func getVerifiedMLKEMKeys(deviceId: UUID) throws -> [MLKEMPublicKey] {
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKey)
        let filteredKeys = signedMLKEMOneTimePublicKeys.filter { $0.deviceId == deviceId }
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
            let encoded = try BinaryEncoder().encode(device)
            id = device.deviceId
            data = encoded
            signature = try signingKey.signature(for: encoded)
        }

        /// Verifies the signature of the device configuration data.
        ///
        /// - Parameter publicKey: The public signing key used for verification.
        /// - Returns: An optional `UserDeviceConfiguration` if verification is successful.
        /// - Throws: An error if verification fails.
        public func verified(using publicKey: Curve25519.Signing.PublicKey) throws -> UserDeviceConfiguration? {
            guard publicKey.isValidSignature(signature, for: data) else { return nil }
            return try BinaryDecoder().decode(UserDeviceConfiguration.self, from: data)
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
            let encoded = try BinaryEncoder().encode(key)
            id = key.id
            self.deviceId = deviceId
            data = encoded
            signature = try signingKey.signature(for: encoded)
        }

        /// Verifies the signature of the public one-time key data.
        ///
        /// - Parameter publicKey: The public signing key used for verification.
        /// - Returns: An optional `CurvePublicKey` if verification is successful.
        /// - Throws: An error if verification fails.
        public func verified(using publicKey: Curve25519.Signing.PublicKey) throws -> CurvePublicKey? {
            guard publicKey.isValidSignature(signature, for: data) else { return nil }
            return try BinaryDecoder().decode(CurvePublicKey.self, from: data)
        }
    }

    /// A struct representing a signed post-quantum KEM one-time public key.
    public struct SignedMLKEMOneTimeKey: Codable, Sendable {
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

        /// Initializes a new `SignedMLKEMOneTimeKey` instance.
        ///
        /// - Parameters:
        ///   - key: The `MLKEMPublicKey` to be signed.
        ///   - deviceId: The unique identifier for the device associated with the key.
        ///   - signingKey: The private signing key used for signing.
        /// - Throws: An error if the signing process fails.
        public init(
            key: MLKEMPublicKey,
            deviceId: UUID,
            signingKey: Curve25519.Signing.PrivateKey
        ) throws {
            let encoded = try BinaryEncoder().encode(key)
            id = key.id
            self.deviceId = deviceId
            data = encoded
            signature = try signingKey.signature(for: encoded)
        }

        /// Verifies the signature of the public one-time key data.
        ///
        /// - Parameter publicKey: The public signing key used for verification.
        /// - Returns: An optional `MLKEMPublicKey` if verification is successful.
        /// - Throws: An error if verification fails.
        public func verified(using publicKey: Curve25519.Signing.PublicKey) throws -> MLKEMPublicKey? {
            guard publicKey.isValidSignature(signature, for: data) else { return nil }
            return try BinaryDecoder().decode(MLKEMPublicKey.self, from: data)
        }
    }

    /// Compares two `UserConfiguration` instances for equality.
    ///
    /// - Parameters:
    ///   - lhs: The left-hand side `UserConfiguration` instance.
    ///   - rhs: The right-hand side `UserConfiguration` instance.
    /// - Returns: A boolean indicating whether the two instances are equal.
    public static func == (lhs: UserConfiguration, rhs: UserConfiguration) -> Bool {
        lhs.signingPublicKey == rhs.signingPublicKey
    }
}

/// An enum representing the different types of cryptographic keys supported by the system.
/// This enum is used to distinguish between key types when working with various cryptographic operations.
public enum KeysType: Sendable {
    /// Curve25519 elliptic curve keys for classical cryptography.
    case curve
    /// Post-quantum KEM keys for quantum-resistant cryptography.
    case mlKEM
}

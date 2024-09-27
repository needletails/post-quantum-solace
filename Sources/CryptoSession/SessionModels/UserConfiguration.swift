//
//  UserConfiguration.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import BSON
import NeedleTailCrypto

/// A struct representing the configuration of a user, including the signing identity and auxiliary devices.
public struct UserConfiguration: Codable, Sendable, Equatable {
    
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case publicSigningKey = "a"          // Key for the signing identity data
        case devices = "b"         // Key for the array of auxiliary device configurations
    }
    
    /// Data representing the signing identity of the user.
    public let publicSigningKey: Data
    public var signed: Signed?
    
    /// An array of auxiliary device configurations associated with the user.
    /// Each `UserDeviceConfiguration` can be signed and verified.
    /// The signature can be accessed via the `signed` property of `UserDeviceConfiguration`.
    var devices: [UserDeviceConfiguration]
    
    /// Initializes a new `UserConfiguration` instance.
    /// - Parameters:
    ///   - signingIdentity: The signing identity data for the user.
    ///   - auxillaryDevices: An array of `UserDeviceConfiguration` instances representing auxiliary devices.
    public init(
        publicSigningKey: Data,
        devices: [UserDeviceConfiguration],
        privateSigningKey: Curve25519SigningPrivateKey
    ) throws {
        self.publicSigningKey = publicSigningKey
        self.devices = devices
        self.signed = try Signed(
            configuration: devices,
            privateSigningKey: privateSigningKey
        )
    }
    
    
    
    /// A struct representing the signed version of the user device configuration.
    public struct Signed: Codable, Sendable {
        
        /// The encoded data of the configuration.
        public let data: Data
        let signature: Data
        
        /// Coding keys for encoding and decoding the signed struct.
        enum CodingKeys: String, CodingKey, Codable, Sendable {
            case data = "a"
            case signature = "b"
        }
        
        /// Initializes a new `Signed` instance.
        /// - Parameters:
        ///   - configuration: The user device configuration to sign.
        ///   - publicSigningKeyRepresentable: The public signing key representation.
        ///   - privateSigningIdentity: The private signing key used for signing.
        /// - Throws: An error if the signature is invalid.
        init(
            configuration: [UserDeviceConfiguration],
            privateSigningKey: Curve25519SigningPrivateKey
        ) throws {
            self.data = try BSONEncoder().encodeData(configuration)
            self.signature = try privateSigningKey.signature(for: data)
        }
      
        /// Verifies the signature of the configuration data.
        /// - Parameter privateSigningIdentity: The private signing key used for verification.
        /// - Returns: A boolean indicating whether the signature is valid.
        /// - Throws: An error if verification fails.
        public func verifySignature(publicKey: Curve25519SigningPublicKey) throws -> Bool {
            return publicKey.isValidSignature(signature, for: data)
        }
    }

    public func getVerifiedDevices() throws -> [UserDeviceConfiguration] {
        let publicKey = try Curve25519SigningPublicKey(rawRepresentation: publicSigningKey)
        guard let signed = signed else { throw CryptoSession.SessionErrors.invalidSignature }
        if try signed.verifySignature(publicKey: publicKey) {
            let devices = try BSONDecoder().decodeData([UserDeviceConfiguration].self, from: signed.data)
            return devices
        } else {
            return []
        }
    }
    
    public static func ==(lhs: UserConfiguration, rhs: UserConfiguration) -> Bool {
        return lhs.publicSigningKey == rhs.publicSigningKey
    }
}

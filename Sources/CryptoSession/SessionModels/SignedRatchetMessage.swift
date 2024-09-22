//
//  SignedRatchetMessage.swift
//  needletail-crypto
//
//  Created by Cole M on 9/15/24.
//
import Foundation
import BSON
import NeedleTailCrypto
import DoubleRatchetKit
@preconcurrency import Crypto

/// A struct representing the configuration of a user device, including its identity, signing information, and whether it is a master device.
public struct SignedRatchetMessage: Codable & Sendable {
    
    /// Optional signed representation of the configuration.
    var signed: Signed?
    
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case signed = "a"
    }
    
    /// Initializes a new `UserDeviceConfiguration` instance.
    /// - Parameters:
    ///   - privateSigningIdentity: The private signing key used for signing the configuration.
    /// - Throws: An error if signing the configuration fails.
    init(
        message: EncryptedMessage,
        privateSigningKey: Data
    ) throws {
        self.signed = try Signed(
            message: message,
            privateSigningIdentity: try Curve25519SigningPrivateKey(rawRepresentation: privateSigningKey)
        )
    }
    
    /// A struct representing the signed version of the user device configuration.
    public struct Signed: Codable & Sendable {
        
        /// The encoded encrypted data for the message
        let data: Data
        /// The generated signature.
        let signature: Data
        
        /// Coding keys for encoding and decoding the signed struct.
        enum CodingKeys: String, CodingKey, Codable & Sendable {
            case data = "a"
            case signature = "c"
        }
        
        /// Initializes a new `Signed` instance.
        /// - Parameters:
        ///   - message: The Ratchet Encrypted Message
        ///   - publicSigningKeyRepresentable: The public signing key representation.
        ///   - privateSigningIdentity: The private signing key used for signing.
        /// - Throws: An error if the signature is invalid.
        init(
            message: EncryptedMessage,
            privateSigningIdentity: Curve25519SigningPrivateKey
        ) throws {
            self.data = try BSONEncoder().encodeData(message)
            signature = try privateSigningIdentity.signature(for: data)
        }

        /// Verifies the signature of the configuration data.
        /// - Parameter privateSigningIdentity: The private signing key used for verification.
        /// - Returns: A boolean indicating whether the signature is valid.
        /// - Throws: An error if verification fails.
        public func verifySignature(publicKey: Curve25519SigningPublicKey) throws -> Bool {
            return publicKey.isValidSignature(signature, for: data)
        }
    }
}

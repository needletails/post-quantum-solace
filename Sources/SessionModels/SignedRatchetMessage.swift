//
//  SignedRatchetMessage.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/15/24.
//
import Foundation
import BSON
import NeedleTailCrypto
import DoubleRatchetKit

/// A struct representing a signed ratchet message, including an optional signed representation
/// of the configuration.
public struct SignedRatchetMessage: Codable & Sendable {
    
    /// Optional signed representation of the configuration.
    public var signed: Signed?
    
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case signed = "a"
    }
    
    /// Initializes a new `SignedRatchetMessage` instance.
    ///
    /// - Parameters:
    ///   - message: The `RatchetMessage` to be signed.
    ///   - privateSigningKey: The private signing key used for signing the configuration.
    /// - Throws: An error if signing the configuration fails.
    public init(
        message: RatchetMessage,
        privateSigningKey: Data
    ) throws {
        self.signed = try Signed(
            message: message,
            privateSigningIdentity: try Curve25519SigningPrivateKey(rawRepresentation: privateSigningKey)
        )
    }
    
    /// A struct representing the signed version of the ratchet message.
    public struct Signed: Codable & Sendable {
        
        /// The encoded encrypted data for the message.
        public let data: Data
        
        /// The generated signature.
        let signature: Data
        
        /// Coding keys for encoding and decoding the signed struct.
        enum CodingKeys: String, CodingKey, Codable & Sendable {
            case data = "a"
            case signature = "c"
        }
        
        /// Initializes a new `Signed` instance.
        ///
        /// - Parameters:
        ///   - message: The `RatchetMessage` to be signed.
        ///   - privateSigningIdentity: The private signing key used for signing.
        /// - Throws: An error if the signing process fails.
        init(
            message: RatchetMessage,
            privateSigningIdentity: Curve25519SigningPrivateKey
        ) throws {
            self.data = try BSONEncoder().encodeData(message)
            signature = try privateSigningIdentity.signature(for: data)
        }

        /// Verifies the signature of the configuration data.
        ///
        /// - Parameter publicKey: The public signing key used for verification.
        /// - Returns: A boolean indicating whether the signature is valid.
        /// - Throws: An error if verification fails.
        public func verifySignature(using publicKey: Curve25519SigningPublicKey) throws -> Bool {
            return publicKey.isValidSignature(signature, for: data)
        }
    }
}

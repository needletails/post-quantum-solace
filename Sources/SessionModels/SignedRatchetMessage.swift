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

/// A struct representing a signed ratchet message that provides cryptographic authenticity
/// and integrity verification for ratchet messages in the post-quantum Solace protocol.
///
/// This type wraps a `RatchetMessage` with a digital signature created using Curve25519,
/// ensuring that the message hasn't been tampered with and originated from the expected sender.
///
/// ## Usage Example
/// ```swift
/// let ratchetMessage = RatchetMessage(...)
/// let privateKeyData = Data(...) // Your Curve25519 private key raw representation
/// 
/// do {
///     let signedMessage = try SignedRatchetMessage(
///         message: ratchetMessage,
///         signingPrivateKey: privateKeyData
///     )
///     
///     // Verify the signature
///     if let signed = signedMessage.signed {
///         let isValid = try signed.verifySignature(using: publicKey)
///         print("Signature is valid: \(isValid)")
///     }
/// } catch {
///     print("Failed to create signed message: \(error)")
/// }
/// ```
public struct SignedRatchetMessage: Codable & Sendable {
    
    /// The signed representation of the ratchet message, containing the encoded data
    /// and cryptographic signature for verification.
    ///
    /// This property is optional because signing might fail during initialization,
    /// in which case this will be `nil`.
    public var signed: Signed?
    
    /// Coding keys for encoding and decoding the struct.
    ///
    /// Uses single-letter keys for serialization efficiency in network transmission.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case signed = "a"  // Single letter for serialization efficiency
    }
    
    /// Initializes a new `SignedRatchetMessage` instance by signing the provided ratchet message.
    ///
    /// This initializer creates a digital signature of the ratchet message using the provided
    /// private key. The signature is created over the BSON-encoded representation of the message
    /// to ensure data integrity.
    ///
    /// - Parameters:
    ///   - message: The `RatchetMessage` to be signed. This should contain the actual
    ///     message payload that needs cryptographic protection.
    ///   - signingPrivateKey: The raw representation of the Curve25519 private signing key
    ///     used to create the digital signature. This key should correspond to the sender's identity.
    /// - Throws: 
    ///   - `BSONEncoderError` if the message cannot be encoded to BSON format
    ///   - `CryptoError` if the signing operation fails due to invalid key or cryptographic issues
    ///   - `Curve25519Error` if the private key is invalid or corrupted
    public init(
        message: RatchetMessage,
        signingPrivateKey data: Data
    ) throws {
        self.signed = try Signed(
            message: message,
            signingPrivateKey: try Curve25519SigningPrivateKey(rawRepresentation: data)
        )
    }
    
    /// A struct representing the signed version of the ratchet message with cryptographic
    /// verification capabilities.
    ///
    /// This nested struct contains the encoded message data and its corresponding digital
    /// signature, providing methods to verify the authenticity and integrity of the message.
    public struct Signed: Codable & Sendable {
        
        /// The BSON-encoded data of the original ratchet message.
        ///
        /// This data represents the serialized form of the `RatchetMessage` that was signed.
        /// The signature was created over this exact data to ensure integrity.
        public let data: Data
        
        /// The cryptographic signature generated from the message data.
        ///
        /// This signature is created using the sender's private key and can be verified
        /// using the corresponding public key to ensure message authenticity.
        private let signature: Data
        
        /// Coding keys for encoding and decoding the signed struct.
        ///
        /// Uses single-letter keys for serialization efficiency in network transmission.
        enum CodingKeys: String, CodingKey, Codable & Sendable {
            case data = "a"      // Single letter for serialization efficiency
            case signature = "c" // Single letter for serialization efficiency
        }
        
        /// Initializes a new `Signed` instance by encoding and signing the provided message.
        ///
        /// This initializer performs two operations:
        /// 1. Encodes the ratchet message to BSON format for serialization
        /// 2. Creates a digital signature over the encoded data using the private key
        ///
        /// - Parameters:
        ///   - message: The `RatchetMessage` to be encoded and signed.
        ///   - signingPrivateKey: The Curve25519 private key used to create the signature.
        /// - Throws: 
        ///   - `BSONEncoderError` if the message cannot be encoded to BSON format
        ///   - `CryptoError` if the signing operation fails
        init(
            message: RatchetMessage,
            signingPrivateKey: Curve25519SigningPrivateKey
        ) throws {
            self.data = try BSONEncoder().encodeData(message)
            signature = try signingPrivateKey.signature(for: data)
        }

        /// Verifies the digital signature of the message data using the provided public key.
        ///
        /// This method validates that the message was signed by the holder of the private key
        /// corresponding to the provided public key, and that the message data hasn't been
        /// modified since signing.
        ///
        /// - Parameter publicKey: The Curve25519 public signing key corresponding to the
        ///   private key used to create the signature. This should be the sender's public key.
        /// - Returns: `true` if the signature is valid and the message data hasn't been
        ///   tampered with, `false` otherwise.
        /// - Throws: `CryptoError` if the verification process fails due to cryptographic issues
        public func verifySignature(using publicKey: Curve25519SigningPublicKey) throws -> Bool {
            return publicKey.isValidSignature(signature, for: data)
        }
    }
}

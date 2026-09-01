//
//  SealedOuterCiphertext.swift
//  post-quantum-solace
//
//  Post-quantum sealed-sender outer ciphertext.
//

import Foundation

/// The wire payload for a post-quantum sealed-sender message.
///
/// The ML-KEM ciphertext carries a fresh per-message shared secret. The
/// AES-GCM combined ciphertext contains the nonce, encrypted
/// ``SealedSenderPlaintext``, and authentication tag.
public struct SealedOuterCiphertext: Codable, Sendable, Equatable {
    public let version: UInt8
    public let kemCiphertext: Data
    public let aeadCiphertext: Data

    enum CodingKeys: String, CodingKey {
        case version = "a"
        case kemCiphertext = "b"
        case aeadCiphertext = "c"
    }

    public init(version: UInt8, kemCiphertext: Data, aeadCiphertext: Data) {
        self.version = version
        self.kemCiphertext = kemCiphertext
        self.aeadCiphertext = aeadCiphertext
    }
}

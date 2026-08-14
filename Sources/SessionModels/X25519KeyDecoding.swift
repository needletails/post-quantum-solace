//
//  X25519KeyDecoding.swift
//  post-quantum-solace
//
//  Published one-time keys are BinaryEncoder-encoded with a type-name header.
//  3.x used `CurvePublicKey` / `CurvePrivateKey`; 4.x uses `X25519PublicKey` /
//  `X25519PrivateKey`. Decoding the 4.x type against a 3.x header throws
//  `DecodingError` and aborts add-contact / OTK consume.
//
//  Use this helper for every *top-level* BinaryDecoder of a published X25519
//  key. Nested Codable fields (OneTimeKeys, SessionIdentity, RatchetState) do
//  not write a type header and do not need it.
//
//  Stored signed OTK `data` blobs cannot be rewritten to the new type name:
//  the signature covers the exact bytes, including the header. New publishes
//  encode `X25519PublicKey`. Existing `CurvePublicKey` blobs stay valid until
//  they are consumed.
//

import BinaryCodable
import DoubleRatchetKit
import Foundation

/// Wire stand-in so BinaryCodable can match a `CurvePublicKey` type header.
struct CurvePublicKey: Codable, Sendable {
    let id: UUID
    let rawRepresentation: Data
}

/// Wire stand-in so BinaryCodable can match a `CurvePrivateKey` type header.
struct CurvePrivateKey: Codable, Sendable {
    let id: UUID
    let rawRepresentation: Data
}

enum X25519KeyDecoding {
    static func publicKey(from data: Data) -> X25519PublicKey? {
        if let key = try? BinaryDecoder().decode(X25519PublicKey.self, from: data) {
            return key
        }
        guard let curveKey = try? BinaryDecoder().decode(CurvePublicKey.self, from: data) else {
            return nil
        }
        return try? X25519PublicKey(id: curveKey.id, curveKey.rawRepresentation)
    }

    static func privateKey(from data: Data) -> X25519PrivateKey? {
        if let key = try? BinaryDecoder().decode(X25519PrivateKey.self, from: data) {
            return key
        }
        guard let curveKey = try? BinaryDecoder().decode(CurvePrivateKey.self, from: data) else {
            return nil
        }
        return try? X25519PrivateKey(id: curveKey.id, curveKey.rawRepresentation)
    }
}

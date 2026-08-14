//
//  X25519KeyWireTests.swift
//  post-quantum-solace
//

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
import Testing
@testable import SessionModels

@Suite("X25519 published-key type-header compatibility")
struct X25519KeyWireTests {
    @Test("CurvePublicKey type-header blobs decode as X25519PublicKey")
    func curvePublicKeyHeaderDecodesAsX25519() throws {
        let id = UUID()
        let raw = Data(repeating: 7, count: 32)
        let encoded = try BinaryEncoder().encode(CurvePublicKey(id: id, rawRepresentation: raw))
        let decoded = try #require(X25519KeyDecoding.publicKey(from: encoded))
        #expect(decoded.id == id)
        #expect(decoded.rawRepresentation == raw)
    }

    @Test("CurvePrivateKey type-header blobs decode as X25519PrivateKey")
    func curvePrivateKeyHeaderDecodesAsX25519() throws {
        let id = UUID()
        let raw = Data(repeating: 9, count: 32)
        let encoded = try BinaryEncoder().encode(CurvePrivateKey(id: id, rawRepresentation: raw))
        let decoded = try #require(X25519KeyDecoding.privateKey(from: encoded))
        #expect(decoded.id == id)
        #expect(decoded.rawRepresentation == raw)
    }

    @Test("X25519PublicKey type-header blobs still decode")
    func x25519PublicKeyHeaderStillDecodes() throws {
        let key = try X25519PublicKey(id: UUID(), Data(repeating: 3, count: 32))
        let encoded = try BinaryEncoder().encode(key)
        let decoded = try #require(X25519KeyDecoding.publicKey(from: encoded))
        #expect(decoded.id == key.id)
        #expect(decoded.rawRepresentation == key.rawRepresentation)
    }

    @Test("signed CurvePublicKey OTK blobs verify without a format error")
    func signedCurvePublicKeyOTKVerifies() throws {
        let signing = Curve25519.Signing.PrivateKey()
        let id = UUID()
        let raw = Data(repeating: 7, count: 32)
        let encoded = try BinaryEncoder().encode(CurvePublicKey(id: id, rawRepresentation: raw))
        let signed = UserConfiguration.SignedOneTimePublicKey(
            id: id,
            deviceId: UUID(),
            data: encoded,
            signature: try signing.signature(for: encoded)
        )
        let verified = try #require(try signed.verified(using: signing.publicKey))
        #expect(verified.id == id)
        #expect(verified.rawRepresentation == raw)
    }
}

//
//  AppKeyDerivationTests.swift
//  post-quantum-solace
//
//  The app-password key must depend on the device salt and carry a work factor.
//

import BinaryCodable
import Crypto
import Foundation
import NeedleTailCrypto
@testable import PQSSession
import SessionModels
import Testing

@Suite("App key derivation")
struct AppKeyDerivationTests {
    @Test("different salts derive different keys and the derivation is stable")
    func saltSeparatesKeys() {
        let crypto = NeedleTailCrypto()
        let password = Data("correct horse".utf8)
        let a = crypto.derivePasswordSymmetricKey(password: password, salt: Data("salt-a".utf8), iterations: 64)
        let b = crypto.derivePasswordSymmetricKey(password: password, salt: Data("salt-b".utf8), iterations: 64)
        let a2 = crypto.derivePasswordSymmetricKey(password: password, salt: Data("salt-a".utf8), iterations: 64)
        #expect(a != b)
        #expect(a == a2)
        #expect(a.bitCount == 256)
    }
}

extension EndToEndTests {
    @Test("a session context sealed under the salt-less pre-4.5 key is rejected")
    func saltlessBlobIsRejected() async throws {
        defer { Task { await shutdownSessions() } }
        let aliceStore = createSenderStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: SessionDelegate(session: _senderSession))
        let password = sMockUserData.sap
        let passwordData = Data(password.utf8)
        let salt = try await aliceStore.fetchLocalDeviceSalt(keyData: passwordData)

        let context = try #require(await _senderSession.sessionContext)
        let saltlessKey = await crypto.deriveStrictSymmetricKey(data: passwordData, salt: salt)
        let blob = try #require(try crypto.encrypt(data: BinaryEncoder().encode(context), symmetricKey: saltlessKey))
        try await aliceStore.updateLocalSessionContext(blob)
        await _senderSession.cache?.clearCache()

        #expect(!(await _senderSession.verifyAppPassword(password)))
        await #expect(throws: (any Error).self) {
            _ = try await _senderSession.unlock(appPassword: password)
        }
        #expect(try await aliceStore.fetchLocalSessionContext() == blob,
                "a rejected unlock must leave the stored blob untouched")
    }
}

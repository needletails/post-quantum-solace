//
//  AppKeyDerivationTests.swift
//  post-quantum-solace
//
//  The app-password key must depend on the device salt and carry a work factor.
//  Session contexts sealed under the old salt-less key still open and are
//  re-sealed under the new key on unlock.
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
    @Test("a session context sealed under the legacy key unlocks and is re-sealed")
    func legacyBlobUnlocksAndIsResealed() async throws {
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

        // Rewrite the stored blob the way a 4.0 client would have written it.
        let context = try #require(await _senderSession.sessionContext)
        let legacyKey = await crypto.deriveStrictSymmetricKey(data: passwordData, salt: salt)
        let legacyBlob = try #require(try crypto.encrypt(data: BinaryEncoder().encode(context), symmetricKey: legacyKey))
        try await aliceStore.updateLocalSessionContext(legacyBlob)
        await _senderSession.cache?.clearCache()

        _senderSession = try await _senderSession.unlock(appPassword: password)

        let stored = try await aliceStore.fetchLocalSessionContext()
        let currentKey = try await _senderSession.getAppSymmetricKey()
        #expect((try? crypto.decrypt(data: stored, symmetricKey: currentKey)) != nil,
                "the blob must be re-sealed under the generation-2 key")
        #expect((try? crypto.decrypt(data: stored, symmetricKey: legacyKey)) == nil,
                "the legacy key must no longer open the stored blob")
        #expect(await _senderSession.verifyAppPassword(password))
    }
}

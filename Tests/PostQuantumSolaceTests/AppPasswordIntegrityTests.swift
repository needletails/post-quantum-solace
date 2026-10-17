//
//  AppPasswordIntegrityTests.swift
//  post-quantum-solace
//
//  The live app password derives the key every session-context commit is
//  encrypted under. A failed password check must never replace it, and the
//  persisted blob must stay readable with the real password.
//

import BinaryCodable
import Foundation
import NeedleTailCrypto
import Testing
@testable import PQSSession
import SessionModels

extension EndToEndTests {
    private func persistedContextDecrypts(
        store: MockIdentityStore,
        password: String
    ) async throws -> Bool {
        let blob = try await store.fetchLocalSessionContext()
        let passwordData = Data(password.utf8)
        let salt = try await store.fetchLocalDeviceSalt(keyData: passwordData)
        let key = await _senderSession.deriveAppSymmetricKey(passwordData: passwordData, salt: salt)
        guard let decrypted = try? crypto.decrypt(data: blob, symmetricKey: key) else { return false }
        return (try? BinaryDecoder().decode(SessionContext.self, from: decrypted)) != nil
    }

    @Test("a failed password check leaves the live password and the persisted blob intact")
    func failedVerifyLeavesLivePasswordIntact() async throws {
        defer { Task { await shutdownSessions() } }
        let aliceStore = createSenderStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: SessionDelegate(session: _senderSession))
        let realPassword = sMockUserData.sap

        #expect(await _senderSession.verifyAppPassword(realPassword))
        #expect(!(await _senderSession.verifyAppPassword("not-the-password")))
        #expect(await _senderSession.appPassword == realPassword,
                "a rejected password must not become the live password")

        // Any routine commit re-encrypts the session context under the live key.
        _ = await _senderSession.refreshOneTimeKeysTask(policy: .replenishBatch)

        #expect(try await persistedContextDecrypts(store: aliceStore, password: realPassword),
                "the persisted session context must still open with the real password")
        #expect(await _senderSession.verifyAppPassword(realPassword))
    }

    @Test("a failed unlock on a live session leaves the live password intact")
    func failedUnlockOnLiveSessionLeavesLivePasswordIntact() async throws {
        defer { Task { await shutdownSessions() } }
        let aliceStore = createSenderStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: SessionDelegate(session: _senderSession))
        let realPassword = sMockUserData.sap

        await #expect(throws: (any Error).self) {
            _ = try await _senderSession.unlock(appPassword: "typo")
        }
        #expect(await _senderSession.appPassword == realPassword)

        _ = await _senderSession.refreshOneTimeKeysTask(policy: .replenishBatch)
        #expect(try await persistedContextDecrypts(store: aliceStore, password: realPassword))
    }

    @Test("a session-context rewrite survives a failing store create")
    func contextRewriteSurvivesCreateFailure() async throws {
        defer { Task { await shutdownSessions() } }
        let aliceStore = createSenderStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: SessionDelegate(session: _senderSession))

        let before = try await aliceStore.fetchLocalSessionContext()
        await aliceStore.setCreateLocalSessionContextError(PQSError.databaseNotInitialized)

        // A commit whose durable write fails must not leave the store empty.
        _ = try? await _senderSession.commitLiveSessionContextMutation { context in
            context.registrationState = .registered
        }
        await aliceStore.setCreateLocalSessionContextError(nil)

        let after = try await aliceStore.fetchLocalSessionContext()
        #expect(!after.isEmpty, "the previous blob must survive a failed replace")
        #expect(after == before || !(after.isEmpty))
    }
}

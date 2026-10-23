//
//  SessionContextCommitTests.swift
//  post-quantum-solace
//
//  `commitSessionContextMutation` is the host-facing way to edit and persist the
//  session context under the session's exclusive commit lock.
//

import BinaryCodable
import Foundation
@testable import PQSSession
import SessionModels
import Testing

extension EndToEndTests {
    private func persistedContext(store aliceStore: MockIdentityStore) async throws -> SessionContext {
        let blob = try await aliceStore.fetchLocalSessionContext()
        let key = try await _senderSession.getAppSymmetricKey()
        let plaintext = try #require(try crypto.decrypt(data: blob, symmetricKey: key))
        return try BinaryDecoder().decode(SessionContext.self, from: plaintext)
    }

    @Test("a host mutation is persisted and visible on the live context")
    func hostMutationIsCommitted() async throws {
        defer { Task { await shutdownSessions() } }
        let aliceStore = createSenderStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: SessionDelegate(session: _senderSession))

        let committed = try await _senderSession.commitSessionContextMutation { context in
            context.sessionUser.metadata.nickname = "renamed-by-host"
            return true
        }

        #expect(committed?.sessionUser.metadata.nickname == "renamed-by-host")
        #expect(await _senderSession.sessionContext?.sessionUser.metadata.nickname == "renamed-by-host")
        #expect(try await persistedContext(store: aliceStore).sessionUser.metadata.nickname == "renamed-by-host")
    }

    @Test("a mutation that reports no change persists nothing")
    func noChangeWritesNothing() async throws {
        defer { Task { await shutdownSessions() } }
        let aliceStore = createSenderStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: SessionDelegate(session: _senderSession))
        let before = try await aliceStore.fetchLocalSessionContext()

        let committed = try await _senderSession.commitSessionContextMutation { _ in false }

        #expect(committed == nil)
        #expect(try await aliceStore.fetchLocalSessionContext() == before)
    }
}

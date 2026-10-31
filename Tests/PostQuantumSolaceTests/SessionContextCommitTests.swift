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

    @Test("adoption starts from the live context, not the cache's warm copy")
    func adoptionKeepsLiveEdit() async throws {
        defer { Task { await shutdownSessions() } }
        let aliceStore = createSenderStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: SessionDelegate(session: _senderSession))
        // Installed on the session only: the warm copy never sees this edit.
        let hostState = Data([1, 2, 3])
        var live = try #require(await _senderSession.sessionContext)
        live.hostLocalPolicyData = hostState
        await _senderSession.setSessionContext(live)

        try await _senderSession.adoptVerifiedUserConfiguration(live.activeUserConfiguration)

        #expect(await _senderSession.sessionContext?.hostLocalPolicyData == hostState)
        #expect(try await persistedContext(store: aliceStore).hostLocalPolicyData == hostState)
    }

    @Test("rotation keeps what the session committed during its publish")
    func rotationKeepsCommitsFromItsPublishWindow() async throws {
        defer { Task { await shutdownSessions() } }
        let aliceStore = createSenderStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: SessionDelegate(session: _senderSession))
        let before = try #require(await _senderSession.sessionContext)
        let hostState = Data([4, 5, 6])
        let session = _senderSession
        aliceTransport.onPublishRotatedKeys = {
            try await session.commitSessionContextMutation { context in
                context.hostLocalPolicyData = hostState
                context.sessionUser.deviceKeys.oneTimePrivateKeys.removeAll()
                return true
            }
        }

        try await _senderSession.rotateCurrentDeviceKeys()

        let live = try #require(await _senderSession.sessionContext)
        let persisted = try await persistedContext(store: aliceStore)
        for context in [live, persisted] {
            #expect(context.hostLocalPolicyData == hostState)
            #expect(context.sessionUser.deviceKeys.oneTimePrivateKeys.isEmpty)
            #expect(context.sessionUser.deviceKeys.longTermPrivateKey != before.sessionUser.deviceKeys.longTermPrivateKey)
        }
    }
}

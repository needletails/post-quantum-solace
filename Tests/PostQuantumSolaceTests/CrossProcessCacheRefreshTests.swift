//
//  CrossProcessCacheRefreshTests.swift
//  post-quantum-solace
//
//  Two processes of one account share one store: the app and its notification
//  extension. Each keeps its own in-memory caches. After the other process advanced a
//  lane, this process must reload every cache before it encrypts again, or its next
//  frame rides a stale chain position and the peer cannot decrypt it (dogfood
//  2026-10-24..27: the master's first frame after each launch failed on its linked
//  device, while frames the extension sent in between decrypted).
//

import Foundation
import Testing
@testable import PQSSession

extension EndToEndTests {
    @Test("a cache refresh after another process wrote the store reloads the ratchet lanes too")
    func refreshAfterExternalWriteReloadsRatchetLanes() async throws {
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceStore = createSenderStore()
        await aliceStore.setDetachesRows(true)
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceDelegate = SessionDelegate(session: _senderSession)
        let bobDelegate = SessionDelegate(session: _recipientSession)
        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: aliceDelegate)
        try await createRecipientSession(
            store: createRecipientStore(),
            transport: bobTransport,
            sessionDelegate: bobDelegate)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: aliceDelegate,
            bobSession: _recipientSession,
            rsd: bobDelegate)

        // The extension: Alice's account unlocked a second time over the same store.
        var extensionSession = PQSSession()
        let extensionTransport = _MockTransportDelegate(session: extensionSession, store: store)
        let extensionReceiver = ReceiverDelegate(session: extensionSession)
        await extensionSession.setLogLevel(.trace)
        await extensionSession.setDatabaseDelegate(conformer: aliceStore)
        await extensionSession.setTransportDelegate(conformer: extensionTransport)
        await extensionSession.setPQSSessionDelegate(conformer: SessionDelegate(session: extensionSession))
        await extensionSession.setReceiverDelegate(conformer: extensionReceiver)
        await extensionSession.setConnectivity(true)
        await extensionSession.setAppPassword(sMockUserData.sap)
        extensionSession = try await extensionSession.unlock(appPassword: sMockUserData.sap)
        try await extensionReceiver.setKey(extensionSession.getDatabaseSymmetricKey())

        // Both processes deliver to Bob. Bob's replies are not part of this scenario.
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
            extensionTransport.continuation = continuation
        }
        bobTask = Task {
            for await received in bobStream {
                guard received.recipient == "bob" else { continue }
                _ = try? await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received)
            }
        }

        // A decrypt failure is handed to recovery, not thrown, so the only honest
        // signal is the chat row Bob persisted.
        func bobDecrypted(_ sharedId: String) async -> Bool {
            let deadline = Date().addingTimeInterval(8)
            while Date() < deadline {
                if (try? await _recipientSession.cache?.fetchMessageIfExists(sharedId: sharedId)) != nil {
                    return true
                }
                try? await Task.sleep(until: .now + .milliseconds(50))
            }
            return false
        }

        // 1. The app establishes the lane.
        let first = "one-\(UUID().uuidString)"
        try await _senderSession.send(recipient: .nickname("bob"), text: "one", sharedIdOverride: first)
        await _senderSession.waitForOutboundJobDrain()
        #expect(await bobDecrypted(first))

        // 2. The extension sends on the same lane from its own process.
        let second = "two-\(UUID().uuidString)"
        try await extensionSession.send(recipient: .nickname("bob"), text: "two", sharedIdOverride: second)
        await extensionSession.waitForOutboundJobDrain()
        #expect(await bobDecrypted(second))

        // 3. The host tells the app another process wrote the store; the app sends.
        try await _senderSession.refreshSessionCache()
        let third = "three-\(UUID().uuidString)"
        try await _senderSession.send(recipient: .nickname("bob"), text: "three", sharedIdOverride: third)
        await _senderSession.waitForOutboundJobDrain()
        #expect(await bobDecrypted(third), "the app must continue the lane where the extension left it")
    }
}

//
//  SynchronizeOneTimeKeysBindingTests.swift
//  post-quantum-solace
//
//  `synchronizeOneTimeKeys` names the one-time keys a bootstrap consumed. The
//  ids inside the decrypted payload are peer-supplied; only the ids the
//  verified ratchet header cites may be acted on, and the private halves stay
//  until deferred consumption confirms. Session-context writes on this path
//  must not roll back a concurrent commit.
//

import BinaryCodable
import Foundation
import Testing
@testable import PQSSession
import SessionModels

extension EndToEndTests {
    private func setUpAliceBob() async throws -> (
        aliceTransport: _MockTransportDelegate,
        bobTransport: _MockTransportDelegate,
        bob: String
    ) {
        let aliceStore = createSenderStore()
        let bobStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceDelegate = SessionDelegate(session: _senderSession)
        let bobDelegate = SessionDelegate(session: _recipientSession)
        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: aliceDelegate)
        try await createRecipientSession(
            store: bobStore,
            transport: bobTransport,
            sessionDelegate: bobDelegate)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: aliceDelegate,
            bobSession: _recipientSession,
            rsd: bobDelegate)
        return (aliceTransport, bobTransport, rMockUserData.rsn)
    }

    @Test("payload key ids that do not match the ratchet header are ignored")
    func payloadKeyIdsMustMatchRatchetHeader() async throws {
        defer { Task { await shutdownSessions() } }
        let (aliceTransport, bobTransport, bob) = try await setUpAliceBob()

        let bobKeys = try #require(await _recipientSession.sessionContext?.sessionUser.deviceKeys)
        let victimX25519 = try #require(bobKeys.oneTimePrivateKeys.first?.id)
        let victimMLKEM = try #require(bobKeys.mlKEMOneTimePrivateKeys.first?.id)

        // Every frame Alice sends now claims, inside the authenticated payload,
        // that it consumed Bob's victim keys. The ratchet header says otherwise.
        let forged = try BinaryEncoder().encode(
            TransportEvent.synchronizeOneTimeKeys(
                SynchronizationKeyIdentities(
                    senderX25519Id: nil,
                    senderMLKEMId: nil,
                    recipientX25519Id: victimX25519.uuidString,
                    recipientMLKEMId: victimMLKEM.uuidString)))
        await _recipientSession.setTestDecryptedPayloadTransform { data in
            guard var message = try? BinaryDecoder().decode(CryptoMessage.self, from: data) else {
                return data
            }
            message.transportInfo = forged
            return (try? BinaryEncoder().encode(message)) ?? data
        }

        let log = SentEnvelopeLog()
        aliceTransport.duringSendMessage = { received in await log.record(received) }

        // Deliver Alice's frames into Bob's session, as the harness receive loops do.
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        let bobLoop = Task {
            for await received in bobStream {
                _ = try? await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
            }
        }
        defer {
            aliceTransport.continuation?.finish()
            bobLoop.cancel()
        }

        let sharedId = "forged-sync-\(UUID().uuidString)"
        try await _senderSession.send(
            recipient: .nickname(bob),
            text: "claims your keys are spent",
            sharedIdOverride: sharedId)
        await _senderSession.waitForOutboundJobDrain()

        // Wait until Bob has committed the frame (ledgered after decrypt + handling).
        let envelope = try #require(await log.first { $0.logicalMessageId == sharedId })
        let aliceDeviceId = try #require(await _senderSession.sessionContext?.sessionUser.deviceId)
        var accepted = false
        for _ in 0..<100 where !accepted {
            accepted = try await _recipientSession.hasAcceptedEnvelope(
                senderSecretName: sMockUserData.ssn,
                senderDeviceId: aliceDeviceId,
                envelopeMessageId: envelope.messageId)
            if !accepted { try await Task.sleep(nanoseconds: 50_000_000) }
        }
        #expect(accepted, "Bob must process the forged frame for this test to be meaningful")

        let after = try #require(await _recipientSession.sessionContext?.sessionUser.deviceKeys)
        #expect(after.oneTimePrivateKeys.contains { $0.id == victimX25519 },
                "a peer must not be able to delete an X25519 one-time private key it never consumed")
        #expect(after.mlKEMOneTimePrivateKeys.contains { $0.id == victimMLKEM },
                "a peer must not be able to delete an ML-KEM one-time private key it never consumed")
        let deleted = await bobTransport.deletedOneTimeKeyIds.map(\.deviceId)
        #expect(!deleted.contains(victimX25519.uuidString),
                "no server-side delete may be issued for a key the header does not cite")
        #expect(!deleted.contains(victimMLKEM.uuidString))
    }
}

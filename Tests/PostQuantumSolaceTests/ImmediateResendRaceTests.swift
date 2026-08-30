//
//  ImmediateResendRaceTests.swift
//  PostQuantumSolaceTests
//
//  Regression for a live recipient requesting resend before the sender's
//  transport call has unwound.
//

import Foundation
import Testing
@testable import PQSSession

extension EndToEndTests {
    @Test("Immediate live resend resolves the original envelope before transport returns")
    func immediateLiveResendBeforeTransportReturns() async throws {
        actor ResendProbe {
            private var armed = true
            private(set) var requestedEnvelopeId: String?
            private(set) var queuedIds: [String] = []
            private(set) var unavailableIds: [String] = []

            func claim(envelopeId: String) -> Bool {
                guard armed else { return false }
                armed = false
                requestedEnvelopeId = envelopeId
                return true
            }

            func record(_ result: PQSSession.OutOfBandResendResult) {
                queuedIds = result.queuedIds
                unavailableIds = result.permanentlyUnavailableIds
            }
        }

        defer {
            Task { await shutdownSessions() }
        }

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

        let bobDeviceId = try #require(
            await _recipientSession.sessionContext?.sessionUser.deviceId)
        let sharedId = "immediate-resend-\(UUID().uuidString)"
        let probe = ResendProbe()
        let originalTransportEntered = ContinuationSignal()
        let releaseOriginalTransport = ContinuationSignal()

        aliceTransport.duringSendMessage = { received in
            guard received.logicalMessageId == sharedId,
                  await probe.claim(envelopeId: received.messageId)
            else { return }
            await originalTransportEntered.signal()
            await releaseOriginalTransport.wait()
        }

        let originalSend = Task {
            try await self._senderSession.send(
                recipient: .nickname("bob"),
                text: "recipient immediately asks for this ciphertext again",
                sharedIdOverride: sharedId)
        }
        defer {
            Task { await releaseOriginalTransport.signal() }
        }
        await originalTransportEntered.wait()

        let requestedEnvelopeId = try #require(await probe.requestedEnvelopeId)
        let result = try await _senderSession.handleOutOfBandResendRequest(
            from: "bob",
            deviceId: bobDeviceId,
            failedSharedMessageIds: [requestedEnvelopeId])
        await probe.record(result)
        await releaseOriginalTransport.signal()
        try await originalSend.value

        #expect(
            await probe.queuedIds.contains(requestedEnvelopeId),
            "The sender must resolve and replay an accepted envelope even when the resend request arrives before transport returns")
        #expect(
            await probe.unavailableIds.isEmpty,
            "A persisted live message must not become permanently unavailable during the transport handoff")
    }
}

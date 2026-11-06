//  ReplayRearmEndToEndTests.swift
//  post-quantum-solace
//
//  Bob NACKs while the sender is away. His host re-arms the placeholder at each offline
//  boundary, so NACKs that can prove nothing pile up before the sender returns. The failed
//  replay must still get its own NACK: only that one proves the lane dead.

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels
@testable import DoubleRatchetKit

extension EndToEndTests {
    private actor NackGate {
        var isOpen = false
        var held: [ReceivedMessage] = []
        var seen = 0
        /// `true` when the caller should service it now.
        func admit(_ received: ReceivedMessage) -> Bool {
            guard received.oobResendRequest != nil else { return true }
            seen += 1
            if isOpen { return true }
            held.append(received)
            return false
        }
        func open() -> [ReceivedMessage] {
            isOpen = true
            defer { held = [] }
            return held
        }
    }

    private actor LastContent {
        var logical: String?
        func note(_ id: String?) { if let id { logical = id } }
    }

    private actor Dropper {
        var remaining: Int
        init(_ n: Int) { remaining = n }
        func shouldDrop() -> Bool {
            if remaining > 0 { remaining -= 1; return true }
            return false
        }
    }

    private func runSenderAwayRecovery(boundaries: Int, failedMessages: Int = 1) async throws -> Bool {
        var bobTask: Task<Void, Never>?
        var aliceRepairTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                aliceRepairTask?.cancel()
                await shutdownSessions()
            }
        }
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        let bobStream = AsyncStream<ReceivedMessage> { aliceTransport.continuation = $0 }
        let aliceRepairStream = AsyncStream<ReceivedMessage> { bobTransport.continuation = $0 }
        let gate = NackGate()
        let lastContent = LastContent()
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        let bobStore = createRecipientStore()
        let aliceStore = createSenderStore()
        try await createSenderMaxSkipSession(store: aliceStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: bobStore, transport: bobTransport, sessionDelegate: rsd)
        await _senderMaxSkipSession.messagePipeline.testSetAckDeadlineNanosecondsForTests(3_600_000_000_000)

        aliceRepairTask = Task {
            for await received in aliceRepairStream {
                guard await gate.admit(received) else { continue }
                _ = try? await self.receiveIgnoringRecoverableErrors(self._senderMaxSkipSession, received: received)
            }
        }
        bobTask = Task {
            for await received in bobStream {
                if received.isContentMessage { await lastContent.note(received.logicalMessageId) }
                _ = try? await self.receiveIgnoringRecoverableErrors(self._recipientMaxSkipSession, received: received)
            }
        }
        try await createFriendship(aliceSession: _senderMaxSkipSession, sd: sd, bobSession: _recipientMaxSkipSession, rsd: rsd)
        let aliceDeviceId = try #require(await _senderMaxSkipSession.sessionContext?.sessionUser.deviceId)

        func waitUntil(_ timeoutSeconds: TimeInterval = 8, _ condition: @escaping @Sendable () async -> Bool) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(until: .now + .milliseconds(50))
            }
            return false
        }
        #expect(await waitUntil {
            let outbound = (try? await self._senderMaxSkipSession.hasInitializedOutboundRatchetForPeer("bob")) == true
            let inbound = await self._recipientMaxSkipSession.hasActiveInboundSessionIdentity(secretName: "alice", deviceId: aliceDeviceId)
            return outbound && inbound
        })
        try await _senderMaxSkipSession.send(recipient: .nickname("bob"), text: "warmup")
        #expect(await waitUntil { await bobStore.getAllMessages().count >= 3 })

        // Bob answers the lane, so alice's first replay rides it and fails too.
        try await _recipientMaxSkipSession.send(recipient: .nickname("alice"), text: "answer")
        #expect(await waitUntil { await aliceStore.getAllMessages().count >= 3 })
        try await Task.sleep(until: .now + .milliseconds(500))

        let dropper = Dropper(11)
        aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob", received.isContentMessage else { return true }
            return !(await dropper.shouldDrop())
        }
        for i in 1...(11 + failedMessages) {
            try await _senderMaxSkipSession.send(recipient: .nickname("bob"), text: "msg \(i)")
        }
        #expect(await waitUntil { await gate.seen >= 1 }, "The dropped frames must cost bob a NACK")
        let logical = try #require(await lastContent.logical)
        let baseline = await bobStore.getAllMessages().count

        // Alice is away. Bob reconnects: each boundary re-arms his placeholder row and flushes.
        for _ in 0..<boundaries {
            await _recipientMaxSkipSession.clearResendCooldownsForTests()
            await _recipientMaxSkipSession.rearmInboundRecoveryPendingResend(
                sender: "alice",
                deviceId: aliceDeviceId,
                sharedMessageId: logical)
            await _recipientMaxSkipSession.flushPendingResendsAfterOfflineReplay()
        }
        // Alice is back and reads her spooled NACKs.
        for received in await gate.open() {
            _ = try? await self.receiveIgnoringRecoverableErrors(self._senderMaxSkipSession, received: received)
        }
        let healed = await waitUntil(failedMessages > 1 ? 25 : 10) { await bobStore.getAllMessages().count >= baseline + failedMessages }
        try await Task.sleep(until: .now + .seconds(2))
        return healed
    }

    @Test("Replay recovery: eight failed messages on one lane")
    func testReplayRecoveryManyMessages() async throws {
        #expect(try await runSenderAwayRecovery(boundaries: 0, failedMessages: 8))
    }

    @Test("Replay recovery: no boundary while the sender is away")
    func testReplayRecoveryControl() async throws {
        #expect(try await runSenderAwayRecovery(boundaries: 0))
    }

    @Test("Replay recovery: two boundaries while the sender is away")
    func testReplayRecoveryTwoBoundaries() async throws {
        #expect(try await runSenderAwayRecovery(boundaries: 2))
    }
}

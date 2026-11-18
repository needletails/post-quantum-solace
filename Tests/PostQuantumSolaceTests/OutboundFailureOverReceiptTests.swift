//
//  OutboundFailureOverReceiptTests.swift
//  post-quantum-solace
//
//  A failure for lack of a server accept must not replace a receipt. Once a peer's
//  delivered or read receipt has advanced a sent message, running out of the accept budget
//  for one of its envelopes leaves that state alone. A message nobody has receipted still
//  fails, also when another device's envelope was accepted first. Nor may a server accept
//  that arrives after a receipt move the message back to waiting for delivery.
//
//  Real pieces: connected PQSSessions (`connectedPair`, plus linked devices where a test
//  needs more than one envelope), the sender's real outbound job, the real accept ledger and
//  deadlines (shortened through the test seam), the sender's real SessionCache, and the
//  recipient really decrypting the routed copy. Doubles: the server, which holds every copy
//  of the test message so no accept is ever written for it, and the host, which makes the
//  calls nudge-kit makes.
//

import DoubleRatchetKit
import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

/// Holds every copy of the test message; everything else is routed to Bob's first device.
actor HeldEnvelopeServer {
    struct Copy: Sendable {
        let envelope: String
        let recipient: String
        let deviceId: UUID?
        let frame: ReceivedMessage
    }

    let heldSharedId: String
    let routedDevice: UUID
    private(set) var copies: [Copy] = []

    init(heldSharedId: String, routedDevice: UUID) {
        self.heldSharedId = heldSharedId
        self.routedDevice = routedDevice
    }

    /// Called from the sender's transport for every outbound frame. Returns whether the
    /// frame is routed to the recipient now.
    func ingest(_ frame: ReceivedMessage) -> Bool {
        if frame.logicalMessageId == heldSharedId && frame.isContentMessage {
            copies.append(Copy(
                envelope: frame.messageId,
                recipient: frame.recipient,
                deviceId: frame.recipientDeviceId,
                frame: frame))
            return false
        }
        return frame.recipient == "bob"
            && (frame.recipientDeviceId == nil || frame.recipientDeviceId == routedDevice)
    }

    func firstCopy(recipient: String, deviceId: UUID) -> Copy? {
        copies.first { $0.recipient == recipient && $0.deviceId == deviceId }
    }

    func copyCount(of envelope: String) -> Int {
        copies.filter { $0.envelope == envelope }.count
    }

    /// Distinct envelopes addressed to bob, in the order they reached the server.
    func bobEnvelopesInOrder() -> [String] {
        var seen: [String] = []
        for copy in copies where copy.recipient == "bob" && !seen.contains(copy.envelope) {
            seen.append(copy.envelope)
        }
        return seen
    }
}

actor ReadSideSilentRecorder {
    private(set) var ids: [String] = []
    func record(_ id: String) { ids.append(id) }
    func contains(_ id: String) -> Bool { ids.contains(id) }
}

extension EndToEndTests {
    struct AcceptRig {
        let pair: ConnectedPair
        let server: HeldEnvelopeServer
        let sink: RecordingAuditSink
        let silent: ReadSideSilentRecorder
        let sharedId: String
        let localId: UUID
        let bobMaster: UUID
        let bobChild: UUID?
        let aliceChild: UUID?
    }

    static let acceptRigShortDeadline: UInt64 = 25_000_000
    static let acceptRigLongDeadline: UInt64 = 3_600_000_000_000

    /// Alice sends one chat message to Bob and the server holds every copy of it. With
    /// `bobChild` Bob has a second linked device (a second envelope that gates the row);
    /// with `aliceChild` Alice has a linked device that gets the sibling copy.
    func startAcceptRig(
        bobChild withBobChild: Bool = false,
        aliceChild withAliceChild: Bool = false,
        onIngest: (@Sendable (ReceivedMessage, HeldEnvelopeServer, PQSSession) async -> Void)? = nil
    ) async throws -> AcceptRig {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(aliceAuditSink: sink)
        // The sender's store hands out a new instance per fetch, as the app's store does, so
        // a state only reaches the store through a store write.
        await pair.aliceStore.setReturnsFreshMessageRows(true)
        await pair.alice.waitForOutboundJobDrain()
        await jobLoopIdle(pair.alice)
        await jobLoopIdle(pair.bob)

        var aliceChildId: UUID?
        if withAliceChild {
            try await linkSenderChildSession1(
                store: createSenderChildStore1(),
                transport: _MockTransportDelegate(session: _senderChildSession1, store: store),
                useProvidedTransport: true)
            _ = try await pair.alice.refreshIdentities(secretName: "alice", forceRefresh: true)
            aliceChildId = try #require(await _senderChildSession1.sessionContext?.sessionUser.deviceId)
            await _senderChildSession1.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigLongDeadline)
        }
        var bobChildId: UUID?
        if withBobChild {
            try await linkRecipientChildSession1(
                store: createRecipientChildStore1(),
                transport: _MockTransportDelegate(session: _recipientChildSession1, store: store),
                useProvidedTransport: true)
            bobChildId = try #require(await _recipientChildSession1.sessionContext?.sessionUser.deviceId)
            await _recipientChildSession1.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigLongDeadline)
            await pair.alice.setVerifiedDeviceIds([pair.bobDeviceId, try #require(bobChildId)], for: "bob")
        }
        await pair.alice.waitForOutboundJobDrain()
        await jobLoopIdle(pair.alice)
        // Setup traffic went out before the server double existed; a live server accepted it.
        for id in await Array(pair.alice.messagePipeline.unackedServerAcceptByEnvelopeId.keys) {
            await pair.alice.confirmServerAcceptedEnvelope(id)
        }

        let sharedId = "accept-rig-\(UUID().uuidString)"
        let server = HeldEnvelopeServer(heldSharedId: sharedId, routedDevice: pair.bobDeviceId)
        let alice = pair.alice
        pair.aliceTransport.shouldDeliver = { frame in
            let routed = await server.ingest(frame)
            await onIngest?(frame, server, alice)
            return routed
        }
        let silent = ReadSideSilentRecorder()
        await alice.setServerAcceptReadSideSilentHandler { id in await silent.record(id) }

        try await alice.send(recipient: .nickname("bob"), text: "accept rig", sharedIdOverride: sharedId)
        let bobMaster = pair.bobDeviceId
        let bobChildIdCopy = bobChildId
        let aliceChildIdCopy = aliceChildId
        let copiesArrived = await pollUntil(timeout: 30) {
            guard await server.firstCopy(recipient: "bob", deviceId: bobMaster) != nil else { return false }
            if let bobChildId = bobChildIdCopy,
               await server.firstCopy(recipient: "bob", deviceId: bobChildId) == nil { return false }
            if let aliceChildId = aliceChildIdCopy,
               await server.firstCopy(recipient: "alice", deviceId: aliceChildId) == nil { return false }
            return true
        }
        try #require(copiesArrived, "setup: one copy per device reached the server")
        await alice.waitForOutboundJobDrain()
        await jobLoopIdle(alice)
        let row = try #require(try await alice.cache?.fetchMessageIfExists(sharedId: sharedId))
        return AcceptRig(
            pair: pair, server: server, sink: sink, silent: silent, sharedId: sharedId,
            localId: row.id, bobMaster: bobMaster, bobChild: bobChildId, aliceChild: aliceChildId)
    }

    func envelope(_ rig: AcceptRig, _ recipient: String, _ deviceId: UUID?) async throws -> String {
        let deviceId = try #require(deviceId)
        return try #require(await rig.server.firstCopy(recipient: recipient, deviceId: deviceId)?.envelope)
    }

    /// The state the host shows: the row in the store, not PQS's cached copy.
    func rowState(_ rig: AcceptRig) async throws -> DeliveryState? {
        let key = try await rig.pair.alice.getDatabaseSymmetricKey()
        let row = try #require(try await rig.pair.aliceStore.fetchMessageIfExists(sharedId: rig.sharedId))
        return await row.props(symmetricKey: key)?.deliveryState
    }

    /// The server routes the copy for Bob's first device; that device really decrypts and
    /// stores it.
    func deliverToBobMaster(_ rig: AcceptRig) async throws {
        let copy = try #require(await rig.server.firstCopy(recipient: "bob", deviceId: rig.bobMaster))
        rig.pair.aliceTransport.continuation?.yield(copy.frame)
        try #require(await persisted(rig.pair.bob, rig.sharedId), "setup: Bob stored the routed message")
    }

    /// What nudge-kit does with a peer's receipt (`applyDeliveryStateChange`): load the row
    /// from its own store, set the state, save it to that store, tell the receiver. It never
    /// goes through PQS's `SessionCache`, and the store returns a new instance per fetch, so
    /// the row PQS cached keeps its old state.
    func hostAppliesReceipt(_ rig: AcceptRig, _ newState: DeliveryState) async throws {
        let alice = rig.pair.alice
        let store = rig.pair.aliceStore
        let key = try await alice.getDatabaseSymmetricKey()
        let row = try #require(try await store.fetchMessageIfExists(sharedId: rig.sharedId))
        var props = try #require(await row.props(symmetricKey: key))
        props.deliveryState = newState
        let updated = try await row.updateMessage(with: props, symmetricKey: key)
        try await store.updateMessage(updated, symmetricKey: key)
        await alice.receiverDelegate?.updatedMessage(updated)
    }

    /// Runs the accept budget out for `envelopes`, the way it happens on a device: in-place
    /// resends until PQS reports read-side silence, the host's replay on the next
    /// registration, then the next accept window ends.
    func exhaustAcceptBudget(_ rig: AcceptRig, for envelopes: [String]) async throws {
        let alice = rig.pair.alice
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigShortDeadline)
        await alice.rearmAllServerAcceptDeadlines()
        let silent = rig.silent
        let allSilent = await pollUntil(timeout: 30) {
            for envelope in envelopes {
                if !(await silent.contains(envelope)) { return false }
            }
            return true
        }
        try #require(allSilent, "setup: read-side silence for every pending envelope")
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigLongDeadline)
        await alice.resendUnackedOutboundEnvelopes(reason: "IRC registered")
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigShortDeadline)
        await alice.rearmAllServerAcceptDeadlines()
        let sink = rig.sink
        let allExhausted = await pollUntil(timeout: 30) {
            envelopes.allSatisfy { sink.contains("pqs.send.ackOverdueExhausted envelopeMessageId=\($0)") }
        }
        try #require(allExhausted, "setup: the accept budget ran out for every pending envelope")
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigLongDeadline)
    }

    func finishRig(_ rig: AcceptRig) async {
        await rig.pair.finish()
        await shutdownSessions()
    }

    /// Accepts Bob's first envelope at the moment his second device's first copy reaches the
    /// server, so the row is past sending while that second envelope is still tracked.
    static let acceptFirstBobEnvelopeOnSecondCopy: @Sendable (ReceivedMessage, HeldEnvelopeServer, PQSSession) async -> Void = { frame, server, alice in
        guard frame.recipient == "bob", frame.isContentMessage, frame.logicalMessageId == server.heldSharedId else { return }
        let order = await server.bobEnvelopesInOrder()
        guard order.count == 2, order[1] == frame.messageId else { return }
        guard await server.copyCount(of: frame.messageId) == 1 else { return }
        await alice.confirmServerAcceptedEnvelope(order[0])
    }

    // MARK: - One envelope

    @Test("A read receipt survives running out of the accept budget")
    func readReceiptSurvivesAcceptExhaustion() async throws {
        let rig = try await startAcceptRig()
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await deliverToBobMaster(rig)
        try await hostAppliesReceipt(rig, .read)
        let applied = try await rowState(rig)
        try #require(applied == .read, "setup: the receipt was applied")
        try await exhaustAcceptBudget(rig, for: [pending])
        let observed = try await rowState(rig)
        #expect(observed == .read, "a read message must not be written back to failed: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    @Test("A delivered receipt survives running out of the accept budget")
    func deliveredReceiptSurvivesAcceptExhaustion() async throws {
        let rig = try await startAcceptRig()
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await deliverToBobMaster(rig)
        try await hostAppliesReceipt(rig, .delivered)
        let applied = try await rowState(rig)
        try #require(applied == .delivered, "setup: the receipt was applied")
        try await exhaustAcceptBudget(rig, for: [pending])
        let observed = try await rowState(rig)
        #expect(observed == .delivered, "a delivered message must not be written back to failed: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    @Test("Control: a message nobody has receipted fails when the accept budget runs out")
    func unreceiptedMessageFailsOnAcceptExhaustion() async throws {
        let rig = try await startAcceptRig()
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        let fresh = try await rowState(rig)
        try #require(fresh == .sending, "setup: a fresh outbound message is sending")
        try await exhaustAcceptBudget(rig, for: [pending])
        let observed = try await rowState(rig)
        #expect(observed == .failed("serverAcceptExhausted"), "observed \(String(describing: observed))")
        await finishRig(rig)
    }

    /// A sequence seen in a field log: the budget runs out and the message fails, a peer's
    /// read receipt corrects it, and the envelope, still tracked, is failed again on the next
    /// registration and again when the next accept window ends.
    @Test("A read receipt applied after the failure survives the next registration")
    func readReceiptAfterFailureSurvivesTheNextRegistration() async throws {
        let rig = try await startAcceptRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await deliverToBobMaster(rig)
        try await exhaustAcceptBudget(rig, for: [pending])
        let failed = try await rowState(rig)
        try #require(failed == .failed("serverAcceptExhausted"), "setup: the message failed first")
        try await hostAppliesReceipt(rig, .read)
        let applied = try await rowState(rig)
        try #require(applied == .read, "setup: the receipt was applied over the failure")
        try #require(await alice.isAwaitingServerAccept(pending), "setup: the envelope is still tracked")

        await alice.resendUnackedOutboundEnvelopes(reason: "IRC registered")
        let afterRegistration = try await rowState(rig)
        #expect(afterRegistration == .read, "the next registration must not fail a read message again: observed \(String(describing: afterRegistration))")

        let exhaustedLine = "pqs.send.ackOverdueExhausted envelopeMessageId=\(pending)"
        let sink = rig.sink
        let firedBefore = sink.lines(containing: exhaustedLine).count
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigShortDeadline)
        await alice.rearmAllServerAcceptDeadlines()
        let firedAgain = await pollUntil(timeout: 30) { sink.lines(containing: exhaustedLine).count > firedBefore }
        try #require(firedAgain, "setup: the next accept window ended without an accept")
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigLongDeadline)
        let observed = try await rowState(rig)
        #expect(observed == .read, "a read message must not be written back to failed: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    // MARK: - Several envelopes for one message

    @Test("One device's read receipt survives another device's accept exhaustion")
    func readReceiptSurvivesAnotherDevicesAcceptExhaustion() async throws {
        let rig = try await startAcceptRig(bobChild: true, aliceChild: true)
        let bobMaster = try await envelope(rig, "bob", rig.bobMaster)
        let bobChild = try await envelope(rig, "bob", rig.bobChild)
        let aliceChild = try await envelope(rig, "alice", rig.aliceChild)
        try await deliverToBobMaster(rig)
        await rig.pair.alice.confirmServerAcceptedEnvelope(bobMaster)
        let stillSending = try await rowState(rig)
        try #require(stillSending == .sending, "setup: Bob's other device still holds the message at sending")
        try await hostAppliesReceipt(rig, .read)
        try await exhaustAcceptBudget(rig, for: [bobChild, aliceChild])
        let observed = try await rowState(rig)
        #expect(observed == .read, "a read message must not be written back to failed: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    /// The failure a guard must not hide: the accept for one of the contact's devices lands
    /// before the envelope for the other device is registered, so the message is already past
    /// sending when that second envelope starts to be tracked, and the second device never
    /// gets its copy.
    @Test("Accepted for one device, the message still fails when another device's accept never comes")
    func acceptedForOneDeviceStillFailsWhenAnotherDeviceExhausts() async throws {
        let rig = try await startAcceptRig(bobChild: true, onIngest: Self.acceptFirstBobEnvelopeOnSecondCopy)
        let order = await rig.server.bobEnvelopesInOrder()
        try #require(order.count == 2, "setup: two envelopes for Bob, observed \(order.count)")
        try #require(await rig.pair.alice.isAwaitingServerAccept(order[0]) == false, "setup: the first was accepted")
        let pastSending = try await rowState(rig)
        try #require(pastSending == .waitingDelivery, "setup: the message is past sending while the second envelope is tracked")
        try await exhaustAcceptBudget(rig, for: [order[1]])
        let observed = try await rowState(rig)
        #expect(observed == .failed("serverAcceptExhausted"), "observed \(String(describing: observed))")
        await finishRig(rig)
    }

    // MARK: - A server accept that arrives after a receipt

    @Test("A read receipt survives a server accept that arrives after it")
    func readReceiptSurvivesALateServerAccept() async throws {
        let rig = try await startAcceptRig()
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await deliverToBobMaster(rig)
        try await hostAppliesReceipt(rig, .read)
        let applied = try await rowState(rig)
        try #require(applied == .read, "setup: the receipt was applied")
        try #require(await rig.pair.alice.isAwaitingServerAccept(pending), "setup: the accept is still outstanding")
        await rig.pair.alice.confirmServerAcceptedEnvelope(pending)
        try #require(await rig.pair.alice.isAwaitingServerAccept(pending) == false, "setup: the accept was consumed")
        let observed = try await rowState(rig)
        #expect(observed == .read, "a read message must not be written back to waiting for delivery: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    @Test("Control: a server accept moves a message nobody has receipted past sending")
    func serverAcceptMovesAnUnreceiptedMessagePastSending() async throws {
        let rig = try await startAcceptRig()
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        let fresh = try await rowState(rig)
        try #require(fresh == .sending, "setup: a fresh outbound message is sending")
        await rig.pair.alice.confirmServerAcceptedEnvelope(pending)
        let observed = try await rowState(rig)
        #expect(observed == .waitingDelivery, "observed \(String(describing: observed))")
        await finishRig(rig)
    }
}

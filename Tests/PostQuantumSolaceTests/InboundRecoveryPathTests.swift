//
//  InboundRecoveryPathTests.swift
//  post-quantum-solace
//
//  The receiver's side of recovery, pinned against dogfood 2026-10-28 (the Mac
//  child lost one channel message and received another 59 minutes late): the
//  archive pass runs before any resend request leaves, an initiating frame
//  opens its lane whatever its position in the sender's chain, and a copy of
//  content this device already holds decrypts first, then settles the resend
//  requests pending for it. A recovery placeholder is not content, whatever
//  its delivery state.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels
@testable import DoubleRatchetKit

extension MessagePipeline {
    /// A pass queued for `token` whose job has not run.
    fileprivate func queueArchivePass(_ token: ArchivedInboundFallbackToken) {
        archivedInboundFallbackPasses[token.storageKey] = []
    }
}

extension PQSSession {
    /// Context present, delegates absent, as `fetchLocalSessionContext` documents.
    fileprivate func clearSessionDelegate() {
        sessionDelegate = nil
    }
}

extension EndToEndTests {
    private func persisted(_ session: PQSSession, _ sharedId: String, timeout: TimeInterval = 20) async -> Bool {
        await pollUntil(timeout: timeout) {
            (try? await session.cache?.fetchMessageIfExists(sharedId: sharedId)) != nil
        }
    }

    private func identity(on session: PQSSession, id: UUID) async throws -> SessionIdentity {
        let cache = try #require(await session.cache)
        return try #require(try await cache.fetchSessionIdentities().first { $0.id == id })
    }

    private func lanePropsOnBob(_ pair: ConnectedPair, id: UUID) async -> SessionIdentity.UnwrappedProps? {
        guard let row = try? await identity(on: pair.bob, id: id),
              let key = try? await pair.bob.getDatabaseSymmetricKey()
        else { return nil }
        return await row.props(symmetricKey: key)
    }

    private func laneSelections(on session: PQSSession, sharedId: String) async -> [InboundLaneSelectionStats] {
        await session.messagePipeline.inboundLaneSelectionStatsLog.filter { $0.sharedId == sharedId }
    }

    /// Writes a chat row on bob for `sharedId`, as alice's device sent it. A recovery
    /// placeholder carries the marker the test delegate recognises.
    private func seedChatRowOnBob(
        _ pair: ConnectedPair,
        sharedId: String,
        text: String,
        deliveryState: DeliveryState,
        transportInfo: Data? = nil
    ) async throws {
        let key = try await pair.bob.getDatabaseSymmetricKey()
        let communication = try await pair.bob.conversation(for: .nickname("alice"))
        let messageId = UUID()
        let row = try EncryptedMessage(
            id: messageId,
            communicationId: communication.id,
            sessionContextId: await pair.bob.sessionContext?.sessionContextId ?? 0,
            sharedId: sharedId,
            sequenceNumber: 1,
            props: EncryptedMessage.UnwrappedProps(
                id: messageId,
                base: communication,
                sentDate: Date(),
                receiveDate: Date(),
                deliveryState: deliveryState,
                message: CryptoMessage(
                    text: text,
                    metadata: Data(),
                    recipient: .nickname("bob"),
                    transportInfo: transportInfo,
                    sentDate: Date(),
                    destructionTime: nil),
                senderSecretName: "alice",
                senderDeviceId: pair.aliceDeviceId),
            symmetricKey: key)
        try await pair.bob.cache?.createMessage(row, symmetricKey: key)
    }

    private func chatRowOnBob(_ pair: ConnectedPair, _ sharedId: String) async -> EncryptedMessage.UnwrappedProps? {
        guard let row = try? await pair.bob.cache?.fetchMessageIfExists(sharedId: sharedId),
              let key = try? await pair.bob.getDatabaseSymmetricKey()
        else { return nil }
        return await row.props(symmetricKey: key)
    }

    private func accepted(_ pair: ConnectedPair, envelope: String) async -> Bool {
        (try? await pair.bob.hasAcceptedEnvelope(
            senderSecretName: "alice",
            senderDeviceId: pair.aliceDeviceId,
            envelopeMessageId: envelope)) == true
    }

    /// Bob's ledger forgets everything, so `frame` redelivered under a fresh envelope
    /// id reaches the lanes and fails there: its keys are spent. `logical` names the
    /// chat row the copy claims.
    private func replayConsumedFrame(_ pair: ConnectedPair, _ frame: ReceivedMessage, logical: String) async throws -> String {
        await pair.bob.pruneAcceptedEnvelopes(now: Date().addingTimeInterval(pair.bob.acceptedEnvelopeRetention + 60))
        let replayId = "replay-\(UUID().uuidString)"
        try await pair.bob.receiveMessage(
            message: frame.message,
            sender: frame.sender,
            deviceId: frame.deviceId,
            messageId: replayId,
            logicalMessageId: logical)
        return replayId
    }

    /// Alice opens a fresh lane toward bob and bob takes `count` of its initial-chain
    /// frames on one row. Returns that row and the frames as they crossed the wire.
    private func openInitialChain(
        _ pair: ConnectedPair,
        frames count: Int
    ) async throws -> (holder: UUID, frames: [ReceivedMessage]) {
        _ = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sendOneTimeIdentities: true,
            reason: "test")
        let captured = HeldFrames()
        pair.aliceTransport.transformOutgoing = { received in
            if received.recipient == "bob", received.isContentMessage { await captured.hold(received) }
            return received
        }
        var holder: UUID?
        for index in 0..<count {
            holder = try await sendAndAwaitInbound(
                from: pair.alice, to: "bob", on: pair.bob, text: "initial chain \(index)").winningLaneId
        }
        pair.aliceTransport.transformOutgoing = nil
        return (try #require(holder), await captured.take())
    }

    /// Bob archives the lane alice is sending on and holds a fresh state-less row
    /// toward her: a remint on his side, as the child's at 02:10:03Z. Returns the
    /// archived row.
    private func archiveBobsLaneBehindABlank(_ pair: ConnectedPair) async throws -> UUID {
        let bobRow = try #require(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).first)
        _ = try await pair.bob.demoteActiveSessionIdentityToInactive(try await identity(on: pair.bob, id: bobRow.id))
        _ = try await pair.bob.resetSessionIdentityForFreshSession(
            secretName: "alice",
            deviceId: pair.aliceDeviceId,
            sendOneTimeIdentities: false,
            reason: "test",
            retiring: .none)
        return bobRow.id
    }

    @Test("a state-less preferred row waits for the archived row that holds the frame's epoch")
    func stateLessPreferredRowYieldsToTheArchivedHolder() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let lane = try await openInitialChain(pair, frames: 2)

        // Master 12:43:52Z: a laneReset archived the row holding frames 0-8 and left a
        // lone state-less row, which every later frame reached first as preferred.
        _ = try await pair.bob.demoteActiveSessionIdentityToInactive(try await identity(on: pair.bob, id: lane.holder))
        _ = try await pair.bob.resetSessionIdentityForFreshSession(
            secretName: "alice",
            deviceId: pair.aliceDeviceId,
            sendOneTimeIdentities: false,
            reason: "test",
            retiring: .none)
        let blank = try #require(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).first { !$0.archived })

        let next = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "next on the initial chain")
        #expect(next.pass == .activeFirst && next.winningLaneId == lane.holder, "\(next.candidateOrder)")
        #expect(!next.attemptedLaneIds.contains(blank.id), "the holder decrypted it first: \(next.candidateOrder)")

        // The holder keeps its ratchet, so the lane survives a turn in each direction.
        let reply = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "reply")
        #expect(reply.winningLaneId != nil, "\(reply.candidateOrder)")
        let after = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "after the reply")
        #expect(after.winningLaneId == lane.holder, "\(after.candidateOrder)")
        await pair.finish()
    }

    @Test("a replay of an initial-chain frame adopts no blank after the holder took a turn")
    func replayOfAConsumedInitialChainFrameAfterATurnAdoptsNoBlank() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let lane = try await openInitialChain(pair, frames: 3)
        let chainBefore = try #require(await lanePropsOnBob(pair, id: lane.holder)).ratchetRemotePublicKey

        _ = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "reply")
        let turn = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "alice's next turn")
        #expect(turn.winningLaneId == lane.holder, "\(turn.candidateOrder)")
        let holderProps = try #require(await lanePropsOnBob(pair, id: lane.holder))
        #expect(holderProps.ratchetRemotePublicKey != chainBefore, "the holder moved to a new receiving chain")
        #expect(holderProps.ratchetReceivedMessagesCount < 3, "the per-chain count restarted")

        // A replay the ledger no longer knows, under a fresh envelope id, of a frame the
        // holder consumed. The blank's count now exceeds the holder's restarted count.
        await pair.bob.pruneAcceptedEnvelopes(now: Date().addingTimeInterval(pair.bob.acceptedEnvelopeRetention + 60))
        let replayId = "replay-\(UUID().uuidString)"
        let replayed = lane.frames[2]
        try await pair.bob.receiveMessage(
            message: replayed.message,
            sender: replayed.sender,
            deviceId: replayed.deviceId,
            messageId: replayId,
            logicalMessageId: nil)

        #expect(await pollUntil(timeout: 20) {
            await self.laneSelections(on: pair.bob, sharedId: replayId).contains { $0.pass == .archived || $0.winningLaneId != nil }
        })
        let selections = await laneSelections(on: pair.bob, sharedId: replayId)
        #expect(selections.allSatisfy { $0.winningLaneId == nil }, "\(selections.map(\.candidateOrder))")
        #expect(sink.contains("pqs.recovery.blankBootstrapRefused reason=replayOfConsumedFrame"), "the blank decrypted it and was refused")
        #expect(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).filter { !$0.archived }.map(\.id) == [lane.holder],
                "the established row stays the one active row")
        #expect(try await pair.bob.cache?.fetchMessageIfExists(sharedId: replayId) == nil, "no second chat row")
        await pair.finish()
    }

    @Test("a frame only an archived lane can decrypt is not NACKed before the archive pass has run")
    func archivePassRunsBeforeAnyResendRequest() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let archivedRow = try await archiveBobsLaneBehindABlank(pair)

        // Alice's new keys open a new epoch, so no row holds the frame by its epoch
        // and only the archived row can mirror the re-key. Her rotation's peerRefresh
        // stays home: it would take the archive pass and leave this frame a holder.
        let sharedId = "archived-\(UUID().uuidString)"
        let captured = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            if received.logicalMessageId == sharedId { await captured.hold(received) }
            return received.isContentMessage
        }
        try await pair.alice.rotateCurrentDeviceKeys()
        try await pair.alice.send(recipient: .nickname("bob"), text: "still on the old lane", sharedIdOverride: sharedId)

        #expect(await persisted(pair.bob, sharedId), "the archived lane decrypts the frame in the background pass")
        let frame = try #require(await captured.take().first)
        #expect(await laneSelections(on: pair.bob, sharedId: frame.messageId).contains {
            $0.pass == .archived && $0.winningLaneId == archivedRow
        }, "the archive pass, not the active-first pass, decrypted it")
        #expect(await pair.bobTransport.outOfBandResendRequestCount == 0,
                "no resend request may leave before the archive pass has had its say")
        #expect(await pair.bob.resendRequestSubmissionCount(
            sender: "alice", deviceId: pair.aliceDeviceId, failedMessageId: sharedId) == 0)

        // The active-first miss reached no failure handler: the pass owned the outcome.
        let trail = sink.lines(containing: frame.messageId)
        #expect(trail.contains { $0.contains("pqs.recovery.inboundDeferredToArchivePass") }, "\(trail)")
        #expect(!trail.contains { $0.contains("pqs.decryptFailure") }, "\(trail)")
        await pair.finish()
    }

    @Test("a blank's missingOneTimeKey decides the class after the archive pass, where the blank is gone")
    func blankMissingOneTimeKeyDecidesTheClassAfterTheArchivePass() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        try await pair.bob.createInactiveSessionSnapshot(for: "alice", policy: .archive)

        // Alice's fresh lane cites a one-time key bob has lost, so no row of his and
        // no blank can open the frame, and the archive pass has nothing to find.
        _ = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sendOneTimeIdentities: true,
            reason: "test")
        let held = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob", received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        try await pair.alice.send(recipient: .nickname("bob"), text: "no row opens this")
        #expect(await pollUntil(timeout: 20) { await held.count == 1 })
        let frame = try #require(await held.take().first)
        let header = try BinaryDecoder().decode(RatchetMessage.self, from: try #require(frame.message.signed).data).header
        #expect(try await pair.bob.removeOwnOneTimeKeys(x25519Id: try #require(header.oneTimeKeyId), mlKEMId: nil))
        pair.aliceTransport.continuation?.yield(frame)

        // Child 02:10:08Z: the stateful rows said maxSkipped and the ensured blank said
        // missingOneTimeKey, then the blank went with the active-first job. Its verdict
        // has to survive into the pass, or recovery NACKs a lane that cannot open.
        let sharedId = frame.messageId
        #expect(await pollUntil(timeout: 30) { sink.contains("action=replaceOTKBatchThenPeerRefresh") },
                "\(sink.lines(containing: sharedId))")
        #expect(await pair.bobTransport.outOfBandResendRequestCount == 0, "a resend cannot open this lane")
        #expect(await laneSelections(on: pair.bob, sharedId: sharedId).map(\.pass) == [.activeFirst, .archived])

        // The pass's rollback line shows both passes' verdicts, each lane once.
        let rollbacks = sink.lines(containing: "pqs.recovery.laneRolledBack")
        #expect(rollbacks.count == 2, "\(rollbacks)")
        let merged = try #require(rollbacks.last)
        #expect(merged.contains("ensured:"), "\(merged)")
        #expect(merged.components(separatedBy: "preferred:").count == 2, "\(merged)")

        // The active-first miss reached no failure handler: the deferral comes first
        // and the only failure outcome the frame gets is the archive pass's.
        let trail = sink.lines(containing: sharedId)
        let deferred = try #require(trail.firstIndex { $0.contains("pqs.recovery.inboundDeferredToArchivePass") }, "\(trail)")
        let failures = trail.indices.filter { trail[$0].contains("pqs.decryptFailure") }
        #expect(failures.count == 1, "\(trail)")
        #expect(failures.allSatisfy { deferred < $0 }, "\(trail)")
        await pair.finish()
    }

    @Test("a frame on the holder's lane keeps the holder's class when another row is preferred, and asks one resend after the pass")
    func frameOnHoldersLaneKeepsTheHoldersClassWhenAnotherRowIsPreferred() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let lane = try await openInitialChain(pair, frames: 2)
        let frame = lane.frames[1]
        let header = try BinaryDecoder().decode(RatchetMessage.self, from: try #require(frame.message.signed).data).header
        #expect(try await pair.bob.removeOwnOneTimeKeys(x25519Id: try #require(header.oneTimeKeyId), mlKEMId: nil))

        // Master 23:20:46Z: the row for a fresh lane has just become preferred, and the
        // frames still arriving belong to the row it archived.
        let fresh = try await openInitialChain(pair, frames: 1)
        #expect(fresh.holder != lane.holder)
        pair.aliceTransport.shouldDeliver = { received in
            !(received.recipient == "bob" && received.isContentMessage)
        }

        // A replay the ledger no longer knows, which the holder rejects.
        await pair.bob.pruneAcceptedEnvelopes(now: Date().addingTimeInterval(pair.bob.acceptedEnvelopeRetention + 60))
        let replayId = "replay-\(UUID().uuidString)"
        try await pair.bob.receiveMessage(
            message: frame.message,
            sender: frame.sender,
            deviceId: frame.deviceId,
            messageId: replayId,
            logicalMessageId: nil)

        #expect(await pollUntil(timeout: 30) { await pair.bobTransport.outOfBandResendRequestCount > 0 },
                "the failed archive pass asks the sender")
        #expect(await pair.bobTransport.outOfBandResendRequestCount == 1)
        #expect(await pair.bob.resendRequestSubmissionCount(
            sender: "alice", deviceId: pair.aliceDeviceId, failedMessageId: replayId) == 1)
        let selections = await laneSelections(on: pair.bob, sharedId: replayId)
        #expect(selections.map(\.pass) == [.activeFirst, .archived], "\(selections.map(\.candidateOrder))")

        // The holder's word stands over the blank's missingOneTimeKey.
        let rollback = try #require(sink.lines(containing: "pqs.recovery.laneRolledBack").last)
        #expect(rollback.contains("ensured:") && rollback.contains("missingOneTimeKey"), "\(rollback)")
        let failures = sink.lines(containing: "pqs.decryptFailure").filter { $0.contains(replayId) }
        #expect(failures.count == 1 && failures[0].contains("failureClass=ratchet.maxSkippedHeadersExceeded"), "\(failures) \(rollback)")
        await pair.finish()
    }

    @Test("a frame dropped at the ledger takes its pending archive pass and evidence with it")
    func frameDroppedAtTheLedgerClearsItsArchivePass() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let frame = try await openInitialChain(pair, frames: 1).frames[0]

        // Another copy was accepted while the pass for this one sat queued.
        await pair.bob.messagePipeline.queueArchivePass(ArchivedInboundFallbackToken(
            senderSecretName: "alice",
            senderDeviceId: pair.aliceDeviceId,
            envelopeMessageId: frame.messageId,
            fingerprint: try #require(frame.message.signed).data))
        pair.aliceTransport.continuation?.yield(frame)

        #expect(await pollUntil(timeout: 20) { sink.contains("pqs.recovery.redeliveryDropped reason=alreadyAccepted") })
        #expect(await pair.bob.messagePipeline.archivedInboundFallbackPasses.isEmpty)
        await pair.finish()
    }

    @Test("a second copy of a deferred frame becomes the pass and the queued job finds it accepted")
    func crashBetweenEnqueueAndDeleteAcceptsOnce() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let archivedRow = try await archiveBobsLaneBehindABlank(pair)

        // The first frame of alice's rotation: no row holds its epoch, so only the
        // archive pass can decrypt it.
        let held = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob" else { return true }
            await held.hold(received)
            return false
        }
        try await pair.alice.rotateCurrentDeviceKeys()
        #expect(await pollUntil(timeout: 20) { await held.count > 0 })
        let frame = try #require(await held.take().first)

        // A crash between the pass's enqueue and the original job's delete leaves two
        // copies of the job, and a relaunch runs both.
        pair.aliceTransport.continuation?.yield(frame)
        pair.aliceTransport.continuation?.yield(frame)

        #expect(await pollUntil(timeout: 20) { sink.contains("pqs.recovery.redeliveryDropped reason=alreadyAccepted") },
                "whichever job runs after the pass finds the frame accepted")
        let selections = await laneSelections(on: pair.bob, sharedId: frame.messageId)
        #expect(selections.map(\.pass) == [.activeFirst, .archived], "\(selections.map(\.candidateOrder))")
        #expect(selections.last?.winningLaneId == archivedRow)
        #expect(sink.lines(containing: "pqs.recovery.envelopeAccepted").filter { $0.contains(frame.messageId) }.count == 1)
        #expect(await pair.bobTransport.outOfBandResendRequestCount == 0, "nothing to ask the sender for")
        await pair.finish()
    }

    @Test("an initiating frame opens its lane even when the sender's first frame never arrived")
    func midChainInitiatingFrameOpensTheLane() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        // Alice starts a fresh lane toward bob (her remint); bob still holds the
        // old stateful lane. Her first frame on the new lane is lost in transit.
        _ = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sendOneTimeIdentities: true,
            reason: "test")
        let held = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob", received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        let lost = "lost-first-\(UUID().uuidString)"
        let second = "second-\(UUID().uuidString)"
        try await pair.alice.send(recipient: .nickname("bob"), text: "first, lost", sharedIdOverride: lost)
        try await pair.alice.send(recipient: .nickname("bob"), text: "second, arrives", sharedIdOverride: second)
        #expect(await pollUntil(timeout: 20) { await held.count == 2 })
        pair.aliceTransport.shouldDeliver = nil
        let frames = await held.take()
        pair.aliceTransport.continuation?.yield(frames[1])

        #expect(await persisted(pair.bob, second),
                "bob's blank decrypted this frame from its header; the plaintext must reach the user, not be refused as mid-session")
        #expect(await pair.bobTransport.outOfBandResendRequestCount == 0, "nothing to ask the sender for")
        await pair.finish()
    }

    @Test("a re-encrypted copy of content this device already holds settles the resend requests pending for it")
    func duplicateOfPersistedContentSettlesPendingResend() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        let sharedId = "held-\(UUID().uuidString)"
        try await pair.alice.send(recipient: .nickname("bob"), text: "content", sharedIdOverride: sharedId)
        #expect(await persisted(pair.bob, sharedId))

        // A host re-arm (a relaunch with a stale placeholder ledger) left a NACK
        // pending for content bob already has, as the master's did for C653BE44.
        await pair.bob.deferPeerResendUntilReestablished(
            sender: "alice",
            deviceId: pair.aliceDeviceId,
            failedMessageId: sharedId,
            failureClass: "hostRearm",
            notifyDelegate: false)
        #expect(await pair.bob.hasPendingResendAfterReestablishment(
            sender: "alice", deviceId: pair.aliceDeviceId, failedMessageId: sharedId))

        // The sender answers with a new frame for the same logical id.
        try await pair.alice.send(recipient: .nickname("bob"), text: "content", sharedIdOverride: sharedId)
        #expect(await pollUntil(timeout: 20) {
            await !pair.bob.hasPendingResendAfterReestablishment(
                sender: "alice", deviceId: pair.aliceDeviceId, failedMessageId: sharedId)
        }, "the copy is held content and settles the pending resend")
        #expect(await pair.bobStore.getAllMessages().filter { $0.sharedId == sharedId }.count == 1)
        #expect(sink.lines(containing: "pqs.recovery.duplicateInboundPersistSkipped").filter { $0.contains(sharedId) }.count == 1,
                "the copy decrypted before held content decided")
        await pair.finish()
    }

    @Test("a same-bytes redelivery under a fresh envelope id leaves the pending resend for the drain")
    func sameBytesRedeliveryLeavesThePendingResendForTheDrain() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        let sharedId = "accepted-\(UUID().uuidString)"
        let captured = HeldFrames()
        pair.aliceTransport.transformOutgoing = { received in
            if received.logicalMessageId == sharedId { await captured.hold(received) }
            return received
        }
        try await pair.alice.send(recipient: .nickname("bob"), text: "content", sharedIdOverride: sharedId)
        #expect(await persisted(pair.bob, sharedId))
        pair.aliceTransport.transformOutgoing = nil
        let original = try #require(await captured.take().first)
        await pair.bob.deferPeerResendUntilReestablished(
            sender: "alice",
            deviceId: pair.aliceDeviceId,
            failedMessageId: sharedId,
            failureClass: "hostRearm",
            notifyDelegate: false)

        // The ledger knows these bytes. It proves nothing about the row they name: the
        // child's false `recovered` came from a placeholder with an accepted record.
        let redeliveredId = UUID().uuidString
        pair.aliceTransport.continuation?.yield(ReceivedMessage(
            message: original.message,
            sender: original.sender,
            recipient: original.recipient,
            deviceId: original.deviceId,
            recipientDeviceId: original.recipientDeviceId,
            messageId: redeliveredId,
            logicalMessageId: sharedId,
            transportEvent: original.transportEvent))
        #expect(await pollUntil(timeout: 20) {
            sink.lines(containing: "pqs.recovery.redeliveryDropped reason=alreadyAccepted").contains { $0.contains(redeliveredId) }
        })
        #expect(await pair.bob.hasPendingResendAfterReestablishment(
            sender: "alice", deviceId: pair.aliceDeviceId, failedMessageId: sharedId))
        await pair.finish()
    }

    @Test("a placeholder a read receipt moved to .read is healed by the resend")
    func placeholderMovedToReadIsHealedByTheResend() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        // Child 02:11:09Z: 8B2FF9BC's placeholder had taken an own-device read, so the
        // guard read it as content and dropped the replay before it could decrypt.
        let sharedId = "placeholder-\(UUID().uuidString)"
        try await seedChatRowOnBob(
            pair, sharedId: sharedId, text: "", deliveryState: .read,
            transportInfo: SessionDelegate.recoveryPlaceholderMarker)
        try await pair.alice.send(recipient: .nickname("bob"), text: "the content", sharedIdOverride: sharedId)

        #expect(await pollUntil(timeout: 20) { await self.chatRowOnBob(pair, sharedId)?.message.text == "the content" })
        #expect(await chatRowOnBob(pair, sharedId)?.deliveryState == .received)
        #expect(await pair.bobStore.getAllMessages().filter { $0.sharedId == sharedId }.count == 1)
        await pair.finish()
    }

    @Test("a content row in .failed is not replaced by a redelivered copy")
    func contentRowInFailedIsNotReplaced() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        let sharedId = "content-\(UUID().uuidString)"
        try await seedChatRowOnBob(pair, sharedId: sharedId, text: "the content", deliveryState: .failed("peer"))
        try await pair.alice.send(recipient: .nickname("bob"), text: "another body", sharedIdOverride: sharedId)

        #expect(await pollUntil(timeout: 20) {
            sink.lines(containing: "pqs.recovery.envelopeAccepted").contains { $0.contains(sharedId) }
        })
        let row = await chatRowOnBob(pair, sharedId)
        #expect(row?.message.text == "the content")
        #expect(row?.deliveryState == .failed("peer"))
        await pair.finish()
    }

    @Test("a resend that opens a re-minted lane bootstraps it when the content is held")
    func resendOpeningARemintedLaneBootstrapsItWhenContentIsHeld() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let established = try #require(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).first { !$0.archived })

        let sharedId = "held-\(UUID().uuidString)"
        try await pair.alice.send(recipient: .nickname("bob"), text: "content", sharedIdOverride: sharedId)
        #expect(await persisted(pair.bob, sharedId))

        // Master 23:49:49Z: the sender's resend was the first frame on her new lane, 3A834CBE.
        _ = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sendOneTimeIdentities: true,
            reason: "test")
        try await pair.alice.send(recipient: .nickname("bob"), text: "content", sharedIdOverride: sharedId)
        #expect(await pollUntil(timeout: 20) {
            sink.lines(containing: "pqs.recovery.envelopeAccepted").filter { $0.contains(sharedId) }.count == 2
        }, "the resend decrypted and was accepted")
        let active = try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).filter { !$0.archived }.map(\.id)
        #expect(active.count == 1 && active != [established.id], "the state-less row the resend bootstrapped is the lane: \(active)")

        let next = "next-\(UUID().uuidString)"
        try await pair.alice.send(recipient: .nickname("bob"), text: "next on the new lane", sharedIdOverride: next)
        #expect(await persisted(pair.bob, next))
        #expect(await lanePropsOnBob(pair, id: try #require(active.first))?.state?.skippedHeaderMessages.count == 0)
        #expect(await pair.bobStore.getAllMessages().filter { $0.sharedId == sharedId }.count == 1)
        #expect(await pair.bobTransport.outOfBandResendRequestCount == 0)
        await pair.finish()
    }

    @Test("resends of held content leave no header gap on the lane")
    func resendsOfHeldContentLeaveNoHeaderGap() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        // Master 12:43:56Z: frames 23 and 24 were resends of held content. Dropped
        // before the ratchet, they left the gap that killed 2824A981.
        for index in 23...24 {
            let sharedId = "frame-\(index)-\(UUID().uuidString)"
            try await seedChatRowOnBob(pair, sharedId: sharedId, text: "held", deliveryState: .received)
            try await pair.alice.send(recipient: .nickname("bob"), text: "held", sharedIdOverride: sharedId)
        }
        let next = "frame-25-\(UUID().uuidString)"
        try await pair.alice.send(recipient: .nickname("bob"), text: "the next frame", sharedIdOverride: next)
        #expect(await persisted(pair.bob, next))

        let active = try #require(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).first { !$0.archived })
        #expect(await lanePropsOnBob(pair, id: active.id)?.state?.skippedHeaderMessages.count == 0)
        await pair.finish()
    }

    @Test("a held copy that fails signature verification is not swallowed as a duplicate")
    func heldCopyFailingSignatureVerificationIsNotSwallowed() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        let sharedId = "held-\(UUID().uuidString)"
        try await seedChatRowOnBob(pair, sharedId: sharedId, text: "the content", deliveryState: .received)
        let forged = HeldFrames()
        pair.aliceTransport.transformOutgoing = { received in
            guard received.logicalMessageId == sharedId, let signed = received.message.signed else { return received }
            let frame = ReceivedMessage(
                message: try SignedRatchetMessage(
                    message: try BinaryDecoder().decode(RatchetMessage.self, from: signed.data),
                    signingPrivateKey: Curve25519.Signing.PrivateKey().rawRepresentation),
                sender: received.sender,
                recipient: received.recipient,
                deviceId: received.deviceId,
                recipientDeviceId: received.recipientDeviceId,
                messageId: received.messageId,
                logicalMessageId: received.logicalMessageId,
                transportEvent: received.transportEvent)
            await forged.hold(frame)
            return frame
        }
        try await pair.alice.send(recipient: .nickname("bob"), text: "another body", sharedIdOverride: sharedId)

        #expect(await pollUntil(timeout: 20) { await pair.bobTransport.outOfBandResendRequestCount > 0 },
                "the signature failure takes its own path")
        pair.aliceTransport.transformOutgoing = nil
        let frame = try #require(await forged.take().first)
        #expect(await !accepted(pair, envelope: frame.messageId), "an unverified frame never reaches the ledger")
        #expect(await chatRowOnBob(pair, sharedId)?.message.text == "the content")
        await pair.finish()
    }

    @Test("a held copy on an archived lane leaves the active lane unchanged")
    func heldCopyOnAnArchivedLaneLeavesTheActiveLaneUnchanged() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let archived = try #require(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).first { !$0.archived })

        // A copy held back on the lane bob is about to leave.
        let sharedId = "held-\(UUID().uuidString)"
        let delayed = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.logicalMessageId == sharedId else { return true }
            await delayed.hold(received)
            return false
        }
        try await pair.alice.send(recipient: .nickname("bob"), text: "a stale copy", sharedIdOverride: sharedId)
        #expect(await pollUntil(timeout: 20) { await delayed.count == 1 })
        pair.aliceTransport.shouldDeliver = nil
        let frame = try #require(await delayed.take().first)
        try await seedChatRowOnBob(pair, sharedId: sharedId, text: "the content", deliveryState: .received)

        // The sender moved to a new lane, and bob with her.
        let fresh = try await openInitialChain(pair, frames: 1)
        #expect(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).filter { !$0.archived }.map(\.id) == [fresh.holder])

        pair.aliceTransport.continuation?.yield(frame)

        #expect(await pollUntil(timeout: 20) {
            sink.lines(containing: "pqs.recovery.envelopeAccepted").contains { $0.contains(sharedId) }
        })
        let selections = await laneSelections(on: pair.bob, sharedId: frame.messageId)
        #expect(selections.last?.winningLaneId == archived.id, "\(selections.map(\.candidateOrder))")
        #expect(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).filter { !$0.archived }.map(\.id) == [fresh.holder],
                "a stale copy must not take the lane the sender moved to")
        await pair.finish()
    }

    @Test("a held copy no lane can open waits for the archive pass, then drops without a resend request")
    func heldCopyNoLaneCanOpenDropsAfterTheArchivePass() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let frame = try await openInitialChain(pair, frames: 2).frames[1]
        try await pair.bob.createInactiveSessionSnapshot(for: "alice", policy: .archive)

        let replayId = try await replayConsumedFrame(pair, frame, logical: try #require(frame.logicalMessageId))

        #expect(await pollUntil(timeout: 30) { sink.contains("pqs.recovery.redeliveryDropped reason=alreadyPersisted") })
        let selections = await laneSelections(on: pair.bob, sharedId: replayId)
        #expect(selections.map(\.pass) == [.activeFirst, .archived], "\(selections.map(\.candidateOrder))")
        #expect(await accepted(pair, envelope: replayId))
        #expect(await pair.bobTransport.outOfBandResendRequestCount == 0, "the content is here")
        await pair.finish()
    }

    @Test("with no delegate a row is not known to be content, so a failed copy is not dropped")
    func failedCopyWithNoDelegateIsNotDropped() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let frame = try await openInitialChain(pair, frames: 2).frames[1]
        await pair.bob.clearSessionDelegate()

        let replayId = try await replayConsumedFrame(pair, frame, logical: try #require(frame.logicalMessageId))

        #expect(await pollUntil(timeout: 30) {
            sink.lines(containing: "pqs.decryptFailure").contains { $0.contains(replayId) }
        }, "the frame took the failure path")
        #expect(await !accepted(pair, envelope: replayId))
        #expect(!sink.contains("pqs.recovery.redeliveryDropped reason=alreadyPersisted"))
        await pair.finish()
    }

    @Test("a copy that cannot decrypt leaves a placeholder's resend request and accepts nothing")
    func undecryptableCopyLeavesAPlaceholdersResendRequest() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let frame = try await openInitialChain(pair, frames: 2).frames[1]

        let sharedId = "placeholder-\(UUID().uuidString)"
        try await seedChatRowOnBob(
            pair, sharedId: sharedId, text: "", deliveryState: .read,
            transportInfo: SessionDelegate.recoveryPlaceholderMarker)
        await pair.bob.deferPeerResendUntilReestablished(
            sender: "alice",
            deviceId: pair.aliceDeviceId,
            failedMessageId: sharedId,
            failureClass: "hostRearm",
            notifyDelegate: false)

        // A2D7E1C8 and 6AB795EB on the child: replays failing on the lane they cite.
        let replayId = try await replayConsumedFrame(pair, frame, logical: sharedId)

        #expect(await pollUntil(timeout: 30) { await pair.bobTransport.outOfBandResendRequestCount > 0 },
                "the failed copy asks the sender")
        #expect(await !accepted(pair, envelope: replayId))
        #expect(await pair.bob.hasPendingResendAfterReestablishment(
            sender: "alice", deviceId: pair.aliceDeviceId, failedMessageId: sharedId))
        #expect(await chatRowOnBob(pair, sharedId) != nil)
        await pair.finish()
    }
}

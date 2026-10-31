//
//  LaneRetirementTests.swift
//  post-quantum-solace
//
//  Only a decrypt archives a lane the peer has answered: a sibling's decrypt, or a
//  NACK of a replay on that exact row. A mint retires the rows nobody answered and
//  leaves the rest carrying traffic (dogfood 2026-10-28: 02:10:03Z archived 9900FA06
//  mid-burst, 02:10:05Z left 8B2FF9BC to ride unanswered 210AC674).
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    private func settledPair() async throws -> (pair: ConnectedPair, answered: LaneRow) {
        let pair = try await connectedPair()
        try await settleLanes(pair)
        let answered = try #require(
            await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId).first)
        return (pair, answered)
    }

    private func activeIds(_ pair: ConnectedPair) async throws -> Set<UUID> {
        let rows = try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId)
        return Set(rows.filter { !$0.archived }.map(\.id))
    }

    /// Bob sees none of Alice's content from here on, so he stays on the lane he knows.
    private func holdAliceContent(_ pair: ConnectedPair) -> HeldFrames {
        let held = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        return held
    }

    /// An initiating row beside the answered lane, as a recovery mint leaves it: one
    /// frame out, nothing back.
    private func mintUnansweredRow(_ pair: ConnectedPair) async throws -> SessionIdentity {
        let row = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            reason: "orphanResend",
            retiring: .none)
        try await pair.alice.messagePipeline.handleWriteMessage(
            outboundTask: OutboundTaskMessage(
                message: CryptoMessage(
                    text: "on the new row",
                    metadata: .init(),
                    recipient: .nickname("bob"),
                    sentDate: Date(),
                    destructionTime: nil),
                recipientIdentity: row,
                localId: UUID(),
                sharedId: UUID().uuidString,
                isPersistedOutbound: false),
            session: pair.alice)
        return row
    }

    /// Alice's replay on `lane` is NACKed on its own envelope: the one proof a row is
    /// dead. Returns the row she minted to replace it.
    private func nackReplay(on lane: UUID, _ pair: ConnectedPair) async throws -> UUID {
        let sharedId = "lane-retirement-\(UUID().uuidString)"
        try await pair.alice.send(
            recipient: .nickname("bob"),
            text: "cited by the NACK",
            sharedIdOverride: sharedId)
        await pair.alice.waitForOutboundJobDrain()
        let replayEnvelopeId = UUID().uuidString
        await pair.alice.recordOutboundDeviceSend(
            sharedId: sharedId,
            recipientSecretName: "bob",
            recipientDeviceId: pair.bobDeviceId,
            sessionIdentityId: lane,
            envelopeMessageId: replayEnvelopeId,
            resendAttempt: 1)
        _ = try await pair.alice.handleOutOfBandResendRequest(
            from: "bob",
            deviceId: pair.bobDeviceId,
            failedSharedMessageIds: [replayEnvelopeId])
        await pair.alice.waitForOutboundJobDrain()
        let replay = try #require(await pair.alice.outboundDeviceSendRecord(
            sharedId: sharedId,
            recipientDeviceId: pair.bobDeviceId))
        return replay.sessionIdentityId
    }

    /// An unanswered recovery row whose replay is NACKed: the escape remint.
    private func escapeMint(_ pair: ConnectedPair) async throws -> UUID {
        let recovery = try await mintUnansweredRow(pair)
        await pair.alice.markOrphanResendInitiatingSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sessionId: recovery.id)
        return try await nackReplay(on: recovery.id, pair)
    }

    /// The row a general send rides.
    private func sendContent(_ pair: ConnectedPair) async throws -> UUID {
        let sharedId = "lane-retirement-content-\(UUID().uuidString)"
        try await pair.alice.send(
            recipient: .nickname("bob"),
            text: "content",
            sharedIdOverride: sharedId)
        await pair.alice.waitForOutboundJobDrain()
        let record = try #require(await pair.alice.outboundDeviceSendRecord(
            sharedId: sharedId,
            recipientDeviceId: pair.bobDeviceId))
        return record.sessionIdentityId
    }

    /// 02:10:03Z: a mint archived 9900FA06, which had just decrypted frames 0-6, so
    /// frame 7 missed first pass and drew a premature NACK.
    @Test("a recovery mint keeps the lane the peer is sending on")
    func recoveryMintKeepsLanePeerIsSendingOn() async throws {
        let (pair, answered) = try await settledPair()
        defer { Task { await shutdownSessions() } }
        _ = holdAliceContent(pair)
        _ = try await escapeMint(pair)

        let stats = try await sendAndAwaitInbound(
            from: pair.bob, to: "alice", on: pair.alice, text: "still on the lane")

        #expect(stats.winningLaneId == answered.id)
        #expect(stats.attempts.map(\.kind) == ["preferred"], "\(stats.attempts)")
        await pair.finish()
    }

    /// 01:41:46Z: `laneReset demotedActive=2` archived 40B58FBC and 9880E02D, both live.
    @Test("two answered rows both survive a mint")
    func twoAnsweredRowsSurviveMint() async throws {
        let (pair, answered) = try await settledPair()
        defer { Task { await shutdownSessions() } }
        _ = holdAliceContent(pair)
        // A second answered row, as a crossing initiation leaves behind.
        let key = try await pair.alice.getDatabaseSymmetricKey()
        let lane = try #require(
            try await pair.alice.cache?.fetchSessionIdentities().first { $0.id == answered.id })
        let props = try #require(await lane.props(symmetricKey: key))
        let twin = try SessionIdentity(id: UUID(), props: props, symmetricKey: key)
        try await pair.alice.cache?.createSessionIdentity(twin)

        let minted = try await escapeMint(pair)

        #expect(try await activeIds(pair) == [answered.id, twin.id, minted])
        await pair.finish()
    }

    @Test("a mint retires an unanswered row")
    func mintRetiresUnansweredRow() async throws {
        let (pair, answered) = try await settledPair()
        defer { Task { await shutdownSessions() } }
        _ = holdAliceContent(pair)
        let unanswered = try await mintUnansweredRow(pair)

        let minted = try await escapeMint(pair)

        #expect(minted != unanswered.id)
        #expect(try await activeIds(pair) == [answered.id, minted])
        await pair.finish()
    }

    /// 02:10:08Z: 8B2FF9BC rode unanswered 210AC674 because the mint had archived every
    /// lane the child had opened.
    @Test("cross-account content stays on the answered lane until the new row is answered")
    func contentStaysOnAnsweredLaneUntilNewRowAnswered() async throws {
        let (pair, answered) = try await settledPair()
        defer { Task { await shutdownSessions() } }
        let held = holdAliceContent(pair)
        let minted = try await escapeMint(pair)
        let replay = try #require(await held.take().last)

        #expect(try await sendContent(pair) == answered.id)

        let bobAccepted = await acceptedCount(pair.bob)
        pair.aliceTransport.continuation?.yield(replay)
        #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.bob) > bobAccepted })
        let stats = try await sendAndAwaitInbound(
            from: pair.bob, to: "alice", on: pair.alice, text: "on the new row")

        #expect(stats.winningLaneId == minted)
        #expect(try await activeIds(pair) == [minted])
        #expect(try await sendContent(pair) == minted)
        await pair.finish()
    }

    /// ACC16F72 was answered and AEAD-failing from 23:25:11Z: nothing but its replay's
    /// own NACK says such a lane is dead, and then it must stop carrying content.
    @Test("a lane its replay proved dead stops carrying content")
    func provenDeadLaneStopsCarryingContent() async throws {
        let (pair, answered) = try await settledPair()
        defer { Task { await shutdownSessions() } }
        _ = holdAliceContent(pair)

        let minted = try await nackReplay(on: answered.id, pair)

        #expect(minted != answered.id)
        #expect(try await activeIds(pair) == [minted])
        #expect(try await sendContent(pair) == minted)
        await pair.finish()
    }

    /// Marks live in memory: a relaunch or the extension sees two rows and no marks,
    /// and the newest row must not take content because of store order.
    @Test("after a relaunch content rides the answered row")
    func contentRidesAnsweredRowAfterRelaunch() async throws {
        let (pair, answered) = try await settledPair()
        defer { Task { await shutdownSessions() } }
        _ = holdAliceContent(pair)
        _ = try await mintUnansweredRow(pair)
        await pair.alice.clearOrphanResendRecoveryState(
            secretName: "bob",
            deviceId: pair.bobDeviceId)
        await pair.alice.messagePipeline.clearPreferredSessionIdentity(
            secretName: "bob",
            deviceId: pair.bobDeviceId)

        #expect(try await sendContent(pair) == answered.id)
        await pair.finish()
    }

    /// 13:48:37Z: the peerRefresh reset healed a recovery row pinned to a dead key. An
    /// answered sibling says nothing about that pin.
    @Test("an unanswered row carrying recovery is reset, keeping the answered lane")
    func unansweredRecoveryRowIsResetKeepingAnsweredLane() async throws {
        let (pair, answered) = try await settledPair()
        defer { Task { await shutdownSessions() } }
        _ = holdAliceContent(pair)
        let recovery = try await mintUnansweredRow(pair)
        await pair.alice.markOrphanResendInitiatingSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sessionId: recovery.id)

        await pair.alice.messagePipeline.resetUnansweredInitiatingLane(
            peerSecretName: "bob",
            peerDeviceId: pair.bobDeviceId,
            trigger: "peerRefreshRequest",
            session: pair.alice)

        let active = try await activeIds(pair)
        #expect(active.contains(answered.id))
        #expect(!active.contains(recovery.id))
        #expect(active.count == 2, "the reset replaces the row: \(active)")
        await pair.finish()
    }

    @Test("an unanswered row carrying nothing is left alone by the reset")
    func idleUnansweredRowIsLeftAloneByReset() async throws {
        let (pair, answered) = try await settledPair()
        defer { Task { await shutdownSessions() } }
        _ = holdAliceContent(pair)
        let idle = try await mintUnansweredRow(pair)
        await pair.alice.clearOrphanResendRecoveryState(
            secretName: "bob",
            deviceId: pair.bobDeviceId)

        await pair.alice.messagePipeline.resetUnansweredInitiatingLane(
            peerSecretName: "bob",
            peerDeviceId: pair.bobDeviceId,
            trigger: "peerRefreshRequest",
            session: pair.alice)

        #expect(try await activeIds(pair) == [answered.id, idle.id])
        await pair.finish()
    }

    @Test("a row the device's keys no longer match retires even when answered")
    func rotatedKeysRetireAnsweredLane() async throws {
        let (pair, answered) = try await settledPair()
        defer { Task { await shutdownSessions() } }
        _ = holdAliceContent(pair)
        let key = try await pair.alice.getDatabaseSymmetricKey()
        let lane = try #require(
            try await pair.alice.cache?.fetchSessionIdentities().first { $0.id == answered.id })
        var props = try #require(await lane.props(symmetricKey: key))
        #expect(props.ratchetReceivedMessagesCount > 0)
        props.longTermPublicKey = Data(repeating: 7, count: props.longTermPublicKey.count)
        try await lane.update(props, symmetricKey: key)
        try await pair.alice.cache?.updateSessionIdentity(lane)

        let minted = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            reason: "orphanResend",
            retiring: .unanswered)

        #expect(try await activeIds(pair) == [minted.id])
        await pair.finish()
    }

    @Test("the same-account force still retires an answered lane")
    func forcedResetRetiresAnsweredLane() async throws {
        let (pair, answered) = try await settledPair()
        defer { Task { await shutdownSessions() } }
        _ = holdAliceContent(pair)

        await pair.alice.messagePipeline.resetUnansweredInitiatingLane(
            peerSecretName: "bob",
            peerDeviceId: pair.bobDeviceId,
            trigger: "missingOneTimeKeyEpisode",
            forceRemintEvenIfAnswered: true,
            session: pair.alice)

        let active = try await activeIds(pair)
        #expect(active.count == 1)
        #expect(!active.contains(answered.id))
        await pair.finish()
    }
}

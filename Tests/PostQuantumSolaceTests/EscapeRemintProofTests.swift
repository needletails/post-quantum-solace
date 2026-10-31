//
//  EscapeRemintProofTests.swift
//  post-quantum-solace
//
//  A NACK says the requester could not decrypt a frame, not that the lane is dead.
//  Only a NACK of a replay's own envelope proves that. Without it, servicing replays
//  on a lane the requester has answered: no mint, no one-time key, no archived row
//  (dogfood 2026-10-28: all six escape remints in the window answered a first NACK).
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    private struct SentOnAnsweredLane {
        let pair: ConnectedPair
        let sink: RecordingAuditSink
        let lane: LaneRow
        let sharedId: String

        var keyFetches: Int { sink.lines(containing: "consumedOTK=true").count }

        func record(of id: String? = nil) async throws -> OutboundDeviceSendRecord {
            try #require(await pair.alice.outboundDeviceSendRecord(
                sharedId: id ?? sharedId,
                recipientDeviceId: pair.bobDeviceId))
        }

        /// Alice answers Bob's request for `citedIds` and finishes the replay.
        func nack(_ citedIds: String...) async throws -> PQSSession.OutOfBandResendResult {
            let result = try await pair.alice.handleOutOfBandResendRequest(
                from: "bob",
                deviceId: pair.bobDeviceId,
                failedSharedMessageIds: citedIds)
            await pair.alice.waitForOutboundJobDrain()
            return result
        }

        /// Names `lane` as the recovery lane, holding a replay of this message.
        func seedReplayOnRecoveryLane() async -> String {
            let replayEnvelopeId = UUID().uuidString
            await pair.alice.markOrphanResendInitiatingSession(
                secretName: "bob",
                deviceId: pair.bobDeviceId,
                sessionId: lane.id)
            await pair.alice.recordOutboundDeviceSend(
                sharedId: sharedId,
                recipientSecretName: "bob",
                recipientDeviceId: pair.bobDeviceId,
                sessionIdentityId: lane.id,
                envelopeMessageId: replayEnvelopeId,
                resendAttempt: 1)
            return replayEnvelopeId
        }
    }

    /// A settled pair with one frame from Alice on the lane Bob has answered.
    private func sendOnAnsweredLane(persisted: Bool = true) async throws -> SentOnAnsweredLane {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(aliceAuditSink: sink)
        try await settleLanes(pair)
        let sharedId = "escape-proof-\(UUID().uuidString)"
        try await pair.alice.send(
            recipient: .nickname("bob"),
            text: "on the answered lane",
            sharedIdOverride: sharedId,
            shouldPersistOverride: persisted ? nil : false)
        await pair.alice.waitForOutboundJobDrain()
        let lane = try #require(
            await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId).first)
        return SentOnAnsweredLane(pair: pair, sink: sink, lane: lane, sharedId: sharedId)
    }

    /// Alice's rows for Bob that are still active.
    private func activeRowIds(_ sent: SentOnAnsweredLane) async throws -> Set<UUID> {
        let rows = try await rows(on: sent.pair.alice, peer: "bob", deviceId: sent.pair.bobDeviceId)
        return Set(rows.filter { !$0.archived }.map(\.id))
    }

    private func expectNoMint(_ sent: SentOnAnsweredLane, keyFetchesBefore: Int) async throws {
        expectSameLane(
            try await rows(on: sent.pair.alice, peer: "bob", deviceId: sent.pair.bobDeviceId),
            sent.lane,
            "after the NACK")
        #expect(sent.keyFetches == keyFetchesBefore)
        #expect(!sent.sink.contains("pqs.recovery.orphanResendRemintAfterProveFail"))
    }

    /// 23:49:47Z: the master's ledger re-arm cited C653BE44 after replay 1D093E25 had
    /// landed, and the child reminted 3A834CBE. The logical id resolves to the live
    /// replay record, but the requester never named that replay.
    @Test("a logical-id citation after a replay mints nothing")
    func logicalCitationAfterReplayMintsNothing() async throws {
        let sent = try await sendOnAnsweredLane()
        defer { Task { await shutdownSessions() } }
        _ = await sent.seedReplayOnRecoveryLane()
        let keyFetchesBefore = sent.keyFetches

        let result = try await sent.nack(sent.sharedId)

        #expect(result.queuedIds == [sent.sharedId])
        try await expectNoMint(sent, keyFetchesBefore: keyFetchesBefore)
        let replay = try await sent.record()
        #expect(replay.sessionIdentityId == sent.lane.id)
        #expect(replay.resendAttempt == 2)
        await sent.pair.finish()
    }

    /// 02:11:07Z: a wave cited one message by more than one id. The logical id resolves
    /// to the live replay, but only that replay's own envelope is proof, and this wave
    /// names the original and an older replay.
    @Test("a wave that names no live replay mints nothing")
    func waveNamingNoLiveReplayMintsNothing() async throws {
        let sent = try await sendOnAnsweredLane()
        defer { Task { await shutdownSessions() } }
        let original = try await sent.record()
        let olderReplayId = await sent.seedReplayOnRecoveryLane()
        _ = await sent.seedReplayOnRecoveryLane()
        let keyFetchesBefore = sent.keyFetches

        let result = try await sent.nack(original.envelopeMessageId, olderReplayId, sent.sharedId)

        #expect(result.queuedIds == [original.envelopeMessageId, olderReplayId, sent.sharedId])
        try await expectNoMint(sent, keyFetchesBefore: keyFetchesBefore)
        await sent.pair.finish()
    }

    /// 02:10:03Z: a relaunch had wiped the recovery row, so the child's first NACK of
    /// an ordinary send fell through to `mintFresh` (90D1C7FF) and archived 9900FA06,
    /// which had just decrypted frames 0-6.
    @Test("a first NACK with no recovery row and an answered lane mints nothing")
    func firstNackOnAnsweredLaneMintsNothing() async throws {
        let sent = try await sendOnAnsweredLane()
        defer { Task { await shutdownSessions() } }
        let original = try await sent.record()
        let keyFetchesBefore = sent.keyFetches

        let result = try await sent.nack(original.envelopeMessageId)

        #expect(result.queuedIds == [original.envelopeMessageId])
        try await expectNoMint(sent, keyFetchesBefore: keyFetchesBefore)
        let replay = try await sent.record()
        #expect(replay.sessionIdentityId == sent.lane.id)
        #expect(replay.resendAttempt == 1)
        await sent.pair.finish()
    }

    /// 02:11:43Z: EF9AEC4D was an ordinary send on the unanswered recovery row while
    /// an answered sibling was live. Any frame on the mark used to count as a replay,
    /// so its first NACK looked like a settled prove-fail and reminted 7FCD5EC9.
    @Test("a first NACK on an unanswered recovery row replays on the answered sibling")
    func firstNackOnUnansweredRecoveryRowReplaysOnAnsweredSibling() async throws {
        let sent = try await sendOnAnsweredLane()
        defer { Task { await shutdownSessions() } }
        let alice = sent.pair.alice
        let bobDeviceId = sent.pair.bobDeviceId
        sent.pair.aliceTransport.shouldDeliver = { _ in false }

        let recovery = try await alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: bobDeviceId,
            reason: "orphanResend",
            retiring: .none)
        await alice.markOrphanResendInitiatingSession(
            secretName: "bob",
            deviceId: bobDeviceId,
            sessionId: recovery.id)
        try await alice.messagePipeline.handleWriteMessage(
            outboundTask: OutboundTaskMessage(
                message: CryptoMessage(
                    text: "general traffic on the recovery row",
                    metadata: .init(),
                    recipient: .nickname("bob"),
                    sentDate: Date(),
                    destructionTime: nil),
                recipientIdentity: recovery,
                localId: UUID(),
                sharedId: sent.sharedId,
                isPersistedOutbound: false),
            session: alice)

        let general = try await sent.record()
        #expect(general.sessionIdentityId == recovery.id)
        #expect(general.resendAttempt == 0, "a frame on the recovery row is not a replay")
        let rowsBefore = try await rows(on: alice, peer: "bob", deviceId: bobDeviceId)
        let keyFetchesBefore = sent.keyFetches

        let result = try await sent.nack(general.envelopeMessageId)

        #expect(result.queuedIds == [general.envelopeMessageId])
        let replay = try await sent.record()
        #expect(replay.sessionIdentityId == sent.lane.id)
        #expect(replay.resendAttempt == 1)
        let rowsAfter = try await rows(on: alice, peer: "bob", deviceId: bobDeviceId)
        #expect(rowsAfter.map(\.id) == rowsBefore.map(\.id))
        #expect(rowsAfter.allSatisfy { !$0.archived })
        #expect(sent.keyFetches == keyFetchesBefore)
        await sent.pair.finish()
    }

    /// The heal the first NACK gives up: an answered lane that really died costs one
    /// more round trip, then the replay's own NACK is the proof.
    @Test("a dead answered lane mints after the replay's envelope is NACKed")
    func deadAnsweredLaneMintsAfterReplayEnvelopeIsNacked() async throws {
        let sent = try await sendOnAnsweredLane()
        defer { Task { await shutdownSessions() } }
        let original = try await sent.record()
        let keyFetchesBefore = sent.keyFetches

        _ = try await sent.nack(original.envelopeMessageId)
        try await expectNoMint(sent, keyFetchesBefore: keyFetchesBefore)
        let replay = try await sent.record()
        #expect(replay.envelopeMessageId != original.envelopeMessageId)

        let result = try await sent.nack(replay.envelopeMessageId)

        #expect(result.queuedIds == [replay.envelopeMessageId])
        let rowsAfter = try await rows(on: sent.pair.alice, peer: "bob", deviceId: sent.pair.bobDeviceId)
        let minted = try #require(rowsAfter.first { !$0.archived })
        #expect(minted.id != sent.lane.id)
        #expect(rowsAfter.first { $0.id == sent.lane.id }?.archived == true)
        #expect(sent.keyFetches == keyFetchesBefore + 1)
        let healed = try await sent.record()
        #expect(healed.sessionIdentityId == minted.id)
        #expect(healed.resendAttempt == 2)
        await sent.pair.finish()
    }

    /// 01:41:46Z and sunflower 02:10:03Z: two answered rows and no marks, after a relaunch
    /// or in the extension. The write path rebinds a replay to the newest answered row, so
    /// a row left standing after its replay's NACK takes every later replay and nothing
    /// ever mints.
    @Test("a proven answered row leaves, so its sibling and then a mint carry the replay")
    func provenAnsweredRowLeavesForItsSibling() async throws {
        let sent = try await sendOnAnsweredLane()
        defer { Task { await shutdownSessions() } }
        let alice = sent.pair.alice
        sent.pair.aliceTransport.shouldDeliver = { _ in false }
        let key = try await alice.getDatabaseSymmetricKey()
        let lane = try #require(
            try await alice.cache?.fetchSessionIdentities().first { $0.id == sent.lane.id })
        let props = try #require(await lane.props(symmetricKey: key))
        let newest = try SessionIdentity(id: UUID(), props: props, symmetricKey: key)
        try await alice.cache?.createSessionIdentity(newest)
        await alice.messagePipeline.clearPreferredSessionIdentity(
            secretName: "bob",
            deviceId: sent.pair.bobDeviceId)
        let original = try await sent.record()
        let keyFetchesBefore = sent.keyFetches

        _ = try await sent.nack(original.envelopeMessageId)
        let onNewest = try await sent.record()
        #expect(onNewest.sessionIdentityId == newest.id)

        _ = try await sent.nack(onNewest.envelopeMessageId)
        let onSibling = try await sent.record()
        #expect(onSibling.sessionIdentityId == sent.lane.id)
        #expect(try await activeRowIds(sent) == [sent.lane.id])
        #expect(sent.keyFetches == keyFetchesBefore)

        _ = try await sent.nack(onSibling.envelopeMessageId)
        let minted = try await sent.record()
        #expect(minted.sessionIdentityId != sent.lane.id)
        #expect(minted.sessionIdentityId != newest.id)
        #expect(try await activeRowIds(sent) == [minted.sessionIdentityId])
        #expect(sent.keyFetches == keyFetchesBefore + 1)
        await sent.pair.finish()
    }

    /// A requester NACKs each failed frame, so one dead lane's frames arrive as separate
    /// waves. The first proof mints and the rest ride that row, even a proof about the
    /// row it replaced: each mint spends a one-time key and retires a row Bob may be
    /// opening (dogfood C3 / 2FA48892 triple newSessionId thrash).
    @Test("every failed frame of one dead lane rides the one recovery row")
    func deadLaneFramesShareOneRecoveryRow() async throws {
        let sent = try await sendOnAnsweredLane()
        defer { Task { await shutdownSessions() } }
        let alice = sent.pair.alice
        sent.pair.aliceTransport.shouldDeliver = { _ in false }
        var siblingIds: [String] = []
        for _ in 1...3 {
            let siblingId = "escape-proof-\(UUID().uuidString)"
            try await alice.send(
                recipient: .nickname("bob"),
                text: "on the same lane",
                sharedIdOverride: siblingId)
            siblingIds.append(siblingId)
        }
        await alice.waitForOutboundJobDrain()
        let original = try await sent.record()
        _ = try await sent.nack(original.envelopeMessageId)
        let replay = try await sent.record()
        let keyFetchesBefore = sent.keyFetches

        _ = try await sent.nack(replay.envelopeMessageId)
        let recoveryRowId = try await sent.record().sessionIdentityId
        #expect(recoveryRowId != sent.lane.id)
        #expect(sent.keyFetches == keyFetchesBefore + 1)

        let provenOnOldRowId = UUID().uuidString
        await alice.recordOutboundDeviceSend(
            sharedId: siblingIds[2],
            recipientSecretName: "bob",
            recipientDeviceId: sent.pair.bobDeviceId,
            sessionIdentityId: sent.lane.id,
            envelopeMessageId: provenOnOldRowId,
            resendAttempt: 1)
        _ = try await sent.nack(try await sent.record(of: siblingIds[0]).envelopeMessageId)
        _ = try await sent.nack(try await sent.record(of: siblingIds[1]).envelopeMessageId)
        _ = try await sent.nack(provenOnOldRowId)

        for siblingId in siblingIds {
            #expect(try await sent.record(of: siblingId).sessionIdentityId == recoveryRowId)
        }
        #expect(try await activeRowIds(sent) == [recoveryRowId])
        #expect(sent.keyFetches == keyFetchesBefore + 1)
        await sent.pair.finish()
    }

    /// 01:41:46Z: 7FACCE52 had nothing to replay, and the child still reminted
    /// FDEAC737 "for later siblings".
    @Test("a NACK for a frame with no plaintext mints nothing")
    func nackWithNoPlaintextMintsNothing() async throws {
        let sent = try await sendOnAnsweredLane(persisted: false)
        defer { Task { await shutdownSessions() } }
        let replayEnvelopeId = await sent.seedReplayOnRecoveryLane()
        let keyFetchesBefore = sent.keyFetches

        let result = try await sent.nack(replayEnvelopeId)

        #expect(result.queuedIds.isEmpty)
        #expect(result.permanentlyUnavailableIds == [replayEnvelopeId])
        #expect(sent.sink.contains("pqs.recovery.orphanResendOwnerMissingPlaintext"))
        try await expectNoMint(sent, keyFetchesBefore: keyFetchesBefore)
        await sent.pair.finish()
    }
}

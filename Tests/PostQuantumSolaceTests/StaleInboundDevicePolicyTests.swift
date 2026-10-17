//
//  StaleInboundDevicePolicyTests.swift
//  post-quantum-solace
//
//  Mail from a device id the directory no longer lists is dropped.
//  A device still in the memo, or an empty memo, keeps the resend.
//

import Foundation
import Testing
@testable import PQSSession

@Suite("Stale inbound device")
struct StaleInboundDevicePolicyTests {
    @Test("empty verified set does not drop")
    func emptySetKeepsResend() {
        #expect(
            !StaleInboundDevicePolicy.shouldDrop(
                senderDeviceId: UUID(),
                verifiedDeviceIds: [],
                source: .live))
    }

    @Test("member of the verified set does not drop")
    func memberKeepsResend() {
        let device = UUID()
        #expect(
            !StaleInboundDevicePolicy.shouldDrop(
                senderDeviceId: device,
                verifiedDeviceIds: [device, UUID()],
                source: .live))
    }

    @Test("non-member of a live non-empty verified set drops")
    func absentDeviceDrops() {
        #expect(
            StaleInboundDevicePolicy.shouldDrop(
                senderDeviceId: UUID(),
                verifiedDeviceIds: [UUID(), UUID()],
                source: .live))
    }

    @Test("a memo from a possibly cached snapshot never drops")
    func cachedSnapshotNeverDrops() {
        #expect(
            !StaleInboundDevicePolicy.shouldDrop(
                senderDeviceId: UUID(),
                verifiedDeviceIds: [UUID(), UUID()],
                source: .cachedOrUnknown))
    }

    @Test("missing row with a cached-snapshot memo keeps the resend path")
    func missingSessionRowWithCachedMemoDefers() async throws {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let sender = "mm26"
        let newDevice = UUID()
        let envelope = UUID().uuidString
        await session.setVerifiedDeviceIds([UUID(), UUID()], for: sender, source: .cachedOrUnknown)

        await session.resolveInboundMissingSessionRow(
            sender: sender,
            deviceId: newDevice,
            failedMessageId: envelope,
            logicalSharedId: nil)

        #expect(await session.hasPendingResendAfterReestablishment(
            sender: sender, deviceId: newDevice, failedMessageId: envelope))
        #expect(!(await session.isInboundFailureQuarantined(
            sender: sender, deviceId: newDevice, messageId: envelope)))
    }

    @Test("no session row for a device absent from the memo does not NACK")
    func missingSessionRowForReplacedDeviceDoesNotDefer() async throws {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let sender = "mm26"
        let liveA = UUID()
        let liveB = UUID()
        let replaced = UUID()
        let envelope = UUID().uuidString
        await installVerifiedDeviceIds(session, sender: sender, ids: [liveA, liveB])

        await session.resolveInboundMissingSessionRow(
            sender: sender,
            deviceId: replaced,
            failedMessageId: envelope,
            logicalSharedId: nil)

        #expect(!(await session.hasPendingResendAfterReestablishment(
            sender: sender, deviceId: replaced, failedMessageId: envelope)))
        #expect(await session.isInboundFailureQuarantined(
            sender: sender, deviceId: replaced, messageId: envelope))
    }

    @Test("no session row for a device still in the memo still defers a resend")
    func missingSessionRowForVerifiedDeviceDefers() async throws {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let sender = "mm26"
        let live = UUID()
        let envelope = UUID().uuidString
        await installVerifiedDeviceIds(session, sender: sender, ids: [live, UUID()])

        await session.resolveInboundMissingSessionRow(
            sender: sender,
            deviceId: live,
            failedMessageId: envelope,
            logicalSharedId: nil)

        #expect(await session.hasPendingResendAfterReestablishment(
            sender: sender, deviceId: live, failedMessageId: envelope))
        #expect(!(await session.isInboundFailureQuarantined(
            sender: sender, deviceId: live, messageId: envelope)))
    }

    @Test("rearm for a device absent from a non-empty memo does not insert a pending resend")
    func rearmOfReplacedDeviceDoesNotInsert() async throws {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let sender = "nudge"
        let replaced = UUID()
        let envelope = "930367BE"
        await installVerifiedDeviceIds(session, sender: sender, ids: [UUID(), UUID()])

        await session.rearmInboundRecoveryPendingResend(
            sender: sender,
            deviceId: replaced,
            sharedMessageId: envelope)

        #expect(!(await session.hasPendingResendAfterReestablishment(
            sender: sender, deviceId: replaced, failedMessageId: envelope)))
        #expect(await session.isInboundFailureQuarantined(
            sender: sender, deviceId: replaced, messageId: envelope))
    }

    @Test("rearm with an empty memo still inserts a pending resend")
    func rearmWithEmptyMemoStillInserts() async throws {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let deviceId = UUID()
        let envelope = UUID().uuidString

        await session.rearmInboundRecoveryPendingResend(
            sender: "nudge",
            deviceId: deviceId,
            sharedMessageId: envelope)

        #expect(await session.hasPendingResendAfterReestablishment(
            sender: "nudge", deviceId: deviceId, failedMessageId: envelope))
    }

    private func installVerifiedDeviceIds(
        _ session: PQSSession,
        sender: String,
        ids: Set<UUID>
    ) async {
        await session.setVerifiedDeviceIds(ids, for: sender)
    }
}

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
                verifiedDeviceIds: []))
    }

    @Test("member of the verified set does not drop")
    func memberKeepsResend() {
        let device = UUID()
        #expect(
            !StaleInboundDevicePolicy.shouldDrop(
                senderDeviceId: device,
                verifiedDeviceIds: [device, UUID()]))
    }

    @Test("non-member of a non-empty verified set drops")
    func absentDeviceDrops() {
        #expect(
            StaleInboundDevicePolicy.shouldDrop(
                senderDeviceId: UUID(),
                verifiedDeviceIds: [UUID(), UUID()]))
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

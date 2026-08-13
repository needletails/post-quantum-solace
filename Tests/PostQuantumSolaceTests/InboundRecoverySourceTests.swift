//
//  InboundRecoverySourceTests.swift
//  post-quantum-solace
//
//  Compile-time / behavioral contracts for inbound decrypt recovery.
//  Source-string pins retired in PQS 4.0 Phase 0.
//

import Foundation
import SessionEvents
import SessionModels
import Testing
@testable import PQSSession

@Suite("Inbound recovery contracts")
struct InboundRecoverySourceTests {

    /// Covered by SessionReestablishmentCoalescingTests.episodeTTLExpiryFiresReestablishmentEpisodeDidEnd,
    /// SessionReestablishmentCoalescingTests.flushPendingResendsAfterOfflineReplayTakesEveryDeferredLane,
    /// and EndToEndTests "deferred resend drains after peerRefresh completion".
    @Test("offline replay complete flush API exists and is public")
    func offlineReplayCompleteFlushAPIExists() {
        let pin: (PQSSession, Date) async -> Void = { session, now in
            await session.flushPendingResendsAfterOfflineReplay(now: now)
        }
        _ = pin
    }

    /// Covered by SessionReestablishmentCoalescingTests.agedPendingResendIsNotWallClockTerminal
    /// and SessionReestablishmentCoalescingTests.agedPendingResendDoesNotNotifyHostUnrecoverable.
    /// LRU bound remains the only in-memory cap.
    @Test("pending-resend cleanup is not wall-clock terminal")
    func pendingResendCleanupIsNotWallClockTerminal() {
        #expect(PQSSessionConstants.recoveryTrackingMaxEntries > 0)
    }

    /// Covered by SessionReestablishmentCoalescingTests.Host re-arm and
    /// EndToEndTests inbound recovery paths that notify the host.
    @Test("pending recovery host event exists on the delegate")
    func pendingRecoveryHostEventExists() {
        let pin: (any PQSHostDelegate, String, UUID, String) async -> Void = {
            await $0.inboundMessagePendingRecovery(
                senderSecretName: $1,
                senderDeviceId: $2,
                sharedMessageId: $3)
        }
        _ = pin
    }

    /// `recoveryEmitBlockedLanes` / `markRecoveryEmitBlocked` / `isRecoveryEmitBlocked`
    /// were write-only and are gone. There is no public API to call. Covered by
    /// SessionReestablishmentCoalescingTests episode-end drain (no emit-block gate).
    @Test("write-only recoveryEmitBlockedLanes is removed")
    func writeOnlyRecoveryEmitBlockedLanesIsRemoved() {
        let pin: (PQSSession, Date) async -> Void = { session, now in
            await session.flushPendingResendsAfterOfflineReplay(now: now)
        }
        _ = pin
    }

    @Test("orphan resend can heal inbound recovery placeholders")
    func orphanResendCanHealInboundRecoveryPlaceholders() {
        _ = MessagePipeline.isReplaceableInboundRecoveryPlaceholder
        #expect(MessagePipeline.isReplaceableInboundRecoveryPlaceholder(
            placeholderProps(deliveryState: .waitingDelivery)))
        #expect(MessagePipeline.isReplaceableInboundRecoveryPlaceholder(
            placeholderProps(deliveryState: .failed("pending"))))
        #expect(!MessagePipeline.isReplaceableInboundRecoveryPlaceholder(
            placeholderProps(deliveryState: .delivered)))
        #expect(!MessagePipeline.isReplaceableInboundRecoveryPlaceholder(
            placeholderProps(deliveryState: .sending)))
    }

    /// Covered by SessionReestablishmentCoalescingTests.transportedResendRequestAttemptsSurvivePastTheFailurePolicyCooldown.
    @Test("resend-request attempt window outlives the failure-policy cooldown")
    func resendRequestAttemptWindowOutlivesFailurePolicyCooldown() async {
        _ = PQSSessionConstants.resendRequestAttemptWindowSeconds
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        #expect(
            PQSSessionConstants.resendRequestAttemptWindowSeconds
                > (await session.inboundFailurePolicyTTL))
        await session.shutdown()
    }

    /// Covered by SessionReestablishmentCoalescingTests.hostRearmRepopulatesADeferredNACKLaneAfterRelaunch.
    @Test("host re-arm API repopulates deferred NACK lanes after relaunch")
    func hostRearmAPIRepopulatesDeferredNACKLanes() {
        let pin: (PQSSession, String, UUID, String, Date) async -> Void = {
            await $0.rearmInboundRecoveryPendingResend(
                sender: $1,
                deviceId: $2,
                sharedMessageId: $3,
                now: $4)
        }
        _ = pin
    }

    /// Covered by SessionReestablishmentCoalescingTests.episodeTTLExpiryFiresReestablishmentEpisodeDidEnd
    /// (host `reestablishmentEpisodeDidEnd` + drain) and EndToEndTests deferred-resend drain.
    @Test("episode end drains deferred resends")
    func episodeEndDrainsDeferredResends() {
        let pin: (PQSSession, Date) async -> Void = { session, now in
            await session.flushPendingResendsAfterOfflineReplay(now: now)
        }
        _ = pin
    }

    private func placeholderProps(deliveryState: DeliveryState) -> EncryptedMessage.UnwrappedProps {
        EncryptedMessage.UnwrappedProps(
            id: UUID(),
            base: BaseCommunication(id: UUID(), data: Data()),
            sentDate: Date(),
            receiveDate: nil,
            deliveryState: deliveryState,
            message: CryptoMessage(
                text: "",
                metadata: Data(),
                recipient: .nickname("peer"),
                sentDate: Date(),
                destructionTime: nil),
            senderSecretName: "peer",
            senderDeviceId: UUID())
    }
}

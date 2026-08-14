//
//  FriendshipFlowSourceTests.swift
//  post-quantum-solace
//
//  Compile-time / behavioral contracts for friendship and recovery flows.
//  Source-string pins retired in PQS 4.0 Phase 0. Each former source test is
//  either a symbol reference below or covered by an existing suite:
//
//  contactSynchronizationRepairsCommunicationShells
//      Covered by FriendshipStateTests / EndToEndTests contact sync.
//  explicitFriendshipPacketsCanOverrideSettledStoredMetadata
//      Covered by FriendshipMetadataMergeTests.
//  inboundFriendshipDefersUntilPeerOTKHandshakeIsReady
//      Covered by EndToEndTests hasInitializedOutboundRatchetForPeer paths.
//  recoveryBaselineIsLocked / recoveryInvariantsAreLocked
//      Covered by DogfoodLogReplayTests C3*, DemotePromoteThrashPolicyTests,
//      OrphanInPlaceHealTests, SessionReestablishmentCoalescingTests.
//  sessionBackgroundWorkUsesCancellableSessionWorkTree
//      Covered by SessionConcurrencyHardeningTests / ConnectivityTests.
//  chatFanoutUsesVerifiedDeviceHelper / warmChatFanoutAvoidsBlockingFindConfiguration
//      Covered by DogfoodLogReplayTests.dogfood N1.
//  outboundDeviceSendLedgerRecordsPerDeviceEncryptAndOrphanResend
//      Covered by EnvelopeMessageIdTests.outboundRecordRetainsEnvelopeHistory.
//  undecryptableInboundUsesResendThenEscalate / inboundDecryptFailuresUseOrphanResend
//      Covered by StrictOOBRetryTests / EndToEndTests maxSkipped + CryptoKit recovery.
//  redeliveredAlreadyPersistedInboundCopiesReEmitSpoolAck
//      Covered by EndToEndTests "Duplicate decrypts and redelivered frames persist
//      exactly one row per shared id".
//  unhandledInboundErrorsPurgeSpoolCopyButCancellationDoesNot
//      Covered by SessionReestablishmentCoalescingTests dogfood coalesced deferred recovery.
//  peerContactBootstrapGatesOnRatchetStateNotIdentityRowCount
//      Compile-time pin of bootstrapPeerContactSession / PeerContactBootstrapPurpose.
//  legacyInverseBlockMetadataStillSendsServerUnblockPacket
//      Covered by FriendshipStateTests blocked-state transitions +
//      FriendshipMetadataMergeTests inbound block/unblock.
//  open peerRefresh episode coalesces / terminal emit failures / decrypt-driven leader
//      Covered by SessionReestablishmentCoalescingTests + EndToEndTests
//      "maxSkipped repair coalesces peerRefresh inside an open episode".
//  OTK recovery rides ungated protocol work
//      Covered by SessionConcurrencyHardeningTests
//      "non-viable session drops gated background work but still runs transport protocol work"
//      and SessionReestablishmentCoalescingTests transport-protocol work while not viable.
//  unanswered initiating lanes reset only on OTK evidence and peerRefresh
//      Covered by NackLaneHealPolicyTests / StrictOOBRetryTests.
//  episode TTL expiry drains deferred resends
//      Covered by SessionReestablishmentCoalescingTests episode TTL + aged pending resend.
//  outbound user ciphertext is prioritized over control frames
//      Covered by TaskProcessorSequenceTests urgent-before-background inbound.
//  fresh session reset preserves at-most-once one-time prekeys
//      Compile-time pin of resetSessionIdentityForFreshSession.
//  out-of-band resend consolidates / requestMessageResend uses OOB /
//  unavailable notice is out-of-band
//      Covered by StrictOOBRetryTests + SessionReestablishmentCoalescingTests OOB unavailable.
//  deferred resend drain caps submissions
//      Covered by SessionReestablishmentCoalescingTests attempt-window +
//      PQSSessionConstants.peerResendRequestMaxSubmissions.
//  successful inbound does not close episode while peerRefresh response expected
//      Covered by SessionReestablishmentCoalescingTests expected-response intent +
//      EndToEndTests "peerRefresh control survives its owning open episode".
//  resend request/replay loop is transport-confirmed
//      Covered by StrictOOBRetryTests / TransportEventCodingTests.
//  session cache delete is idempotent when row is already absent
//      Covered by SessionIdentityTests.testSessionCacheDeleteIsIdempotentWhenRowIsAlreadyAbsent.
//  every lane teardown is audited with a caller reason
//      Compile-time pin of resetSessionIdentityForFreshSession(reason:).
//  undecryptable lane saturation stays on sender orphanResend path
//      Covered by StrictOOBRetryTests + undecryptableLaneEscalateThreshold below.
//  orphan remint does not capture general outbound fan-out
//      Covered by OrphanOwnershipHealPolicyTests + NackLaneHealPolicyTests
//      ExplicitOutboundRecipientPinPolicy.
//  dogfood N3 outbound persist without live findConfiguration
//      Covered by DogfoodLogReplayTests.dogfood N3 +
//      OutboundJobEnqueueTests.Nonviable compose still persists durable jobs.
//  dogfood C2 inbound active-first / archive HOL
//      Covered by DogfoodLogReplayTests C2b/C2c/C2f/C2g,
//      EnvelopeMessageIdTests T17, OrphanInPlaceHealTests P1b.
//  sticky orphan wave drain does not clear mark
//      Covered by OrphanInPlaceHealTests P3 + DogfoodLogReplayTests C3* +
//      DemotePromoteThrashPolicyTests P1 reuseRecoveryWave.
//  non-viable transport parks recovery outbound / enqueue persists without enqueue
//      Covered by SessionConcurrencyHardeningTests + OutboundJobEnqueueTests nonviable compose.
//  failed orphan replay re-arms bounded NACK; personal refresh cannot stomp orphan lane
//      Covered by NackLaneHealPolicyTests OrphanReplayRearmPolicy +
//      DemotePromoteThrashPolicyTests skipPersonalRefreshForHealLanes.
//  same-account orphan resend defers non-owners
//      Covered by OrphanOwnershipHealPolicyTests.
//  handleWriteMessage always records OutboundDeviceSendRecord
//      Compile-time pin of recordOutboundDeviceSend.
//  DEAD LEGACY / forceFreshControlLane / shouldMintFreshControlLane source pins
//      Retired so Phase 1 can delete dead stubs. OOB retry remains
//      StrictOOBRetryTests; ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane
//      is the replacement mint policy.
//

import Foundation
import DoubleRatchetKit
import SessionModels
import Testing
@testable import PQSSession
@testable import SessionEvents

@Suite("Friendship flow contracts")
struct FriendshipFlowSourceTests {

    @Test("public and internal friendship/recovery APIs still exist")
    func compileTimeAPIPins() {
        _ = PeerContactBootstrapPurpose.newOutbound
        _ = PeerContactBootstrapPurpose.friendshipReply
        _ = FriendshipMetadataConflictPolicy.inboundFriendship
        _ = FriendshipMetadataConflictPolicy.preferSettled
        let prefer: (FriendshipMetadata, FriendshipMetadata) -> FriendshipMetadata =
            preferInboundFriendshipMetadata
        _ = prefer

        let bootstrap: (PQSSession, String, PeerContactBootstrapPurpose) async throws -> Void = {
            try await $0.bootstrapPeerContactSession(secretName: $1, purpose: $2)
        }
        _ = bootstrap

        let friendship: (PQSSession, FriendshipMetadata.State, Contact) async throws -> Void = {
            try await $0.requestFriendshipStateChange(state: $1, contact: $2)
        }
        _ = friendship

        let fanout: (PQSSession, String) async throws -> [SessionIdentity] = {
            try await $0.sessionIdentitiesForChatFanout(secretName: $1)
        }
        _ = fanout

        let outboundReady: (PQSSession, String) async throws -> Bool = {
            try await $0.hasInitializedOutboundRatchetForPeer($1)
        }
        _ = outboundReady

        let needsBootstrap: (PQSSession, String) async throws -> Bool = {
            try await $0.peerNeedsOutboundBootstrap($1)
        }
        _ = needsBootstrap

        let reset: (PQSSession, String, UUID, Bool, String, Bool) async throws -> SessionIdentity = {
            try await $0.resetSessionIdentityForFreshSession(
                secretName: $1,
                deviceId: $2,
                sendOneTimeIdentities: $3,
                reason: $4,
                demotePriorActives: $5)
        }
        _ = reset

        let activate: (PQSSession, SessionIdentity) async throws -> SessionIdentity = {
            try await $0.activateSessionIdentityAfterInboundDecrypt($1)
        }
        _ = activate

        let promote: (PQSSession, SessionIdentity) async throws -> SessionIdentity = {
            try await $0.promoteArchivedSessionIdentityToActive($1)
        }
        _ = promote

        let demoteZombies: (PQSSession, String, UUID) async throws -> Void = {
            _ = try await $0.demoteZombieStateLessActives(secretName: $1, deviceId: $2)
        }
        _ = demoteZombies

        let markOrphan: (PQSSession, String, UUID, UUID) async -> Void = {
            await $0.markOrphanResendInitiatingSession(secretName: $1, deviceId: $2, sessionId: $3)
        }
        _ = markOrphan

        let recordSend: (PQSSession, String, String, UUID, UUID, String, Int) async -> Void = {
            await $0.recordOutboundDeviceSend(
                sharedId: $1,
                recipientSecretName: $2,
                recipientDeviceId: $3,
                sessionIdentityId: $4,
                envelopeMessageId: $5,
                resendAttempt: $6)
        }
        _ = recordSend

        let resend: (PQSSession, String, String, UUID) async throws -> Void = {
            try await $0.requestMessageResend(
                sharedMessageId: $1,
                senderName: $2,
                senderDeviceId: $3)
        }
        _ = resend

        let oobRequest: (any PQSNetworkHost, [String], String, UUID, UUID) async throws -> Void = {
            try await $0.sendOutOfBandResendRequest(
                failedEnvelopeMessageIds: $1,
                to: $2,
                deviceId: $3,
                requestingDeviceId: $4)
        }
        _ = oobRequest

        let oobUnavailable: (any PQSNetworkHost, [String], String, UUID, UUID) async throws -> Void = {
            try await $0.sendOutOfBandResendUnavailable(
                unavailableEnvelopeMessageIds: $1,
                to: $2,
                deviceId: $3,
                respondingDeviceId: $4)
        }
        _ = oobUnavailable

        let handleUnavailable: (PQSSession, String, UUID, [String]) async -> Void = {
            await $0.handleOutOfBandResendUnavailable(
                from: $1,
                deviceId: $2,
                unavailableEnvelopeMessageIds: $3)
        }
        _ = handleUnavailable

        let emit: (PQSSession, SessionReestablishmentKind, MessageRecipient, ControlEventScope, Bool) async throws -> Bool = {
            try await $0.emitSessionReestablishment(
                kind: $1,
                recipient: $2,
                scope: $3,
                forceReemit: $4)
        }
        _ = emit

        let transported: (PQSSession, String, UUID, [String], Date) async -> Void = {
            await $0.markPeerResendRequestTransported(
                sender: $1,
                deviceId: $2,
                failedMessageIds: $3,
                now: $4)
        }
        _ = transported

        let background: (PQSSession) async -> SessionWorkAdmission = { session in
            await session.scheduleBackgroundWork {}
        }
        _ = background

        let protocolWork: (PQSSession) async -> SessionWorkAdmission = { session in
            await session.scheduleTransportProtocolWork {}
        }
        _ = protocolWork

        let connectivity: (PQSSession, Bool) async -> Void = {
            await $0.setConnectivity($1)
        }
        _ = connectivity

        _ = OutboundDeviceSendRecord.self
        _ = OrphanResendOwnershipPolicy.decision
        _ = OutboundOrphanSessionSelectionPolicy.decision
        _ = PersonalOutboundRefreshPolicy.shouldSkipRefresh
        _ = ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane
        _ = InboundInitiatingSlotPolicy.shouldEnsureInboundBlank
        _ = OrphanResendRemintPolicy.decision
        _ = InboundRecoveryStormPolicy.shouldDeferArchivedFallback
        _ = ExplicitOutboundRecipientPinPolicy.shouldHonorExplicitRecipient
        _ = OrphanReplayRearmPolicy.shouldRearm
        _ = MessagePipeline.isReplaceableInboundRecoveryPlaceholder
    }

    @Test("Inactive session retention supports multi-device offline lag")
    func inactiveSessionRetentionSupportsMultiDeviceOfflineLag() {
        #expect(PQSSessionConstants.inactiveSessionMaxCountPerDevice == 40)
        #expect(PQSSessionConstants.inactiveSessionMaxAgeSeconds == 60 * 60 * 24 * 30)
        #expect(PQSSessionConstants.outboundDeviceSendRecordMaxCount == 2_000)
    }

    @Test("undecryptable lane saturation stays on sender orphanResend path")
    func undecryptableLaneSaturationStaysOnSenderOrphanResendPath() {
        #expect(PQSSessionConstants.undecryptableLaneEscalateThreshold == 3)
        #expect(PQSSessionConstants.peerResendRequestMaxSubmissions == 3)
        #expect(
            !ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: true,
                forceFreshInitiating: true,
                liveOrphanOrRecovery: true))
    }

    @Test("explicit friendship packets can override settled stored metadata")
    func explicitFriendshipPacketsCanOverrideSettledStoredMetadata() {
        let stored = FriendshipMetadata(myState: .requested, theirState: .pending, ourState: .pending)
        let inbound = FriendshipMetadata(myState: .accepted, theirState: .accepted, ourState: .accepted)
        let resolved = FriendshipMetadataConflictPolicy.inboundFriendship.resolve(
            passed: inbound,
            stored: stored)
        #expect(resolved.ourState == FriendshipMetadata.State.accepted)
    }
}

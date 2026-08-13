//
//  SessionIdentitySourceTests.swift
//  post-quantum-solace
//
//  Compile-time regression guards for identity refresh hardening.
//  Source-string pins retired in PQS 4.0 Phase 0.
//

import Foundation
import SessionModels
import Testing
@testable import PQSSession

@Suite("Session identity contracts")
struct SessionIdentitySourceTests {

    /// Covered by SessionIdentityTests refresh / force-refresh suites
    /// (`Should handle error conditions gracefully`,
    /// `Should rethrow critical invalid-signature refresh failures`,
    /// `Force refresh rejects peer account signing key drift from pinned contact`).
    /// Private helper `verifiedDevicesWithUsableKeyMaterial` is not @testable.
    @Test("identity refresh skips malformed provisional devices")
    func identityRefreshSkipsMalformedProvisionalDevices() {
        let pin: (PQSSession, String, [SessionIdentity], Bool, Bool, String?, String?) async throws -> [SessionIdentity] = {
            try await $0.refreshSessionIdentities(
                for: $1,
                from: $2,
                createIdentity: $3,
                forceRefresh: $4,
                sendOneTimeIdentities: false,
                oneTime: $5,
                oneTime: $6)
        }
        _ = pin
    }

    /// Covered by SessionIdentityTests `Force refresh replaces rotated active identity instead of mutating it`
    /// and `Should assess peer refresh impact for unchanged and rotated peer identity keys`.
    /// Private helper `pruneStaleSessionIdentities` is not @testable.
    @Test("full identity refresh prunes ghost devices via shared helper")
    func fullIdentityRefreshPrunesGhostDevicesViaSharedHelper() {
        let pin: (PQSSession, String, [SessionIdentity], Bool, String?, String?) async throws -> [SessionIdentity] = {
            try await $0.refreshSessionIdentities(
                for: $1,
                from: $2,
                createIdentity: true,
                forceRefresh: $3,
                sendOneTimeIdentities: false,
                oneTime: $4,
                oneTime: $5)
        }
        _ = pin
    }

    /// Covered by SessionIdentityTests cache alignment tests and
    /// RecoveryScenarioHarnessTests.clearOrphanResendRecoveryState.
    /// Device-local reset must invalidate cache, not `removeIdentity(with:)`.
    @Test("device-local reset never performs account-wide transient cleanup")
    func deviceLocalResetUsesCacheOnlyInvalidation() {
        let reset: (PQSSession, String, UUID, Bool, String, Bool) async throws -> SessionIdentity = {
            try await $0.resetSessionIdentityForFreshSession(
                secretName: $1,
                deviceId: $2,
                sendOneTimeIdentities: $3,
                reason: $4,
                demotePriorActives: $5)
        }
        _ = reset
        let clear: (PQSSession, String, UUID) async -> Void = {
            await $0.clearOrphanResendRecoveryState(secretName: $1, deviceId: $2)
        }
        _ = clear
    }

    /// Covered by SessionReestablishmentCoalescingTests flush-after-offline-replay
    /// and EndToEndTests offline backlog suites. Startup must not prune archives
    /// before mailbox settlement.
    @Test("startup does not prune archives before mailbox settlement")
    func archiveMaintenanceRequiresReplaySettlement() {
        let pin: (PQSSession) async -> Void = { session in
            await session.offlineReplayDidSettle()
        }
        _ = pin
    }

    /// Covered by SessionIdentityTests SessionCache persistence-failure alignment
    /// (`SessionCache keeps memory and disk aligned when delete persistence fails`).
    @Test("prepared outbound commits job and ratchet checkpoint together")
    func preparedOutboundUsesAtomicCacheCommit() {
        let pin: (SessionCache, SessionIdentity, JobModel) async throws -> Void = {
            try await $0.commitPreparedOutbound(sessionIdentity: $1, job: $2)
        }
        _ = pin
    }
}

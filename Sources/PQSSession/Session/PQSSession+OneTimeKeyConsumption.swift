//
//  PQSSession+OneTimeKeyConsumption.swift
//  post-quantum-solace
//
//  Deferred one-time-key consumption bookkeeping, applied inside the exclusive
//  session-context commit so it can never roll back a concurrent commit (for
//  example a one-time-key batch replacement that finished while an inbound
//  frame was being processed).
//

import DoubleRatchetKit
import Foundation
import SessionModels

extension DeviceKeys {
    /// What a committed inbound frame did to the deferred-consumption ledger.
    struct CommittedInboundFrameOutcome: Sendable {
        /// An entry the lane proved it no longer needs, and which private halves
        /// that removed. A half stays while another lane has it pending.
        struct Confirmation: Sendable {
            let entry: PendingOneTimeKeyConsumption
            let deletedOneTimeKey: Bool
            let deletedMLKEMKey: Bool

            var privateDeleted: String {
                let deleted = [deletedOneTimeKey ? "otk" : nil, deletedMLKEMKey ? "mlkem" : nil].compactMap { $0 }
                return deleted.isEmpty ? "none" : deleted.joined(separator: ",")
            }
        }

        var confirmed: [Confirmation] = []
        /// Newly recorded pending consumption for this frame's bootstrap keys.
        var recordedPending: PendingOneTimeKeyConsumption?
        var mutated = false
    }

    /// Applies the deferred-consumption rules for one committed inbound frame.
    ///
    /// Only the X25519 `oneTimeKeyId` discriminates lanes. In DRK 4.0.0 a live
    /// lane cites its bootstrap OTK id for its whole lifetime (the state OTK
    /// participates in every epoch re-key), so the deletion-confirming events are:
    ///   1. A committed frame on the same lane citing a *different* id: the peer
    ///      re-fetched our bundle and epoch re-keyed the lane, so the superseded
    ///      key can never be legitimately cited again.
    ///   2. A committed frame with no id: a lane established without an OTK, and
    ///      the forward-compatible trigger for a future DRK that stops citing
    ///      after the reverse handshake completes.
    /// `mlKEMOneTimeKeyId` mirrors non-optional lane state and is cited on every
    /// frame forever, so it never drives confirmation alone.
    mutating func applyCommittedInboundFrame(
        laneId: UUID,
        headerOneTimeKeyId: UUID?,
        headerMLKEMOneTimeKeyId: UUID?
    ) -> CommittedInboundFrameOutcome {
        var outcome = CommittedInboundFrameOutcome()
        var confirmedEntries: [PendingOneTimeKeyConsumption] = []

        if let headerOneTimeKeyId {
            let laneEntries = removePendingOneTimeKeyConsumptions(for: laneId)
            for entry in laneEntries {
                if entry.oneTimeKeyId == headerOneTimeKeyId {
                    recordPendingOneTimeKeyConsumption(entry)
                } else {
                    confirmedEntries.append(entry)
                    outcome.mutated = true
                }
            }
            // Record only keys we can actually delete later. A bootstrap
            // decrypted purely via archived-state fallback (pool already
            // rotated) has nothing to defer.
            let alreadyPending = (pendingOneTimeKeyConsumptions ?? []).contains {
                $0.sessionIdentityId == laneId && $0.oneTimeKeyId == headerOneTimeKeyId
            }
            if !alreadyPending,
               oneTimePrivateKeys.contains(where: { $0.id == headerOneTimeKeyId }) {
                // The cited MLKEM id is consumable only while it is a pool key;
                // the final (last-resort) MLKEM key is never consumed.
                let pendingMLKEMId = headerMLKEMOneTimeKeyId.flatMap { id in
                    mlKEMOneTimePrivateKeys.contains(where: { $0.id == id }) ? id : nil
                }
                let entry = PendingOneTimeKeyConsumption(
                    sessionIdentityId: laneId,
                    oneTimeKeyId: headerOneTimeKeyId,
                    mlKEMOneTimeKeyId: pendingMLKEMId)
                recordPendingOneTimeKeyConsumption(entry)
                outcome.recordedPending = entry
                outcome.mutated = true
            }
        } else {
            confirmedEntries = removePendingOneTimeKeyConsumptions(for: laneId)
            outcome.mutated = !confirmedEntries.isEmpty
        }

        for entry in confirmedEntries {
            let heldOneTimeKeys = oneTimePrivateKeys.count
            let heldMLKEMKeys = mlKEMOneTimePrivateKeys.count
            if let otkId = entry.oneTimeKeyId,
               !isOneTimeKeyStillPending(otkId) {
                oneTimePrivateKeys.removeAll { $0.id == otkId }
            }
            if let kemId = entry.mlKEMOneTimeKeyId,
               !isMLKEMOneTimeKeyStillPending(kemId) {
                mlKEMOneTimePrivateKeys.removeAll { $0.id == kemId }
            }
            outcome.confirmed.append(CommittedInboundFrameOutcome.Confirmation(
                entry: entry,
                deletedOneTimeKey: oneTimePrivateKeys.count != heldOneTimeKeys,
                deletedMLKEMKey: mlKEMOneTimePrivateKeys.count != heldMLKEMKeys))
        }
        return outcome
    }
}

extension PQSSession {
    /// Records or confirms deferred one-time-key consumption for a committed
    /// inbound frame as one exclusive commit. Returns `nil` when no session is
    /// active or nothing changed.
    func commitDeferredOneTimeKeyConsumption(
        laneId: UUID,
        headerOneTimeKeyId: UUID?,
        headerMLKEMOneTimeKeyId: UUID?
    ) async throws -> DeviceKeys.CommittedInboundFrameOutcome? {
        var outcome: DeviceKeys.CommittedInboundFrameOutcome?
        _ = try await commitLiveSessionContextMutationIfChanged { context in
            var deviceKeys = context.sessionUser.deviceKeys
            let result = deviceKeys.applyCommittedInboundFrame(
                laneId: laneId,
                headerOneTimeKeyId: headerOneTimeKeyId,
                headerMLKEMOneTimeKeyId: headerMLKEMOneTimeKeyId)
            outcome = result
            guard result.mutated else { return false }
            context.sessionUser.deviceKeys = deviceKeys
            context.updateSessionUser(context.sessionUser)
            return true
        }
        return outcome
    }

    /// Retires the published halves of one-time keys the verified ratchet header
    /// cites, after the server was told to drop them. Private halves are left for
    /// deferred consumption. Returns `false` when nothing changed.
    func retirePublishedOneTimeKeys(
        x25519Id: UUID?,
        mlKEMId: UUID?
    ) async throws -> Bool {
        let updated = try await commitLiveSessionContextMutationIfChanged { context in
            var mutated = false
            if let x25519Id {
                let before = context.activeUserConfiguration.signedOneTimePublicKeys.count
                context.activeUserConfiguration.signedOneTimePublicKeys.removeAll { $0.id == x25519Id }
                mutated = mutated || context.activeUserConfiguration.signedOneTimePublicKeys.count != before
            }
            if let mlKEMId {
                let before = context.activeUserConfiguration.signedMLKEMOneTimePublicKeys.count
                context.activeUserConfiguration.signedMLKEMOneTimePublicKeys.removeAll { $0.id == mlKEMId }
                mutated = mutated || context.activeUserConfiguration.signedMLKEMOneTimePublicKeys.count != before
            }
            return mutated
        }
        return updated != nil
    }

    /// Removes one-time keys this device chose to retire (outbound bookkeeping),
    /// public and private halves, as one exclusive commit. Returns `false` when
    /// no live session exists.
    func removeOwnOneTimeKeys(
        x25519Id: UUID?,
        mlKEMId: UUID?
    ) async throws -> Bool {
        let updated = try await commitLiveSessionContextMutationIfChanged { context in
            if let x25519Id {
                context.activeUserConfiguration.signedOneTimePublicKeys.removeAll { $0.id == x25519Id }
                context.sessionUser.deviceKeys.oneTimePrivateKeys.removeAll { $0.id == x25519Id }
            }
            if let mlKEMId {
                context.activeUserConfiguration.signedMLKEMOneTimePublicKeys.removeAll { $0.id == mlKEMId }
                context.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.removeAll { $0.id == mlKEMId }
            }
            return true
        }
        return updated != nil
    }
}

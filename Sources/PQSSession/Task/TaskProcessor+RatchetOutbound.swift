//
//  TaskProcessor+RatchetOutbound.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-14.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//

import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
import SessionEvents
import SessionModels
import NeedleTailLogger

/// Outbound Double Ratchet path: identity resolution, control-lane
/// selection, and `handleWriteMessage` encryption/signing.
extension MessagePipeline {
    // MARK: - Outbound Message Handling
    
    /// Handles writing a message and performing the necessary ratchet operations.
    ///
    /// This method implements the sender side of the Double Ratchet protocol for outbound
    /// messages. It manages key selection, ratchet initialization, message encryption,
    /// and signature generation. The method handles both initial message setup and
    /// subsequent message encryption with proper key rotation.
    ///
    /// ## Encryption Process
    /// 1. Validates session context and recipient identity
    /// 2. Selects appropriate keys (long-term, one-time, PQ-KEM)
    /// 3. Initializes ratchet state for sender
    /// 4. Encrypts message using ratchet encryption
    /// 5. Signs the encrypted message
    /// 6. Removes used keys and updates session state
    /// 7. Sends message through transport layer
    ///
    /// ## Key Management
    /// - Long-term keys are used for session establishment
    /// - One-time keys provide forward secrecy
    /// - PQ-KEM keys provide post-quantum security
    /// - Keys are rotated automatically when needed
    ///
    /// ## Security Considerations
    /// - All cryptographic operations use secure random number generation
    /// - Keys are validated before use to prevent attacks
    /// - Used keys are immediately removed to maintain forward secrecy
    /// - Message signatures prevent tampering and impersonation
    ///
    /// - Parameters:
    ///   - outboundTask: The outbound task message to be processed. Contains the
    ///                   plaintext message and recipient information.
    ///   - session: The current crypto session providing context and keys.
    /// - Throws: An error if the message handling fails due to missing keys,
    ///           cryptographic errors, or transport failures.
    ///
    /// Outbound jobs embed a `SessionIdentity` snapshot at enqueue time. Identity refresh can delete,
    /// archive, and recreate rows while preserving `(secretName, deviceId)`, leaving jobs with stale ids.
    /// Always reselect the current active row for that device so archived snapshots are never used to send.
    private func resolveSessionIdentityForOutbound(
        embeddedRecipient: SessionIdentity,
        session: PQSSession,
        databaseSymmetricKey: SymmetricKey
    ) async throws -> SessionIdentity {
        guard let cache = await session.cache else {
            throw PQSError.databaseNotInitialized
        }
        let stored = try await cache.fetchSessionIdentities()

        // Pin heal/initiating explicit recipients only. Blanket "any live active"
        // would defeat intentional rebind (same-account orphan ownership for queued
        // jobs still naming a poison initialized row). StickyAdvancedRemint must
        // not steal surgical/orphan blanks (dogfood: DEE14418 mint → NACK on 995FE37C).
        if let pinned = await pinnedExplicitOutboundRecipient(
            embeddedRecipient,
            in: stored,
            session: session,
            symmetricKey: databaseSymmetricKey
        ) {
            return try await prepareStateLessPersonalSessionIdentityForOutbound(
                pinned,
                session: session,
                databaseSymmetricKey: databaseSymmetricKey)
        }

        let lookupProps: SessionIdentity.UnwrappedProps?
        if let embeddedProps = await embeddedRecipient.props(symmetricKey: databaseSymmetricKey) {
            lookupProps = embeddedProps
        } else if let direct = stored.first(where: { $0.id == embeddedRecipient.id }),
                  let directProps = await direct.props(symmetricKey: databaseSymmetricKey) {
            lookupProps = directProps
        } else {
            lookupProps = nil
        }

        guard let lookupProps else {
            throw PQSError.missingSessionIdentity
        }

        let preferredDevice = await currentDeviceConfiguration(
            secretName: lookupProps.secretName,
            deviceId: lookupProps.deviceId,
            session: session)
        if let match = await outboundSessionIdentity(
            secretName: lookupProps.secretName,
            deviceId: lookupProps.deviceId,
            in: stored,
            symmetricKey: databaseSymmetricKey,
            session: session,
            preferredDevice: preferredDevice
        ) {
            return try await prepareStateLessPersonalSessionIdentityForOutbound(
                match,
                session: session,
                databaseSymmetricKey: databaseSymmetricKey)
        }
        _ = try await session.refreshIdentities(secretName: lookupProps.secretName, forceRefresh: true)
        let refreshed = try await cache.fetchSessionIdentities()
        if let match = await outboundSessionIdentity(
            secretName: lookupProps.secretName,
            deviceId: lookupProps.deviceId,
            in: refreshed,
            symmetricKey: databaseSymmetricKey,
            session: session,
            preferredDevice: preferredDevice
        ) {
            return try await prepareStateLessPersonalSessionIdentityForOutbound(
                match,
                session: session,
                databaseSymmetricKey: databaseSymmetricKey)
        }
        throw PQSError.missingSessionIdentity
    }

    /// Returns the stored row when the task-embedded recipient is still a live
    /// heal/initiating lane that must not be rebound by `outboundSessionIdentity`.
    private func pinnedExplicitOutboundRecipient(
        _ candidate: SessionIdentity,
        in identities: [SessionIdentity],
        session: PQSSession,
        symmetricKey: SymmetricKey
    ) async -> SessionIdentity? {
        guard let stored = identities.first(where: { $0.id == candidate.id }),
              let props = await stored.props(symmetricKey: symmetricKey)
        else {
            return nil
        }
        let isLiveActive = !props.deviceName.hasPrefix(
            PQSSessionConstants.inactiveSessionDeviceNamePrefix)
        let orphanId = await session.orphanResendInitiatingSessionId(
            secretName: props.secretName,
            deviceId: props.deviceId)
        let recoveryId = await session.orphanResendRecoverySessionId(
            secretName: props.secretName,
            deviceId: props.deviceId)
        let isOrphanOrRecoveryLane =
            stored.id == orphanId || stored.id == recoveryId
        guard ExplicitOutboundRecipientPinPolicy.shouldHonorExplicitRecipient(
            isLiveActive: isLiveActive,
            isStateLess: !props.hasRatchetState,
            isOrphanOrRecoveryLane: isOrphanOrRecoveryLane
        ) else {
            return nil
        }
        return stored
    }

    private func prepareStateLessPersonalSessionIdentityForOutbound(
        _ identity: SessionIdentity,
        session: PQSSession,
        databaseSymmetricKey: SymmetricKey
    ) async throws -> SessionIdentity {
        guard let context = await session.sessionContext else {
            throw PQSError.sessionNotInitialized
        }
        guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else {
            return identity
        }

        guard props.secretName == context.sessionUser.secretName,
              props.deviceId != context.sessionUser.deviceId,
              !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix),
              !props.hasRatchetState
        else {
            return identity
        }

        // Heal lanes must not be reminted: orphan initiating, recovery SessionID,
        // or control/repair blank (state-less, no curve OTK).
        let hasOrphanMark = await session.orphanResendInitiatingSessionId(
            secretName: props.secretName,
            deviceId: props.deviceId) != nil
        let hasRecovery = await session.orphanResendRecoverySessionId(
            secretName: props.secretName,
            deviceId: props.deviceId) != nil
        let isRepairLaneBlank = !props.hasRatchetState && props.oneTimePublicKey == nil
        if PersonalOutboundRefreshPolicy.shouldSkipRefresh(
            hasOrphanInitiatingMark: hasOrphanMark,
            hasRecoverySession: hasRecovery,
            isRepairLaneBlank: isRepairLaneBlank
        ) {
            logger.log(
                level: .info,
                message: "pqs.recovery.orphanResendProtectsPersonalRefresh peer=\(props.secretName) deviceId=\(props.deviceId) sessionId=\(identity.id)")
            audit(.recovery, "pqs.recovery.orphanResendProtectsPersonalRefresh peer=\(props.secretName) deviceId=\(props.deviceId.uuidString) sessionId=\(identity.id.uuidString)")
            return identity
        }

        logger.log(
            level: .info,
            message: "Refreshing state-less personal SessionIdentity for \(props.secretName) (\(props.deviceId)) before outbound establishment")

        return try await session.resetSessionIdentityForFreshSession(
            secretName: props.secretName,
            deviceId: props.deviceId,
            sendOneTimeIdentities: true,
            reason: "stateLessPersonalOutboundRefresh")
    }
    
    /// Picks the active identity row for a peer device.
    ///
    /// Active `sessionContextId`s are intentionally random, so they are not a recency signal.
    /// If duplicate active rows survive from an older persistence failure, prefer the row whose
    /// key bundle matches the peer's currently advertised device bundle, then prefer initialized
    /// ratchet state, then preserve store order by choosing the last row.
    /// Archived (inactive) identities are excluded so they are never used for outbound encryption.
    func bestSessionIdentity(
        secretName: String,
        deviceId: UUID,
        in identities: [SessionIdentity],
        symmetricKey: SymmetricKey,
        preferredDevice: UserDeviceConfiguration? = nil
    ) async -> SessionIdentity? {
        var candidates: [(identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, index: Int)] = []
        for (index, identity) in identities.enumerated() {
            guard let p = await identity.props(symmetricKey: symmetricKey),
                  p.secretName == secretName,
                  p.deviceId == deviceId,
                  !p.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
            candidates.append((identity, p, index))
        }

        guard candidates.isEmpty == false else { return nil }
        guard candidates.count > 1 else { return candidates[0].identity }

        let preferenceKey = peerDeviceIdentityPreferenceKey(
            secretName: secretName,
            deviceId: deviceId)
        if let preferredId = preferredSessionIdentityIdByPeerDevice[preferenceKey],
           let preferred = candidates.first(where: { $0.identity.id == preferredId }) {
            return preferred.identity
        }

        if let preferredDevice {
            let currentBundleMatches = candidates.filter { candidate in
                candidate.props.longTermPublicKey == preferredDevice.longTermPublicKey &&
                candidate.props.signingPublicKey == preferredDevice.signingPublicKey
            }
            let initializedBundleMatches = currentBundleMatches.filter { $0.props.hasRatchetState }
            if let match = bestCandidatePreservingStoreOrder(
                initializedBundleMatches.isEmpty ? currentBundleMatches : initializedBundleMatches
            ) {
                return match.identity
            }
        }

        let initialized = candidates.filter { $0.props.hasRatchetState }
        if initialized.count == 1 {
            return initialized[0].identity
        }

        let previouslyRekeyed = candidates.filter { $0.props.previousRekey != nil }
        if let newestRekey = previouslyRekeyed.max(by: { lhs, rhs in
            (lhs.props.previousRekey ?? .distantPast) < (rhs.props.previousRekey ?? .distantPast)
        }) {
            return newestRekey.identity
        }

        return bestCandidatePreservingStoreOrder(candidates)?.identity
    }

    /// Outbound lane for a peer device: encrypt with that peer-device’s **active**
    /// session only.
    ///
    /// Orphan remint **inserts** a new initiating session (becomes active) and
    /// encrypts that replay via explicit `recipientIdentity` on the outbound task.
    ///
    /// When an orphan mark and another initialized active both exist (transient):
    /// - **Same-account (personal/sibling):** bind outbound to the orphan recovery
    ///   row so sibling sync does not keep riding the dead maxSkipped lane.
    /// - **Cross-account (peer):** StickyAdvancedRemint — prefer the initialized
    ///   non-orphan active (one-active invariant); remint encrypt uses explicit
    ///   `recipientIdentity`.
    func outboundSessionIdentity(
        secretName: String,
        deviceId: UUID,
        in identities: [SessionIdentity],
        symmetricKey: SymmetricKey,
        session: PQSSession,
        preferredDevice: UserDeviceConfiguration? = nil
    ) async -> SessionIdentity? {
        // Drop a stale orphan mark that no longer names a live active row.
        if let orphanId = await session.orphanResendInitiatingSessionId(
            secretName: secretName,
            deviceId: deviceId
        ) {
            var orphanStillActive = false
            for identity in identities where identity.id == orphanId {
                guard let props = await identity.props(symmetricKey: symmetricKey),
                      props.secretName == secretName,
                      props.deviceId == deviceId,
                      !props.deviceName.hasPrefix(
                        PQSSessionConstants.inactiveSessionDeviceNamePrefix)
                else { continue }
                orphanStillActive = true
                break
            }
            if !orphanStillActive {
                await session.clearOrphanResendInitiatingSession(
                    secretName: secretName,
                    deviceId: deviceId)
            }
        }

        let orphanId = await session.orphanResendInitiatingSessionId(
            secretName: secretName,
            deviceId: deviceId)
        let recoveryId = await session.orphanResendRecoverySessionId(
            secretName: secretName,
            deviceId: deviceId)

        var actives: [(identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, index: Int)] = []
        for (index, identity) in identities.enumerated() {
            guard let p = await identity.props(symmetricKey: symmetricKey),
                  p.secretName == secretName,
                  p.deviceId == deviceId,
                  !p.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            else { continue }
            actives.append((identity, p, index))
        }
        guard !actives.isEmpty else { return nil }

        let localSecretName = await session.sessionContext?.sessionUser.secretName
        let isSameAccount = localSecretName == secretName
        // Prefer initiating mark, else surviving recovery SessionID (mark may clear
        // after StickyAdvancedRemint while recovery row is still the heal lane).
        let recoveryBindId = orphanId ?? recoveryId
        let orphanRow = recoveryBindId.flatMap { id in
            actives.first(where: { $0.identity.id == id })
        }
        let nonOrphanInitialized = actives.filter { candidate in
            guard let recoveryBindId else { return candidate.props.hasRatchetState }
            return candidate.identity.id != recoveryBindId && candidate.props.hasRatchetState
        }
        switch OutboundOrphanSessionSelectionPolicy.decision(
            isSameAccount: isSameAccount,
            hasLiveOrphanRow: orphanRow != nil,
            hasNonOrphanInitialized: !nonOrphanInitialized.isEmpty
        ) {
        case .preferOrphanRecovery:
            if let orphanRow {
                return orphanRow.identity
            }
        case .preferNonOrphanInitialized:
            clearPreferredSessionIdentity(secretName: secretName, deviceId: deviceId)
            if let match = bestCandidatePreservingStoreOrder(nonOrphanInitialized) {
                return match.identity
            }
        case .fallThroughBest:
            break
        }

        return await bestSessionIdentity(
            secretName: secretName,
            deviceId: deviceId,
            in: identities,
            symmetricKey: symmetricKey,
            preferredDevice: preferredDevice)
    }

    /// Single-device control write: resolves one session identity for
    /// `(secretName, deviceId)` and feeds exactly one outbound task. Recipient
    /// `.personalMessage` / `.nickname` is only a label — device scope is the identity.
    /// Must never call `gatherPersonalIdentities` / multi-device fan-out.
    func feedDeviceScopedControlWrite(
        message: CryptoMessage,
        secretName: String,
        deviceId: UUID,
        sharedId: String,
        session: PQSSession,
        forceFreshInitiating: Bool = false
    ) async throws {
        let identity = try await resolveControlDeliverySessionIdentity(
            secretName: secretName,
            deviceId: deviceId,
            session: session,
            forceFreshInitiating: forceFreshInitiating)
        try await feedDeviceScopedControlWrite(
            message: message,
            recipientIdentity: identity,
            sharedId: sharedId,
            session: session)
    }

    /// Device-scoped control write with a pre-resolved recipient identity.
    func feedDeviceScopedControlWrite(
        message: CryptoMessage,
        recipientIdentity: SessionIdentity,
        sharedId: String,
        session: PQSSession
    ) async throws {
        let task = EncryptableTask(
            task: .writeMessage(OutboundTaskMessage(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: UUID(),
                sharedId: sharedId,
                isPersistedOutbound: false
            )),
            priority: .urgent)
        try await enqueue(task, session: session)
    }

    /// Control-plane delivery identity for resend requests and similar urgent frames.
    /// Cross-account: healthy control may ride ``outboundSessionIdentity`` (orphan →
    /// recovery → preferred); a try-all-proven poison lane requires surgical insert.
    /// Same-account: surgical mint once per continuous peer-device episode unless
    /// orphan/recovery already owns the heal lane; later NACKs reuse that episode lane.
    /// Explicit `forceFreshInitiating` (prove-fail rearm) replaces the episode lane once.
    /// Never demote-all; never write preference on try-all failure.
    func resolveControlDeliverySessionIdentity(
        secretName: String,
        deviceId: UUID,
        session: PQSSession,
        forceFreshInitiating: Bool = false
    ) async throws -> SessionIdentity {
        if forceFreshInitiating {
            clearPreferredSessionIdentity(secretName: secretName, deviceId: deviceId)
        }

        let localSecretName = await session.sessionContext?.sessionUser.secretName
        let isSameAccount = localSecretName == secretName
        let liveInitiating = await session.orphanResendInitiatingSessionId(
            secretName: secretName, deviceId: deviceId) != nil
        let liveRecovery = await session.orphanResendRecoverySessionId(
            secretName: secretName, deviceId: deviceId) != nil
        let liveOrphanOrRecovery = liveInitiating || liveRecovery
        let episodeKey = peerDeviceIdentityPreferenceKey(
            secretName: secretName,
            deviceId: deviceId)
        let callerEpisodeGeneration =
            surgicalControlEpisodeGenerationByPeerDevice[episodeKey, default: 0]

        // Orphan/recovery owns the heal lane: ride outbound selection (do not mint).
        var requireSurgical = ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
            isSameAccount: isSameAccount,
            forceFreshInitiating: forceFreshInitiating,
            liveOrphanOrRecovery: liveOrphanOrRecovery)

        // Same continuous episode: reuse the live surgical control identity unless this
        // call is an explicit prove-fail rearm (`forceFreshInitiating`).
        if !forceFreshInitiating, !liveOrphanOrRecovery {
            switch try await surgicalControlEpisodeLane(
                episodeKey: episodeKey,
                secretName: secretName,
                deviceId: deviceId,
                session: session) {
            case .live(let identity):
                auditSurgicalControlEpisodeLaneReuse(
                    identity,
                    secretName: secretName,
                    deviceId: deviceId)
                return identity
            case .stale:
                // The episode already proved normal outbound unsafe. If its owned lane
                // disappeared or became inactive, replace it surgically even for
                // cross-account control; never fall back onto the prior poison active.
                requireSurgical = true
            case .absent:
                break
            }
        }

        // Actor reentrancy: a peer resolve may be suspended inside resetSessionIdentity.
        // Park on an event-driven continuation instead of minting a second blank. Loop
        // after wake-up because another waiter may claim an explicit replacement first.
        while surgicalControlEpisodeMintInFlight.contains(episodeKey) {
            let completion = await waitForSurgicalControlEpisodeMint(episodeKey: episodeKey)
            guard completion.episodeGeneration == callerEpisodeGeneration else {
                // A caller from a newer episode must not inherit an older episode's
                // completion or failure. It will claim/reuse its own generation below.
                continue
            }
            switch completion.result {
            case .success(let sessionIdentityId):
                if !forceFreshInitiating,
                   !liveOrphanOrRecovery,
                   let reused = try await liveSurgicalControlIdentity(
                    sessionIdentityId: sessionIdentityId,
                    secretName: secretName,
                    deviceId: deviceId,
                    session: session)
                {
                    auditSurgicalControlEpisodeLaneReuse(
                        reused,
                        secretName: secretName,
                        deviceId: deviceId)
                    return reused
                }
                // Explicit rearm (or stale lane) falls through to mint a replacement
                // once the prior mint slot is free.
            case .failure(let error):
                throw error
            }
        }

        // Successful inbound decrypt wins over a resolver that began in the prior
        // generation. The now-proven preferred lane is safe for this already-pending
        // control; do not open a new surgical episode solely because this actor resumed.
        if surgicalControlEpisodeGenerationByPeerDevice[episodeKey, default: 0]
            != callerEpisodeGeneration
        {
            requireSurgical = false
        }

        if !requireSurgical {
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            var identities = try await session.cache?.fetchSessionIdentities() ?? []
            let preferredDevice = await currentDeviceConfiguration(
                secretName: secretName,
                deviceId: deviceId,
                session: session)

            if let match = await outboundSessionIdentity(
                secretName: secretName,
                deviceId: deviceId,
                in: identities,
                symmetricKey: symmetricKey,
                session: session,
                preferredDevice: preferredDevice
            ) {
                return match
            }

            _ = try await session.refreshIdentities(secretName: secretName, forceRefresh: true)
            identities = try await session.cache?.fetchSessionIdentities() ?? []
            if let match = await outboundSessionIdentity(
                secretName: secretName,
                deviceId: deviceId,
                in: identities,
                symmetricKey: symmetricKey,
                session: session,
                preferredDevice: preferredDevice
            ) {
                return match
            }
        }

        // Claim the episode mint slot synchronously before awaiting PQSSession so a
        // re-entrant resolver cannot also mint for this peer-device.
        let mintEpisodeGeneration =
            surgicalControlEpisodeGenerationByPeerDevice[episodeKey, default: 0]
        surgicalControlEpisodeMintInFlight.insert(episodeKey)
        do {
            // Surgical insert without demoting other peer-device rows (recovery / honest
            // actives must survive NACK escape). Same-account and proven-poison
            // cross-account hit this for the first NACK of an episode (or an explicit
            // prove-fail rearm).
            let fresh = try await session.resetSessionIdentityForFreshSession(
                secretName: secretName,
                deviceId: deviceId,
                sendOneTimeIdentities: false,
                reason: "resendRequestControlDelivery",
                demotePriorActives: false)
            let episodeIsCurrent =
                surgicalControlEpisodeGenerationByPeerDevice[episodeKey, default: 0]
                    == mintEpisodeGeneration
            if episodeIsCurrent {
                clearPreferredSessionIdentity(secretName: secretName, deviceId: deviceId)
                surgicalControlSessionIdentityIdByPeerDevice[episodeKey] = fresh.id
            } else {
                audit(.recovery, "pqs.recovery.controlDeliveryFreshLaneDetached peer=\(secretName) deviceId=\(deviceId.uuidString) sessionId=\(fresh.id.uuidString) reason=episodeAdvanced")
            }
            finishSurgicalControlEpisodeMint(
                episodeKey: episodeKey,
                completion: SurgicalControlEpisodeMintCompletion(
                    episodeGeneration: mintEpisodeGeneration,
                    result: .success(fresh.id)))
            audit(.recovery, "pqs.recovery.controlDeliveryFreshLane peer=\(secretName) deviceId=\(deviceId.uuidString) sessionId=\(fresh.id.uuidString) sameAccount=\(isSameAccount) surgicalRequired=\(requireSurgical) episodeCurrent=\(episodeIsCurrent)")
            return fresh
        } catch {
            finishSurgicalControlEpisodeMint(
                episodeKey: episodeKey,
                completion: SurgicalControlEpisodeMintCompletion(
                    episodeGeneration: mintEpisodeGeneration,
                    result: .failure(error)))
            throw error
        }
    }

    private enum SurgicalControlEpisodeLane {
        case absent
        case stale
        case live(SessionIdentity)
    }

    /// Validates the currently owned episode lane. If actor reentrancy replaces or
    /// clears the mapping while storage is being read, retry against the new mapping;
    /// never remove a newer lane based on an older lookup.
    private func surgicalControlEpisodeLane(
        episodeKey: String,
        secretName: String,
        deviceId: UUID,
        session: PQSSession
    ) async throws -> SurgicalControlEpisodeLane {
        while true {
            guard let episodeLaneId =
                    surgicalControlSessionIdentityIdByPeerDevice[episodeKey]
            else {
                return .absent
            }
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            let identities = try await session.cache?.fetchSessionIdentities() ?? []

            // Actor reentrancy may have cleared/replaced this map entry while awaiting
            // storage. Retry rather than deleting or returning the superseded identity.
            guard surgicalControlSessionIdentityIdByPeerDevice[episodeKey] == episodeLaneId
            else {
                continue
            }
            guard let live = await liveSurgicalControlIdentity(
                sessionIdentityId: episodeLaneId,
                secretName: secretName,
                deviceId: deviceId,
                in: identities,
                symmetricKey: symmetricKey)
            else {
                surgicalControlSessionIdentityIdByPeerDevice.removeValue(forKey: episodeKey)
                return .stale
            }
            return .live(live)
        }
    }

    private func liveSurgicalControlIdentity(
        sessionIdentityId: UUID,
        secretName: String,
        deviceId: UUID,
        session: PQSSession
    ) async throws -> SessionIdentity? {
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let identities = try await session.cache?.fetchSessionIdentities() ?? []
        return await liveSurgicalControlIdentity(
            sessionIdentityId: sessionIdentityId,
            secretName: secretName,
            deviceId: deviceId,
            in: identities,
            symmetricKey: symmetricKey)
    }

    private func liveSurgicalControlIdentity(
        sessionIdentityId: UUID,
        secretName: String,
        deviceId: UUID,
        in identities: [SessionIdentity],
        symmetricKey: SymmetricKey
    ) async -> SessionIdentity? {
        guard let identity = identities.first(where: { $0.id == sessionIdentityId }),
              let props = await identity.props(symmetricKey: symmetricKey),
              props.secretName == secretName,
              props.deviceId == deviceId,
              !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
        else {
            return nil
        }
        return identity
    }

    private func auditSurgicalControlEpisodeLaneReuse(
        _ identity: SessionIdentity,
        secretName: String,
        deviceId: UUID
    ) {
        audit(.recovery, "pqs.recovery.controlDeliveryEpisodeLaneReused peer=\(secretName) deviceId=\(deviceId.uuidString) sessionId=\(identity.id.uuidString)")
    }

    private func waitForSurgicalControlEpisodeMint(
        episodeKey: String
    ) async -> SurgicalControlEpisodeMintCompletion {
        await withCheckedContinuation { continuation in
            surgicalControlEpisodeMintWaiters[episodeKey, default: []].append(continuation)
        }
    }

    private func finishSurgicalControlEpisodeMint(
        episodeKey: String,
        completion: SurgicalControlEpisodeMintCompletion
    ) {
        surgicalControlEpisodeMintInFlight.remove(episodeKey)
        let waiters = surgicalControlEpisodeMintWaiters.removeValue(forKey: episodeKey) ?? []
        for waiter in waiters {
            waiter.resume(returning: completion)
        }
    }

    /// Re-mints the outbound lane toward a peer device when our initiating
    /// handshake provably never completed.
    ///
    /// An initiating session pins the peer's one-time prekey at mint time and
    /// re-references it on every frame until the peer's first reply advances the
    /// ratchet. If the peer replaced its published batch since the mint (every
    /// missingOneTimeKey episode replaces it) and the retention cap evicted the
    /// old private, the peer fails every one of our frames with
    /// missingOneTimeKey — including the peerRefresh envelopes that are supposed
    /// to heal the lane, so a bilaterally dead pair can never recover on its own.
    /// The identity force-refresh path deliberately skips re-pinning initialized
    /// rows; only a lane reset heals this.
    ///
    /// Trigger and state are both event-derived: callers invoke this when the
    /// peer signals it cannot decrypt us (inbound peerRefresh request) or when we
    /// open a missingOneTimeKey episode for the peer device.
    /// `ratchetReceivedMessagesCount == 0` on an initialized state proves the peer has
    /// never advanced our session; answered lanes are never touched. The repair
    /// mint (`sendOneTimeIdentities: false`) rides long-term + final ML-KEM keys
    /// only, so it cannot re-enter the missingOneTimeKey failure.
    ///
    /// - Parameter forceRemintEvenIfAnswered: same-account `missingOneTimeKeyEpisode`
    ///   only (`UnansweredInitiatingLanePolicy`). Cross-account answered lanes stay
    ///   untouched so we do not remint on every undecryptable NACK.
    func resetUnansweredInitiatingLane(
        peerSecretName: String,
        peerDeviceId: UUID,
        trigger: String,
        forceRemintEvenIfAnswered: Bool = false,
        session: PQSSession
    ) async {
        do {
            guard let localUser = await session.sessionContext?.sessionUser,
                  peerDeviceId != localUser.deviceId
            else { return }
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            let identities = try await session.getSessionIdentities(with: peerSecretName)
            var shouldRemint = false
            for identity in identities {
                guard let props = await identity.props(symmetricKey: symmetricKey),
                      props.deviceId == peerDeviceId,
                      !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix),
                      props.hasRatchetState
                else { continue }
                if props.ratchetReceivedMessagesCount > 0 {
                    // The peer has decrypted us on this session before, so the
                    // handshake is not the failure — unless same-account OTK
                    // evidence forces remint so peerRefresh cannot ride the
                    // answered poison pin (dogfood echo primary↔linked deadlock).
                    if forceRemintEvenIfAnswered {
                        shouldRemint = true
                        break
                    }
                    return
                }
                shouldRemint = true
            }
            guard shouldRemint else { return }
            _ = try await session.resetSessionIdentityForFreshSession(
                secretName: peerSecretName,
                deviceId: peerDeviceId,
                sendOneTimeIdentities: false,
                reason: "unansweredInitiatorReset")
            clearPreferredSessionIdentity(secretName: peerSecretName, deviceId: peerDeviceId)
            audit(.recovery, "pqs.recovery.unansweredInitiatorLaneReset trigger=\(trigger) peer=\(peerSecretName) deviceId=\(peerDeviceId.uuidString) forceAnswered=\(forceRemintEvenIfAnswered)")
        } catch PQSError.invalidDeviceIdentity {
            // The device is absent from the peer's current verified config
            // (re-registered install). There is no live lane to heal.
            logger.log(
                level: .debug,
                message: "Skipping unanswered-initiator reset for dead device \(peerSecretName) (\(peerDeviceId))")
        } catch {
            logger.log(
                level: .warning,
                message: "Failed unanswered-initiator reset for \(peerSecretName) (\(peerDeviceId)): \(error)")
        }
    }

    func peerDeviceIdentityPreferenceKey(
        secretName: String,
        deviceId: UUID
    ) -> String {
        "\(secretName)|\(deviceId.uuidString)"
    }

    /// Clears the continuous NACK-episode surgical escape reservation and owned
    /// control lane for a peer device. Called after successful inbound decrypt;
    /// also available for focused episode lifecycle tests.
    func clearSurgicalControlEpisode(secretName: String, deviceId: UUID) {
        let key = peerDeviceIdentityPreferenceKey(
            secretName: secretName,
            deviceId: deviceId)
        surgicalControlEscapeAttemptedPeerDevices.remove(key)
        surgicalControlSessionIdentityIdByPeerDevice.removeValue(forKey: key)
        surgicalControlEpisodeGenerationByPeerDevice[key, default: 0] &+= 1
    }

    /// Drops a stale preferred-lane pointer after automatic session reset so the
    /// next inbound/outbound selection cannot pin a deleted SessionIdentity id.
    func clearPreferredSessionIdentity(secretName: String, deviceId: UUID) {
        preferredSessionIdentityIdByPeerDevice.removeValue(
            forKey: peerDeviceIdentityPreferenceKey(
                secretName: secretName,
                deviceId: deviceId))
    }

    /// After orphan remint, demote MessageRecord's prior SessionID when it differs
    /// from the new recovery row so `bestSessionIdentity` cannot keep the poison.
    func demotePriorOrphanMessageRecordSession(
        priorSessionId: UUID?,
        newSessionId: UUID,
        secretName: String,
        deviceId: UUID,
        session: PQSSession
    ) async {
        guard let priorSessionId, priorSessionId != newSessionId else { return }
        _ = try? await session.demoteProveFailedActive(
            sessionId: priorSessionId,
            secretName: secretName,
            deviceId: deviceId)
    }

    /// One escape-hatch initiating session (new OTK header) when settled recovery
    /// still fails to prove (peer NACK) — clears the receiver `blankForHeaderExists` trap.
    func performOrphanEscapeRemint(
        serviceKey: String,
        remintsAfterProveFail: Int,
        priorRecordSessionId: UUID?,
        secretName: String,
        deviceId: UUID,
        sharedId: String,
        session: PQSSession
    ) async throws -> SessionIdentity {
        orphanResendRemintsAfterProveFailByServiceKey[serviceKey] = remintsAfterProveFail + 1
        orphanResendRetransportCountByServiceKey[serviceKey] = 0
        orphanResendTransportByServiceKey.removeValue(forKey: serviceKey)
        await session.clearOrphanResendInitiatingSession(
            secretName: secretName,
            deviceId: deviceId)
        let replayIdentity = try await session.resetSessionIdentityForFreshSession(
            secretName: secretName,
            deviceId: deviceId,
            sendOneTimeIdentities: true,
            reason: "orphanResend")
        await session.markOrphanResendInitiatingSession(
            secretName: secretName,
            deviceId: deviceId,
            sessionId: replayIdentity.id)
        clearPreferredSessionIdentity(secretName: secretName, deviceId: deviceId)
        await demotePriorOrphanMessageRecordSession(
            priorSessionId: priorRecordSessionId,
            newSessionId: replayIdentity.id,
            secretName: secretName,
            deviceId: deviceId,
            session: session)
        audit(.recovery, "pqs.recovery.orphanResendRemintAfterProveFail sharedId=\(sharedId) requester=\(secretName) deviceId=\(deviceId.uuidString) newSessionId=\(replayIdentity.id.uuidString)")
        return replayIdentity
    }

    private func bestCandidatePreservingStoreOrder(
        _ candidates: [(identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, index: Int)]
    ) -> (identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, index: Int)? {
        candidates.max(by: { $0.index < $1.index })
    }

    /// Resolves a device bundle for outbound selection from **local** configuration
    /// only. Must not await live `findConfiguration` — that blocked every encrypt on
    /// contact-config REST (dogfood N1 hang / CHILD_DEVICE_2 `-1001`).
    func currentDeviceConfiguration(
        secretName: String,
        deviceId: UUID,
        session: PQSSession
    ) async -> UserDeviceConfiguration? {
        // Only the local account bundle is available without REST. Peer DMs use the
        // SessionIdentity already chosen in chat fan-out; personal sync can use self.
        let mySecret = await session.sessionContext?.sessionUser.secretName
        guard secretName == mySecret,
              let configuration = await session.sessionContext?.activeUserConfiguration,
              let devices = try? configuration.getVerifiedDevices().map({
                  try configuration.deviceWithCurrentKeyBundle($0)
              })
        else {
            return nil
        }
        return devices.first(where: { $0.deviceId == deviceId })
    }
    
    func handleWriteMessage(
        outboundTask: OutboundTaskMessage,
        session: PQSSession
    ) async throws {
        self.session = session
        var outboundTask = outboundTask
        
        guard let sessionContext = await session.sessionContext else {
            throw PQSError.sessionNotInitialized
        }
        
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        if let pendingTransport = pendingOutboundTransport(sharedId: outboundTask.sharedId) {
            try await sendPendingOutboundTransport(
                pendingTransport,
                outboundTask: outboundTask,
                session: session)
            return
        }
        
        var sessionIdentity = try await resolveSessionIdentityForOutbound(
            embeddedRecipient: outboundTask.recipientIdentity,
            session: session,
            databaseSymmetricKey: databaseSymmetricKey
        )
        
        if await session.keyLoadingState == .rotating {
            if let secretName = await sessionIdentity.props(symmetricKey: databaseSymmetricKey)?.secretName,
               let deviceId = await sessionIdentity.props(symmetricKey: databaseSymmetricKey)?.deviceId {
                let refreshedIdentities = try await session.refreshIdentities(secretName: secretName, forceRefresh: true)
                let preferredDevice = await currentDeviceConfiguration(
                    secretName: secretName,
                    deviceId: deviceId,
                    session: session)
                if let refreshed = refreshedIdentities.first(where: { $0.id == sessionIdentity.id }) {
                    sessionIdentity = refreshed
                } else if let refreshed = await bestSessionIdentity(
                    secretName: secretName,
                    deviceId: deviceId,
                    in: refreshedIdentities,
                    symmetricKey: databaseSymmetricKey,
                    preferredDevice: preferredDevice
                ) {
                    sessionIdentity = refreshed
                }
            }
        }
        
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw PQSError.propsError
        }
        
        let results = try await loadKeys(
            props: props,
            sessionContext: sessionContext,
            session: session,
            sessionIdentityId: sessionIdentity.id)
        
        // If we are intially attempting communication with a contact, we need to first send a session identity created message for the contact to delete their one time keys from being used again, the recipient can know what keys via key identities that are sent. This call also needs to send the sender's one time key identities so that the recipient also knows what one times to create their session with. We get the sender's next.
        var transportEvent: TransportEvent?
        if let data = outboundTask.message.transportInfo {
            do {
                let event = try BinaryDecoder().decode(TransportEvent.self, from: data)
                transportEvent = event
                switch event {
                case .sessionReestablishment(let envelope):
                    logger.log(
                        level: .info,
                        message: "Prepared to send session reestablishment: \(envelope.kind.rawValue) intent=\(envelope.intentId?.uuidString ?? "nil") epoch=\(envelope.epoch)")
                case .linkedDeviceReprovisioning(let bundle):
                    logger.log(level: .info, message: "Prepared to send linked-device reprovisioning for target=\(bundle.targetDeviceId.uuidString)")
                case .synchronizeOneTimeKeys(var info):
                    info.senderX25519Id = results.localOneTimePrivateKey?.id.uuidString
                    info.senderMLKEMId = results.localMLKEMPrivateKey.id.uuidString
                    transportEvent = .synchronizeOneTimeKeys(info)
                    let encodedData = try BinaryEncoder().encode(info)
                    await session.setAddingContact(encodedData)
                    outboundTask.message.transportInfo = encodedData
                case .refreshOneTimeKeys:
                    logger.log(level: .info, message: "Prepared to send one-time-key refresh request")
                case .publishedOneTimeKeysReplenished:
                    logger.log(level: .info, message: "Prepared to send one-time-key replenish acknowledgement")
                }
            } catch {}
        }
        let localLTK = (try? Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: sessionContext.sessionUser.deviceKeys.longTermPrivateKey
        ).publicKey.rawRepresentation.base64EncodedString().prefix(10)) ?? "invalidLTK"
        if shouldEmitKeyPayloadLogs {
            logger.log(level: .debug, message: """
                senderInit: recipient=\(props.secretName)\n
                sender=\(await session.sessionContext?.sessionUser.secretName ?? "nil")\n
                localLTK=\(localLTK) localOTK=\(results.localOneTimePrivateKey?.id.uuidString ?? "nil")\n
                localMLKEM=\(results.localMLKEMPrivateKey.id.uuidString)\n
                remoteLTK=\(results.remoteLongTermPublicKey.prefix(10).base64EncodedString())\n
                remoteOTK=\(results.remoteOneTimePublicKey?.id.uuidString ?? "nil")\n
                remoteMLKEM=\(results.remoteMLKEMPublicKey.id.uuidString)
                """)
        }
        
        let outboundSessionIdentityDataBeforeAttempt = sessionIdentity.data
        let persistenceJob = processingOutboundJobBySharedId[outboundTask.sharedId]
        if persistenceJob != nil {
            atomicOutboundPreparationIdentityIds.insert(sessionIdentity.id)
        }
        let signedMessage: SignedRatchetMessage
        do {
            try await ratchetManager.initiateSession(
                sessionIdentity: sessionIdentity,
                sessionSymmetricKey: databaseSymmetricKey,
                remoteKeys: RemoteKeys(
                    longTerm: .init(results.remoteLongTermPublicKey),
                    oneTime: results.remoteOneTimePublicKey,
                    mlKEM: results.remoteMLKEMPublicKey),
                localKeys: LocalKeys(
                    longTerm: .init(sessionContext.sessionUser.deviceKeys.longTermPrivateKey),
                    oneTime: results.localOneTimePrivateKey,
                    mlKEM: results.localMLKEMPrivateKey))

            if let sessionDelegate = await session.sessionDelegate {
                outboundTask.message = sessionDelegate.updateCryptoMessageMetadata(
                    outboundTask.message,
                    sharedMessageId: outboundTask.sharedId)
            }

            let encodedData = try BinaryEncoder().encode(outboundTask.message)
            let ratchetedMessage = try await ratchetManager.encrypt(
                plainText: encodedData,
                sessionId: sessionIdentity.id)
            signedMessage = try await signRatchetMessage(message: ratchetedMessage, session: session)
        } catch {
            atomicOutboundPreparationIdentityIds.remove(sessionIdentity.id)
            // Discard in-place mutations on encrypt failure. Do not remint a
            // new SessionIdentity UUID (`laneReplaced`) — that broke ledger matching.
            try await restoreSessionIdentityData(
                sessionIdentity,
                data: outboundSessionIdentityDataBeforeAttempt,
                session: session,
                reason: "outbound ratchet failed before transport send")
            throw error
        }
        
        // §4.1: mint a unique envelope MessageID per recipient-device encrypt.
        // Logical sharedId stays stable for chat/media/plaintext lookup and resend.
        let envelopeMessageId = EnvelopeMessageIdentityPolicy.mintEnvelopeMessageId().rawValue
        let transportMetadata = SignedRatchetMessageMetadata(
            secretName: props.secretName,
            deviceId: props.deviceId,
            recipient: outboundTask.message.recipient,
            transportMetadata: outboundTask.message.transportInfo,
            sharedMessageId: outboundTask.sharedId,
            envelopeMessageId: envelopeMessageId,
            transportEvent: transportEvent,
            requiresServerAck: outboundTask.isPersistedOutbound)
        if let persistenceJob {
            guard let cache = await session.cache,
                  var jobProps = await persistenceJob.props(symmetricKey: databaseSymmetricKey) else {
                atomicOutboundPreparationIdentityIds.remove(sessionIdentity.id)
                try await restoreSessionIdentityData(
                    sessionIdentity,
                    data: outboundSessionIdentityDataBeforeAttempt,
                    session: session,
                    reason: "prepared outbound job unavailable")
                throw PQSError.databaseNotInitialized
            }
            let prepared = JobModel.PreparedOutbound(
                signedMessage: signedMessage,
                secretName: transportMetadata.secretName,
                deviceId: transportMetadata.deviceId,
                recipient: transportMetadata.recipient,
                transportMetadata: transportMetadata.transportMetadata,
                sharedMessageId: transportMetadata.sharedMessageId,
                envelopeMessageId: transportMetadata.envelopeMessageId,
                transportEvent: transportMetadata.transportEvent,
                requiresServerAck: transportMetadata.requiresServerAck,
                sessionIdentityId: sessionIdentity.id,
                needsRemoteDeletion: results.needsRemoteDeletion,
                x25519OneTimeKeyId: results.localOneTimePrivateKey?.id.uuidString,
                mlKEMOneTimeKeyId: results.localMLKEMPrivateKey.id.uuidString)
            jobProps.preparedOutbound = prepared
            do {
                _ = try await persistenceJob.updateProps(
                    symmetricKey: databaseSymmetricKey,
                    props: jobProps)
                try await cache.commitPreparedOutbound(
                    sessionIdentity: sessionIdentity,
                    job: persistenceJob)
            } catch {
                atomicOutboundPreparationIdentityIds.remove(sessionIdentity.id)
                jobProps.preparedOutbound = nil
                _ = try? await persistenceJob.updateProps(
                    symmetricKey: databaseSymmetricKey,
                    props: jobProps)
                try await restoreSessionIdentityData(
                    sessionIdentity,
                    data: outboundSessionIdentityDataBeforeAttempt,
                    session: session,
                    reason: "atomic prepared outbound commit failed")
                throw error
            }
        }
        atomicOutboundPreparationIdentityIds.remove(sessionIdentity.id)
        let shouldRememberPendingTransport = shouldRememberPendingOutboundTransport(outboundTask.message)
        if shouldRememberPendingTransport {
            rememberPendingOutboundTransport(
                sharedId: outboundTask.sharedId,
                message: signedMessage,
                metadata: transportMetadata,
                sessionIdentityId: sessionIdentity.id,
                needsRemoteDeletion: results.needsRemoteDeletion,
                x25519OneTimeKeyId: results.localOneTimePrivateKey?.id.uuidString,
                mlKEMOneTimeKeyId: results.localMLKEMPrivateKey.id.uuidString)
        }
        
        guard let transportDelegate = await session.transportDelegate else {
            audit(.send, "pqs.send.transportMissing sharedId=\(outboundTask.sharedId)", level: .error)
            throw PQSError.transportNotInitialized
        }
        
        try await transportDelegate.sendMessage(signedMessage, metadata: transportMetadata)
        
        audit(.send, "pqs.send.deviceTransportOk sharedId=\(outboundTask.sharedId) envelopeMessageId=\(envelopeMessageId) recipientSecret=\(props.secretName) recipientDeviceId=\(props.deviceId.uuidString) sessionIdentityId=\(sessionIdentity.id.uuidString) recipient=\(outboundTask.message.recipient.auditRecipientTag) persisted=\(outboundTask.isPersistedOutbound)",
            level: .info)
        
        // MessageRecord-lite: envelope id + logical sharedId + encrypting SessionID.
        let priorAttempt = await session.outboundDeviceSendRecord(
            sharedId: outboundTask.sharedId,
            recipientDeviceId: props.deviceId)?.resendAttempt ?? -1
        let isOrphanReplayForAttempt =
            await session.isOrphanResendInitiatingSession(
                secretName: props.secretName,
                deviceId: props.deviceId,
                sessionId: sessionIdentity.id)
            || pendingResendReplayBySharedId[outboundTask.sharedId] != nil
        await session.recordOutboundDeviceSend(
            sharedId: outboundTask.sharedId,
            recipientSecretName: props.secretName,
            recipientDeviceId: props.deviceId,
            sessionIdentityId: sessionIdentity.id,
            envelopeMessageId: envelopeMessageId,
            resendAttempt: isOrphanReplayForAttempt ? max(0, priorAttempt) + 1 : 0)
        let isOrphanReplay = isOrphanReplayForAttempt
        if isOrphanReplay {
            audit(.recovery, "pqs.recovery.messageRecordSessionId=\(sessionIdentity.id.uuidString) sharedId=\(outboundTask.sharedId) recipientDeviceId=\(props.deviceId.uuidString)")
            rememberOrphanResendTransport(
                requestingDeviceId: props.deviceId,
                sharedId: outboundTask.sharedId,
                message: signedMessage,
                metadata: transportMetadata,
                sessionIdentityId: sessionIdentity.id,
                needsRemoteDeletion: false,
                x25519OneTimeKeyId: nil,
                mlKEMOneTimeKeyId: results.localMLKEMPrivateKey.id.uuidString)
        }
        logRecoveryTransportSendSuccess(transportEvent, sharedId: outboundTask.sharedId)
        await noteResendReplayTransported(sharedId: outboundTask.sharedId)
        if shouldRememberPendingTransport {
            pendingOutboundTransportBySharedId.removeValue(forKey: outboundTask.sharedId)
        }
        await completeResponderPeerRefreshIfNeeded(
            transportEvent,
            peerSecretName: props.secretName,
            peerDeviceId: props.deviceId,
            session: session)

        await rememberRecentOutboundReplayIfNeeded(outboundTask, session: session)

        if outboundTask.isPersistedOutbound || transportMetadata.requiresServerAck {
            await registerUnackedServerAccept(
                pending: PendingOutboundTransport(
                    message: signedMessage,
                    metadata: transportMetadata,
                    sessionIdentityId: sessionIdentity.id,
                    needsRemoteDeletion: results.needsRemoteDeletion,
                    x25519OneTimeKeyId: results.localOneTimePrivateKey?.id.uuidString,
                    mlKEMOneTimeKeyId: results.localMLKEMPrivateKey.id.uuidString,
                    createdAt: Date()),
                localId: outboundTask.localId,
                sharedId: outboundTask.sharedId,
                isPersistedOutbound: outboundTask.isPersistedOutbound,
                session: session)
        }
        // Ephemeral / control traffic without accept-ack: no local delivery row to advance.
        
        // Perform remote key deletion only after a successful send
        if results.needsRemoteDeletion {
            try await removeKeys(
                session: session,
                x25519Id: results.localOneTimePrivateKey?.id.uuidString,
                mlKEMId: results.localMLKEMPrivateKey.id.uuidString)
        }
    }

    func completeResponderPeerRefreshIfNeeded(
        _ event: TransportEvent?,
        peerSecretName: String,
        peerDeviceId: UUID,
        session: PQSSession
    ) async {
        guard case .sessionReestablishment(let envelope) = event,
              envelope.kind == .peerRefresh,
              envelope.isResponse
        else {
            return
        }

        let pending = await session.takePendingResendsAfterReestablishment(
            sender: peerSecretName,
            deviceId: peerDeviceId)
        await session.endReestablishmentEpisode(
            sender: peerSecretName,
            deviceId: peerDeviceId)
        await sendDeferredResendRequests(
            pending,
            session: session,
            reason: "peerRefresh response transported")
        logger.log(
            level: .info,
            message: "Completed responder peerRefresh on device lane peer=\(peerSecretName) deviceId=\(peerDeviceId)")
    }
    
}

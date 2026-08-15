//
//  TaskProcessor+RatchetInbound.swift
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

/// Inbound Double Ratchet path: `handleStreamMessage` verification and
/// decryption, recipient initialization, and decoded-message routing.
extension MessagePipeline {
    // MARK: - Inbound Message Handling
    
    /// Handles streaming a message and performing the necessary ratchet operations.
    ///
    /// This method implements the recipient side of the Double Ratchet protocol for inbound
    /// messages. It verifies message signatures, initializes ratchet state, decrypts messages,
    /// and processes the decrypted content. The method handles both initial message setup
    /// and subsequent message decryption with proper key management.
    ///
    /// ## Decryption Process
    /// 1. Verifies message signature and extracts ratchet message
    /// 2. Initializes ratchet state for recipient
    /// 3. Decrypts message using ratchet decryption
    /// 4. Processes decrypted message content
    /// 5. Removes used keys and updates session state
    /// 6. Handles message persistence and delivery
    ///
    /// ## Message Processing
    /// - Messages are verified for authenticity before processing
    /// - Decrypted content is validated and routed appropriately
    /// - Session state is updated to reflect new message
    /// - Used keys are cleaned up to maintain forward secrecy
    ///
    /// ## Security Considerations
    /// - Message signatures are verified to prevent impersonation
    /// - Ratchet state prevents replay attacks
    /// - Keys are validated before use to prevent attacks
    /// - Failed decryption attempts are handled gracefully
    ///
    /// - Parameters:
    ///   - inboundTask: The inbound task message to be processed. Contains the
    ///                  encrypted message and sender information.
    ///   - session: The current crypto session providing context and keys.
    /// - Throws: An error if the message handling fails due to invalid signatures,
    ///           missing keys, or cryptographic errors.
    func handleStreamMessage(
        inboundTask: InboundTaskMessage,
        session: PQSSession
    ) async throws {
        // T13: accepted-envelope ledger covers non-persisted successes (nudgeLocal).
        // Re-emit spool ACK; never re-enter ratchet / NACK / remint.
        if try await session.hasAcceptedEnvelope(
            senderSecretName: inboundTask.senderSecretName,
            senderDeviceId: inboundTask.senderDeviceId,
            envelopeMessageId: inboundTask.sharedMessageId
        ) {
            audit(.recovery, "pqs.recovery.redeliveryDropped reason=alreadyAccepted sharedId=\(inboundTask.sharedMessageId) logical=\(inboundTask.resolvedLogicalSharedId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
            let acceptedSharedId = inboundTask.sharedMessageId
            let acceptedDelegate = await session.sessionDelegate
            await session.scheduleTransportProtocolWork {
                await acceptedDelegate?.inboundCiphertextAccepted(sharedMessageId: acceptedSharedId)
            }
            return
        }

        // Redelivery ingress guard: offline queues redeliver un-ACKed frames on
        // every reconnect. Lookup by logical id (chat row) with sender-device match.
        // Waiting/failed recovery placeholders must NOT short-circuit — orphan
        // resend heals by decrypting into that same sharedId.
        let logicalLookupId = inboundTask.resolvedLogicalSharedId
        if let existing = try await session.cache?.fetchMessageIfExists(sharedId: logicalLookupId) {
            let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
            if let existingProps = await existing.props(symmetricKey: databaseSymmetricKey),
               existingProps.senderSecretName == inboundTask.senderSecretName,
               existingProps.senderDeviceId == inboundTask.senderDeviceId,
               !Self.isReplaceableInboundRecoveryPlaceholder(existingProps)
            {
                audit(.recovery, "pqs.recovery.redeliveryDropped reason=alreadyPersisted sharedId=\(inboundTask.sharedMessageId) logical=\(logicalLookupId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
                try await session.markEnvelopeAccepted(
                    senderSecretName: inboundTask.senderSecretName,
                    senderDeviceId: inboundTask.senderDeviceId,
                    envelopeMessageId: inboundTask.sharedMessageId,
                    logicalSharedId: logicalLookupId)
                let acceptedSharedId = inboundTask.sharedMessageId
                let acceptedDelegate = await session.sessionDelegate
                await session.scheduleTransportProtocolWork {
                    await acceptedDelegate?.inboundCiphertextAccepted(sharedMessageId: acceptedSharedId)
                }
                return
            }
        }

        let verificationResult = try await verifyEncryptedMessage(session: session, inboundTask: inboundTask)
        let rollbackSymmetricKey = try await session.getDatabaseSymmetricKey()
        let rollbackPeerIdentities = try await session.cache?.fetchSessionIdentities().asyncFilter { identity in
            guard let props = await identity.props(symmetricKey: rollbackSymmetricKey) else {
                return false
            }
            return props.secretName == inboundTask.senderSecretName
                && props.deviceId == inboundTask.senderDeviceId
        } ?? []
        let rollbackIdentityData = Dictionary(
            uniqueKeysWithValues: rollbackPeerIdentities.map { ($0.id, $0.data) })
        
        do {
            // Inbound decrypt: try the preferred/current session, then other
            // actives, then inactive sessions. Whichever decrypts becomes current
            // (activate = promote inactive / demote sibling actives).
            let preferredSessionIdentity = verificationResult.sessionIdentity
            let preferredSessionIdentityDataBeforeAttempt = preferredSessionIdentity.data
            var decryptionSessionIdentity = preferredSessionIdentity
            var decryptedData: Data
            do {
                try await initializeRecipient(
                    sessionIdentity: preferredSessionIdentity,
                    session: session,
                    ratchetMessage: verificationResult.ratchetMessage)
                
                decryptedData = try await ratchetManager.decrypt(
                    verificationResult.ratchetMessage,
                    sessionId: preferredSessionIdentity.id)
            } catch {
                let preferredError = error
                try await restoreSessionIdentityData(
                    preferredSessionIdentity,
                    data: preferredSessionIdentityDataBeforeAttempt,
                    session: session,
                    reason: "preferred inbound decrypt failed before multi-session fallback")
                let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
                let activeIdentities = try await session.getSessionIdentities(
                    with: inboundTask.senderSecretName)
                let alternateActiveIdentities = await activeIdentities.asyncFilter { identity in
                    guard identity.id != preferredSessionIdentity.id,
                          let props = await identity.props(symmetricKey: databaseSymmetricKey)
                    else {
                        return false
                    }
                    return props.deviceId == inboundTask.senderDeviceId
                }
                // Inbound try-all: stateful Active → Archives → state-less Active.
                // Blank PQXDH runs only on state-less rows already in (or ensured into)
                // the device record — not a gated post-failure matching mint.
                //
                // activeFirstInboundPass: try actives + state-less first. Archive walk is
                // deferred to a `.background` job via deferArchivedInboundFallback so
                // fresher `.urgent` ciphertext is not HOL-blocked on the single consumer.
                let statefulAlternates = await alternateActiveIdentities.asyncFilter { identity in
                    (await identity.props(symmetricKey: databaseSymmetricKey))?.hasRatchetState == true
                }
                let stateLessAlternates = await alternateActiveIdentities.asyncFilter { identity in
                    (await identity.props(symmetricKey: databaseSymmetricKey))?.hasRatchetState != true
                }
                let archivedIdentities = try await session.fetchArchivedSessionIdentities(
                    secretName: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)
                let archiveToken = ArchivedInboundFallbackToken(
                    senderSecretName: inboundTask.senderSecretName,
                    senderDeviceId: inboundTask.senderDeviceId,
                    envelopeMessageId: inboundTask.sharedMessageId,
                    fingerprint: PQSSession.nackFrameFingerprint(for: inboundTask))
                let includeArchivedFallback =
                    archivedInboundFallbackPasses.contains(archiveToken.storageKey)
                    || archivedInboundFallbackPasses.contains(inboundTask.sharedMessageId)
                if includeArchivedFallback {
                    archivedInboundFallbackPasses.remove(archiveToken.storageKey)
                    archivedInboundFallbackPasses.remove(inboundTask.sharedMessageId)
                }
                // Mark exhausted when this pass actually walks archives (success or
                // total failure). Prevents re-defer on the same ciphertext.
                let shouldMarkArchivePassExhausted = includeArchivedFallback

                var fallbackData: Data?
                // Per-candidate failure classes for the rollback audit; without this the
                // try-all loop swallows every error and only the preferred error surfaces.
                var attemptFailures: [String] = [
                    "preferred:\(preferredSessionIdentity.id.uuidString.prefix(8)):\(preferredError)"
                ]

                func tryDecryptCandidates(
                    _ candidates: [(identity: SessionIdentity, kind: String)]
                ) async {
                    for candidate in candidates {
                        let fallbackIdentity = candidate.identity
                        let fallbackDataBeforeAttempt = fallbackIdentity.data
                        do {
                            try await initializeRecipient(
                                sessionIdentity: fallbackIdentity,
                                session: session,
                                ratchetMessage: verificationResult.ratchetMessage)

                            let data = try await ratchetManager.decrypt(
                                verificationResult.ratchetMessage,
                                sessionId: fallbackIdentity.id)
                            logger.log(
                                level: .info,
                                message: "\(candidate.kind) identity fallback succeeded for \(inboundTask.senderSecretName) (\(inboundTask.senderDeviceId))")
                            decryptionSessionIdentity = fallbackIdentity
                            fallbackData = data
                            return
                        } catch {
                            attemptFailures.append(
                                "\(candidate.kind):\(fallbackIdentity.id.uuidString.prefix(8)):\(error)")
                            try? await restoreSessionIdentityData(
                                fallbackIdentity,
                                data: fallbackDataBeforeAttempt,
                                session: session,
                                reason: "inbound identity fallback attempt failed")
                        }
                    }
                }

                let inboundHeader = verificationResult.ratchetMessage.header
                let archivedBlanks = await archivedIdentities.asyncFilter { identity in
                    (await identity.props(symmetricKey: databaseSymmetricKey))?.hasRatchetState != true
                }
                // Active-first never walks full archives, but blankForHeaderExists
                // counts archived blanks. Include the single header-matched archived
                // blank in the active pass so demoted blanks are not invisible until
                // a (possibly exhausted) archive defer.
                let headerMatchedArchivedBlank = await archivedBlanks.asyncFirst(where: { identity in
                    guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else {
                        return false
                    }
                    return props.longTermPublicKey == inboundHeader.remoteLongTermPublicKey
                        && props.oneTimePublicKey?.id == inboundHeader.remoteOneTimePublicKey?.id
                })

                if includeArchivedFallback {
                    // Background pass: archives only (actives already failed).
                    await tryDecryptCandidates(
                        archivedIdentities.map { (identity: $0, kind: "archived") })
                } else {
                    // activeFirstInboundPass — decryptInboundActiveOnly candidates,
                    // plus header-matched archived blank when policy allows.
                    var activeFirstCandidates =
                        statefulAlternates.map { (identity: $0, kind: "active") }
                        + stateLessAlternates.map { (identity: $0, kind: "stateLess") }
                    if let matched = headerMatchedArchivedBlank,
                       InboundInitiatingSlotPolicy.shouldTryArchivedHeaderMatchBeforeEnsureSkip(
                           blankForHeaderExists: true,
                           matchedIsArchived: true,
                           includeArchivedFallback: false)
                    {
                        activeFirstCandidates.append((identity: matched, kind: "archivedHeaderMatch"))
                    }
                    await tryDecryptCandidates(activeFirstCandidates)
                }

                // Every existing row failed. The receiver must always be able to
                // build the matching session from the initiating frame itself, so
                // ensure a blank from this frame's header even when stale blanks
                // exist — a blank minted from older key material can never PQXDH
                // this frame and must not block recovery. Dedupe on the header's
                // key material (remote LTK + OTK id): if a blank for this exact
                // header already exists (it just failed in try-all above), a fresh
                // one would fail identically, so redelivered copies don't mint storms.
                if fallbackData == nil, !includeArchivedFallback {
                    if let preferredProps = await preferredSessionIdentity.props(
                        symmetricKey: databaseSymmetricKey)
                    {
                        let header = inboundHeader
                        var blankRows = stateLessAlternates
                        if !preferredProps.hasRatchetState {
                            blankRows.append(preferredSessionIdentity)
                        }
                        // Archived blanks count too: a prior ensured blank demoted by a
                        // sibling's activation is still in the try-all set above, so a
                        // fresh mint for the same header would fail identically. Without
                        // this, every activate-then-fail cycle mints a new blank whose
                        // archival evicts a real stateful snapshot at the retention cap.
                        blankRows.append(contentsOf: archivedBlanks)
                        let blankForHeaderExists = await blankRows.asyncFirst(where: { identity in
                            guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else {
                                return false
                            }
                            return props.longTermPublicKey == header.remoteLongTermPublicKey
                                && props.oneTimePublicKey?.id == header.remoteOneTimePublicKey?.id
                        }) != nil
                        if !InboundInitiatingSlotPolicy.shouldEnsureInboundBlank(
                            blankForHeaderExists: blankForHeaderExists)
                        {
                            audit(.recovery, "pqs.recovery.inboundInitiatingSlotEnsureSkipped reason=blankForHeaderExists peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
                        } else {
                            do {
                                let ensured = try await session.ensureInboundInitiatingSessionIdentity(
                                    secretName: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId,
                                    longTermPublicKey: header.remoteLongTermPublicKey,
                                    signingPublicKey: preferredProps.signingPublicKey,
                                    oneTimePublicKey: header.remoteOneTimePublicKey,
                                    mlKEMPublicKey: header.remoteMLKEMPublicKey,
                                    deviceNameHint: preferredProps.deviceName)
                                audit(.recovery, "pqs.recovery.inboundInitiatingSlotEnsured peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) sessionId=\(ensured.id.uuidString)")
                                let ensuredDataBeforeAttempt = ensured.data
                                do {
                                    try await initializeRecipient(
                                        sessionIdentity: ensured,
                                        session: session,
                                        ratchetMessage: verificationResult.ratchetMessage)
                                    let data = try await ratchetManager.decrypt(
                                        verificationResult.ratchetMessage,
                                        sessionId: ensured.id)
                                    logger.log(
                                        level: .info,
                                        message: "stateLess identity fallback succeeded for \(inboundTask.senderSecretName) (\(inboundTask.senderDeviceId))")
                                    decryptionSessionIdentity = ensured
                                    fallbackData = data
                                } catch {
                                    attemptFailures.append(
                                        "ensured:\(ensured.id.uuidString.prefix(8)):\(error)")
                                    try? await restoreSessionIdentityData(
                                        ensured,
                                        data: ensuredDataBeforeAttempt,
                                        session: session,
                                        reason: "inbound identity fallback attempt failed")
                                }
                            } catch {
                                logger.log(
                                    level: .warning,
                                    message: "pqs.recovery.inboundInitiatingSlotEnsureFailed peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) error=\(error)")
                                audit(.recovery, "pqs.recovery.inboundInitiatingSlotEnsureFailed peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) error=\(error)")
                            }
                        }
                    }
                }

                guard let data = fallbackData else {
                    let frameFingerprint = PQSSession.nackFrameFingerprint(for: inboundTask)
                    if shouldMarkArchivePassExhausted {
                        markArchivedInboundFallbackExhausted(
                            sharedId: inboundTask.sharedMessageId,
                            sender: inboundTask.senderSecretName,
                            deviceId: inboundTask.senderDeviceId,
                            fingerprint: frameFingerprint)
                    }
                    // Active-first miss with archives remaining: defer archive try-all
                    // to a background job so urgent inbound can proceed.
                    if !includeArchivedFallback, !archivedIdentities.isEmpty {
                        await deferArchivedInboundFallback(
                            inboundTask: inboundTask,
                            session: session)
                    }
                    // Inbound decrypt: no session decrypted — discard mutations and abort.
                    try await restoreSessionIdentityData(
                        preferredSessionIdentity,
                        data: preferredSessionIdentityDataBeforeAttempt,
                        session: session,
                        reason: "active and archived inbound decrypt attempts failed")
                    audit(.recovery, "pqs.recovery.laneRolledBack reason=active and archived inbound decrypt attempts failed peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) attempts=[\(attemptFailures.joined(separator: "; "))]")
                    // Do NOT write the failed try-first id into the preference map here.
                    // Dogfood 2026-07-25: that armed preferredFailedInTryAll on every
                    // poison redelivery → demoteProveFailedActive walked unique session
                    // ids (nudge primary: 92 demotes / 4k blankForHeader skips against
                    // linked). Preference stays success-only; demote remains rearm-gated.
                    throw preferredError
                }
                if shouldMarkArchivePassExhausted {
                    markArchivedInboundFallbackExhausted(
                        sharedId: inboundTask.sharedMessageId,
                        sender: inboundTask.senderSecretName,
                        deviceId: inboundTask.senderDeviceId,
                        fingerprint: PQSSession.nackFrameFingerprint(for: inboundTask))
                }
                decryptedData = data
            }

            // Strict mode clears the state copy of the OTK after authenticated
            // decrypt, but DRK 4.0.0 lanes embed and re-use that key in every
            // epoch re-key, so it must be written back or the peer's chains
            // desync. Re-run recipient init while the private half is still in
            // the pool: `respondToSession` sees a local-key change and writes
            // the OTK back without a sending DH ratchet. Once the key is
            // deleted (lane superseded) this is a no-op, so replays fail fast.
            await restoreDeferredOneTimeKeyIntoRatchetState(
                sessionIdentity: decryptionSessionIdentity,
                session: session,
                ratchetMessage: verificationResult.ratchetMessage)

#if DEBUG
            if let transform = await session._testDecryptedPayloadTransform {
                decryptedData = transform(decryptedData)
            }
#endif
            
            guard !decryptedData.isEmpty else {
                throw PQSError.sessionDecryptionError
            }
            let decodedMessage: CryptoMessage
            do {
                decodedMessage = try BinaryDecoder().decode(CryptoMessage.self, from: decryptedData)
            } catch {
                throw PQSError.sessionDecryptionError
            }

            var canSaveMessage = true
            
            if let sessionDelegate = await session.sessionDelegate {
                canSaveMessage = await sessionDelegate.processMessage(
                    decodedMessage,
                    senderSecretName: inboundTask.senderSecretName,
                    senderDeviceId: inboundTask.senderDeviceId)
            }

            if let transportInfo = decodedMessage.transportInfo,
               let event = try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo) {
                var processedReestablishment: SessionReestablishmentEnvelope?
                do {
                    switch event {
                    case .sessionReestablishment(let envelope):
                        canSaveMessage = false

                        guard let context = await session.sessionContext else {
                            throw PQSError.sessionNotInitialized
                        }
                        if let targetDeviceId = envelope.targetDeviceId,
                           targetDeviceId != context.sessionUser.deviceId {
                            logger.log(
                                level: .info,
                                message: "Ignoring peerRefresh for another local device target=\(targetDeviceId) local=\(context.sessionUser.deviceId)")
                            decryptionSessionIdentity = try await finalizeAcceptedInbound(
                                decryptionSessionIdentity,
                                inboundTask: inboundTask,
                                session: session,
                                headerOneTimeKeyId: verificationResult.ratchetMessage.header.oneTimeKeyId,
                                headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId)
                            return
                        }

                        // Decrypt path already activated the proven session (inbound decrypt).

                        // Receiver-side coalescing: drop duplicates and stale-epoch replays from
                        // an offline mailbox before any expensive work or delegate dispatch.
                        let dedupDecision = await session.recordReceivedSessionReestablishment(
                            envelope: envelope,
                            senderDeviceId: inboundTask.senderDeviceId)

                        switch dedupDecision {
                        case .skipDuplicate:
                            logger.log(
                                level: .info,
                                message: "[control-event] coalesced duplicate kind=\(envelope.kind.rawValue) sender=\(inboundTask.senderDeviceId) intent=\(envelope.intentId?.uuidString ?? "nil") epoch=\(envelope.epoch)"
                            )
                            decryptionSessionIdentity = try await finalizeAcceptedInbound(
                                decryptionSessionIdentity,
                                inboundTask: inboundTask,
                                session: session,
                                headerOneTimeKeyId: verificationResult.ratchetMessage.header.oneTimeKeyId,
                                headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId)
                            return
                        case .skipStale:
                            logger.log(
                                level: .info,
                                message: "[control-event] dropping stale kind=\(envelope.kind.rawValue) sender=\(inboundTask.senderDeviceId) epoch=\(envelope.epoch)"
                            )
                            decryptionSessionIdentity = try await finalizeAcceptedInbound(
                                decryptionSessionIdentity,
                                inboundTask: inboundTask,
                                session: session,
                                headerOneTimeKeyId: verificationResult.ratchetMessage.header.oneTimeKeyId,
                                headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId)
                            return
                        case .process:
                            processedReestablishment = envelope
                            break
                        }

                        let kind = envelope.kind
                        let disposition = try sessionReestablishmentDisposition(
                            for: kind,
                            inboundTask: inboundTask,
                            decodedMessage: decodedMessage,
                            context: context)
                        var shouldSendRefreshResponse = false
                        switch disposition {
                        case .ignore:
                            logger.log(level: .warning, message: "Ignoring unauthorized session reestablishment control event")
                        case .refreshOnly:
                            shouldSendRefreshResponse = kind == .peerRefresh && !envelope.isResponse
                            break
                        case .rotateCurrentDevice:
                            // Sync local activeUserConfiguration before checking signing-key
                            // agreement; the post-disposition refresh below cannot cover this
                            // because the check needs to run on fresh state.
                            if await session.shouldForceIdentityRefresh(secretName: inboundTask.senderSecretName) {
                                _ = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
                            }
                            if await session.localSigningKeyMatchesActiveConfiguration() {
                                try await performPendingLinkedDeviceRepair(session: session)
                            } else {
                                await session.setPendingLinkedDeviceRepair(true)
                                logger.log(level: .info, message: "Linked-device repair requested; waiting for reprovisioning bundle before rotating")
                            }
                        case .compromiseObserved:
                            logger.log(
                                level: .error,
                                message: "Linked device reported possible compromise; notifying delegate (intent=\(envelope.intentId?.uuidString ?? "nil") epoch=\(envelope.epoch))")

                            await session.sessionDelegate?.linkedDeviceReportedPotentialCompromise(
                                deviceId: inboundTask.senderDeviceId,
                                intentId: envelope.intentId)
                        }

                        // Throttled refresh after the disposition. Without this, a 30-message
                        // backlog from the same sender would each force-refresh identities.
                        if await session.shouldForceIdentityRefresh(secretName: inboundTask.senderSecretName) {
                            _ = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
                            logger.log(level: .info, message: "Received Session Reestablishment, refreshed session identities")
                        } else {
                            logger.log(level: .debug, message: "[control-event] coalesced redundant identity refresh for sender=\(inboundTask.senderSecretName)")
                        }

                        if kind == .peerRefresh {
                            if envelope.isResponse {
                                guard await session.isExpectedPeerRefreshResponse(
                                    sender: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId,
                                    intentId: envelope.intentId)
                                else {
                                    logger.log(
                                        level: .info,
                                        message: "Ignoring unmatched peerRefresh response sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) intent=\(envelope.intentId?.uuidString ?? "nil")")
                                    decryptionSessionIdentity = try await finalizeAcceptedInbound(
                                        decryptionSessionIdentity,
                                        inboundTask: inboundTask,
                                        session: session,
                                        headerOneTimeKeyId: verificationResult.ratchetMessage.header.oneTimeKeyId,
                                        headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId)
                                    return
                                }
                                // Keep the proven lane after a correlated peerRefresh
                                // response. Resetting again would immediately diverge.
                                await session.markReconciliationAttempt(
                                    sender: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId,
                                    flow: .inbound)
                                let pending = await session.takePendingResendsAfterReestablishment(
                                    sender: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId)
                                await session.endReestablishmentEpisode(
                                    sender: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId)
                                await sendDeferredResendRequests(
                                    pending,
                                    session: session,
                                    reason: "peerRefresh response")
                            } else if shouldSendRefreshResponse {
                                // The peer explicitly cannot decrypt our frames. If our
                                // outbound lane toward that device is initialized but
                                // unanswered, its pinned one-time prekey is dead and
                                // every send re-references it — reset before responding
                                // so the resends the peer drains after our response ride
                                // a lane it can actually decrypt.
                                await resetUnansweredInitiatingLane(
                                    peerSecretName: inboundTask.senderSecretName,
                                    peerDeviceId: inboundTask.senderDeviceId,
                                    trigger: "peerRefreshRequest",
                                    session: session)
                                let isSelf = inboundTask.senderSecretName == context.sessionUser.secretName
                                let recipient: MessageRecipient = isSelf ? .personalMessage : .nickname(inboundTask.senderSecretName)
                                do {
                                    _ = try await session.emitSessionReestablishmentResponse(
                                        kind: .peerRefresh,
                                        recipient: recipient,
                                        respondingTo: envelope,
                                        targetDeviceId: inboundTask.senderDeviceId)
                                } catch {
                                    await session.forgetReceivedSessionReestablishment(
                                        envelope: envelope,
                                        senderDeviceId: inboundTask.senderDeviceId)
                                    logger.log(level: .warning, message: "Failed to emit peerRefresh response: \(error)")
                                }
                            }
                        }
                    case .linkedDeviceReprovisioning(let bundle):
                        canSaveMessage = false
                        guard let context = await session.sessionContext else {
                            throw PQSError.sessionNotInitialized
                        }
                        guard try shouldAcceptLinkedDeviceReprovisioning(
                            bundle: bundle,
                            inboundTask: inboundTask,
                            decodedMessage: decodedMessage,
                            context: context
                        ) else {
                            logger.log(level: .warning, message: "Ignoring unauthorized linked-device reprovisioning bundle")
                            decryptionSessionIdentity = try await finalizeAcceptedInbound(
                                decryptionSessionIdentity,
                                inboundTask: inboundTask,
                                session: session,
                                headerOneTimeKeyId: verificationResult.ratchetMessage.header.oneTimeKeyId,
                                headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId)
                            return
                        }
                        try await session.installLinkedDeviceReprovisioningBundle(bundle)
                        _ = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
                        if await session.hasPendingLinkedDeviceRepair() {
                            try await performPendingLinkedDeviceRepair(session: session)
                        } else {
                            logger.log(level: .info, message: "Installed linked-device reprovisioning bundle; awaiting repair signal")
                        }
                        
                    case .synchronizeOneTimeKeys(let info):
                        try await removeKeys(
                            session: session,
                            x25519Id: info.recipientX25519Id,
                            mlKEMId: info.recipientMLKEMId)
                        canSaveMessage = false
                    case .refreshOneTimeKeys:
                        canSaveMessage = false
                        logger.log(
                            level: .info,
                            message: "Received refreshOneTimeKeys from \(inboundTask.senderSecretName); replenishing local published OTK batch")
                        async let x25519Refresh = session.refreshOneTimeKeysTask(policy: .replenishBatch)
                        async let mlKEMRefresh = session.refreshMLKEMOneTimeKeysTask(policy: .replenishBatch)
                        let (x25519Replaced, mlKEMReplaced) = await (x25519Refresh, mlKEMRefresh)
                        if !x25519Replaced || !mlKEMReplaced {
                            logger.log(
                                level: .warning,
                                message: "refreshOneTimeKeys inbound replenish incomplete for \(inboundTask.senderSecretName) curve=\(x25519Replaced) mlkem=\(mlKEMReplaced)")
                        } else {
                            try await session.ackPublishedOneTimeKeysReplenished(to: inboundTask.senderSecretName)
                        }
                    case .publishedOneTimeKeysReplenished:
                        canSaveMessage = false
                        logger.log(
                            level: .info,
                            message: "Received publishedOneTimeKeysReplenished from \(inboundTask.senderSecretName)")
                        await session.completePeerPublishedOneTimeKeysReplenishmentWait(
                            secretName: inboundTask.senderSecretName)
                    }
                } catch {
                    if let processedReestablishment {
                        await session.forgetReceivedSessionReestablishment(
                            envelope: processedReestablishment,
                            senderDeviceId: inboundTask.senderDeviceId)
                    }
                    logger.log(level: .error, message: "Error handling transport event from \(inboundTask.senderSecretName): \(error)")
                    throw error
                }
            }

            var didAcceptInbound = false
            if canSaveMessage {
                /// Now we can handle the message
                try await handleDecodedMessage(
                    decodedMessage,
                    inboundTask: inboundTask,
                    session: session,
                    sessionIdentity: decryptionSessionIdentity)
                decryptionSessionIdentity = try await finalizeAcceptedInbound(
                    decryptionSessionIdentity,
                    inboundTask: inboundTask,
                    session: session,
                    headerOneTimeKeyId: verificationResult.ratchetMessage.header.oneTimeKeyId,
                    headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId,
                    acknowledgeTransport: false)
                didAcceptInbound = true
            } else if await shouldAcceptWithoutChatRow(decodedMessage, session: session) {
                // Intentional non-persist (TransportEvent controls / nudgeLocal):
                // still ledger-accept so spool can ACK. Persistable host declines
                // must not accept — redelivery needs another chance at UI persist.
                decryptionSessionIdentity = try await finalizeAcceptedInbound(
                    decryptionSessionIdentity,
                    inboundTask: inboundTask,
                    session: session,
                    headerOneTimeKeyId: verificationResult.ratchetMessage.header.oneTimeKeyId,
                    headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId,
                    acknowledgeTransport: false)
                didAcceptInbound = true
            }

            if canSaveMessage {
                // Recovery bookkeeping is committed only after the accepted
                // envelope is durable and the winning lane is active.
                let recoveredFailureClasses = await session.takeInboundFailureClasses(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    messageId: inboundTask.sharedMessageId)
                if !recoveredFailureClasses.isEmpty {
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.messageDecrypted sharedId=\(inboundTask.sharedMessageId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) priorFailureClasses=\(recoveredFailureClasses.joined(separator: ","))")
                    // Heal event in the same audit file as the failures: bounded to
                    // messages that previously failed, so the audit shows fail-then-heal
                    // per sharedId instead of requiring success to be inferred from quiet.
                    audit(.recovery, "pqs.recovery.recovered sharedId=\(inboundTask.sharedMessageId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) priorFailureClasses=\(recoveredFailureClasses.joined(separator: ","))")
                }
                // A late orphan replay can land after the tuple was written off as
                // unrecoverable; the content is back, so lift the terminal mark.
                await session.clearInboundTerminalOutcome(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    sharedId: inboundTask.sharedMessageId)
                // Proven decrypt heals the lane: clear distinct-failure escalate bookkeeping
                // and re-arm archive fallback for this peer-device.
                await session.clearUndecryptableLaneFailures(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)

                let pending = await session.takePendingResendsAfterReestablishment(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    satisfiedSharedMessageId: inboundTask.sharedMessageId)
                // Still waiting for our own peerRefresh response: an ordinary inbound
                // decrypt (e.g. media the peer encrypted after their reset) does not
                // complete the coordinated exchange. Closing here drained resends onto
                // a lane the peer never accepted — Echo transported requests that Nudge
                // never received.
                //
                // Still waiting for our own peerRefresh response: ordinary inbound
                // decrypt (including activate-on-decrypt of an older session) does not
                // complete the coordinated exchange.
                let awaitingPeerRefreshResponse = await session.hasActiveLocalPeerRefreshRequest(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)
                if awaitingPeerRefreshResponse {
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendDrainDeferred reason=awaitingPeerRefreshResponse sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) pendingCount=\(pending.count) sharedId=\(inboundTask.sharedMessageId)")
                    audit(.recovery, "pqs.recovery.resendDrainDeferred reason=awaitingPeerRefreshResponse sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) pendingCount=\(pending.count) sharedId=\(inboundTask.sharedMessageId)")
                    for pendingRequest in pending {
                        await session.deferPeerResendUntilReestablished(
                            sender: pendingRequest.senderName,
                            deviceId: pendingRequest.senderDeviceId,
                            failedMessageId: pendingRequest.failedSharedMessageId,
                            failureClass: pendingRequest.failureClass)
                    }
                } else {
                    // Proven decrypt with no outstanding local peerRefresh request:
                    // close the episode and drain deferred resends.
                    await session.endReestablishmentEpisode(
                        sender: inboundTask.senderSecretName,
                        deviceId: inboundTask.senderDeviceId)
                    await sendDeferredResendRequests(
                        pending,
                        session: session,
                        reason: "successful inbound message")
                }
            }

            if didAcceptInbound {
                await acknowledgeAcceptedInbound(inboundTask, session: session)
            }
            
        } catch {
            if let cache = await session.cache {
                let currentIdentities =
                    (try? await cache.fetchSessionIdentities()) ?? []
                for (identityId, originalData) in rollbackIdentityData {
                    if let identity = currentIdentities.first(where: { $0.id == identityId }) {
                        try? await restoreSessionIdentityData(
                            identity,
                            data: originalData,
                            session: session,
                            reason: "post-decrypt processing failed")
                    } else if let deletedOriginal = rollbackPeerIdentities.first(
                        where: { $0.id == identityId })
                    {
                        deletedOriginal.data = originalData
                        try? await cache.createSessionIdentity(deletedOriginal)
                        await ratchetManager.discardCachedLane(identityId)
                    }
                }
                for identity in currentIdentities
                    where rollbackIdentityData[identity.id] == nil
                {
                    if let props = await identity.props(symmetricKey: rollbackSymmetricKey),
                       props.secretName == inboundTask.senderSecretName,
                       props.deviceId == inboundTask.senderDeviceId
                    {
                        try? await cache.deleteSessionIdentity(identity.id)
                        await ratchetManager.discardCachedLane(identity.id)
                    }
                }
                await session.invalidateSessionIdentityCache(
                    secretName: inboundTask.senderSecretName)
            }
#if DEBUG
            logger.log(
                level: .debug,
                message: "pqs.recovery.decryptAttemptFailed sharedId=\(inboundTask.sharedMessageId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) action=handOffToRecoveryPolicy error=\(error)")
#endif
            throw error
        }
    }

    /// True when decrypt succeeded but no chat row is expected — TransportEvent
    /// controls or host `shouldPersist == false` (nudgeLocal). Persistable host
    /// declines (`processMessage == false` with persistable transport) must return
    /// false so the envelope stays retryable.
    private func shouldAcceptWithoutChatRow(
        _ message: CryptoMessage,
        session: PQSSession
    ) async -> Bool {
        guard let transportInfo = message.transportInfo, !transportInfo.isEmpty else {
            return false
        }
        if (try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo)) != nil {
            return true
        }
        return await session.sessionDelegate?.shouldPersist(transportInfo: transportInfo) == false
    }

    /// Commits the winning receive lane only after decrypt, decode, and all host
    /// handling have completed. Durable accepted-ledger write precedes spool ACK.
    private func finalizeAcceptedInbound(
        _ decryptionSessionIdentity: SessionIdentity,
        inboundTask: InboundTaskMessage,
        session: PQSSession,
        headerOneTimeKeyId: UUID?,
        headerMLKEMOneTimeKeyId: UUID?,
        acknowledgeTransport: Bool = true
    ) async throws -> SessionIdentity {
        let activated = try await session.activateSessionIdentityAfterInboundDecrypt(
            decryptionSessionIdentity)
        // Do not publish preference / clear recovery state until the durable
        // accepted ledger write succeeds. The outer catch restores identity
        // inventory if persistence fails.
        try await session.markEnvelopeAccepted(
            senderSecretName: inboundTask.senderSecretName,
            senderDeviceId: inboundTask.senderDeviceId,
            envelopeMessageId: inboundTask.sharedMessageId,
            logicalSharedId: inboundTask.resolvedLogicalSharedId)
        // Deferred OTK consumption is driven only by committed frames, so a
        // rolled-back decrypt can neither record nor confirm a consumption.
        await noteAcceptedInboundForDeferredOneTimeKeyConsumption(
            laneId: activated.id,
            headerOneTimeKeyId: headerOneTimeKeyId,
            headerMLKEMOneTimeKeyId: headerMLKEMOneTimeKeyId,
            session: session)
        preferredSessionIdentityIdByPeerDevice[
            peerDeviceIdentityPreferenceKey(
                secretName: inboundTask.senderSecretName,
                deviceId: inboundTask.senderDeviceId)
        ] = activated.id
        clearSurgicalControlEpisode(
            secretName: inboundTask.senderSecretName,
            deviceId: inboundTask.senderDeviceId)
        if acknowledgeTransport {
            await acknowledgeAcceptedInbound(inboundTask, session: session)
        }
        logger.log(
            level: .info,
            message: "pqs.recovery.laneSelectedAfterInboundDecrypt sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) sessionId=\(activated.id)")
        return activated
    }

    /// Writes the deferred OTK back into ratchet state after strict-mode decrypt
    /// cleared it. No-op when the header cites no OTK or the private half has
    /// already been deleted (lane superseded).
    ///
    /// This restore is deliberately **unconditional** for cited frames. In
    /// DRK 4.0.0 the state OTK is not a one-shot bootstrap key: its public half
    /// is embedded in every outgoing header while present, and it participates
    /// in every PQXDH epoch re-key. If we let the state copy stay nil after a
    /// consuming decrypt, our next outbound header embeds no OTK, the peer's
    /// `hasReceivingKeyChanges` sees an identity-key change, and it performs a
    /// receive-driven epoch re-key that we never mirrored — permanent chain
    /// divergence (`maxSkippedHeadersExceeded` storms). Verified empirically:
    /// gating this restore on `sendingHandshakeFinished` produced exactly that
    /// divergence.
    private func restoreDeferredOneTimeKeyIntoRatchetState(
        sessionIdentity: SessionIdentity,
        session: PQSSession,
        ratchetMessage: RatchetMessage
    ) async {
        guard let otkId = ratchetMessage.header.oneTimeKeyId else { return }
        guard let sessionContext = await session.sessionContext else { return }
        guard sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.contains(where: { $0.id == otkId }) else {
            return
        }
        do {
            try await initializeRecipient(
                sessionIdentity: sessionIdentity,
                session: session,
                ratchetMessage: ratchetMessage)
        } catch {
            logger.log(
                level: .error,
                message: "pqs.otk.restoreIntoRatchetStateFailed lane=\(sessionIdentity.id.uuidString) otkId=\(otkId.uuidString) error=\(error)")
        }
    }

    private func noteAcceptedInboundForDeferredOneTimeKeyConsumption(
        laneId: UUID,
        headerOneTimeKeyId: UUID?,
        headerMLKEMOneTimeKeyId: UUID?,
        session: PQSSession
    ) async {
        do {
            guard var sessionContext = await session.sessionContext else { return }
            var deviceKeys = sessionContext.sessionUser.deviceKeys
            var mutated = false
            var confirmed: [PendingOneTimeKeyConsumption] = []
            // Only the X25519 `oneTimeKeyId` discriminates lanes here. In
            // DRK 4.0.0 a live lane cites its bootstrap OTK id for its whole
            // lifetime (the state OTK participates in every epoch re-key), so
            // the deletion-confirming events are:
            //   1. A committed frame on the same lane citing a *different* id —
            //      the peer re-fetched our bundle and epoch re-keyed the lane,
            //      so the superseded key can never be legitimately cited again.
            //   2. A committed frame with no id — a lane established without an
            //      OTK, and the forward-compatible trigger for a future DRK
            //      that stops citing after the reverse handshake completes.
            // `mlKEMOneTimeKeyId` mirrors non-optional lane state and is cited
            // on every frame forever, so it never drives confirmation alone.
            if let headerOneTimeKeyId {
                let laneEntries = deviceKeys.removePendingOneTimeKeyConsumptions(for: laneId)
                for entry in laneEntries {
                    if entry.oneTimeKeyId == headerOneTimeKeyId {
                        deviceKeys.recordPendingOneTimeKeyConsumption(entry)
                    } else {
                        confirmed.append(entry)
                        mutated = true
                    }
                }
                // Record only keys we can actually delete later. A bootstrap
                // decrypted purely via archived-state fallback (pool already
                // rotated) has nothing to defer.
                let alreadyPending = (deviceKeys.pendingOneTimeKeyConsumptions ?? []).contains {
                    $0.sessionIdentityId == laneId && $0.oneTimeKeyId == headerOneTimeKeyId
                }
                if !alreadyPending,
                   deviceKeys.oneTimePrivateKeys.contains(where: { $0.id == headerOneTimeKeyId }) {
                    // The cited MLKEM id is consumable only while it is a pool key —
                    // the final (last-resort) MLKEM key is never consumed.
                    let pendingMLKEMId = headerMLKEMOneTimeKeyId.flatMap { id in
                        deviceKeys.mlKEMOneTimePrivateKeys.contains(where: { $0.id == id }) ? id : nil
                    }
                    deviceKeys.recordPendingOneTimeKeyConsumption(PendingOneTimeKeyConsumption(
                        sessionIdentityId: laneId,
                        oneTimeKeyId: headerOneTimeKeyId,
                        mlKEMOneTimeKeyId: pendingMLKEMId))
                    mutated = true
                    audit(.recovery, "pqs.otk.consumptionPending lane=\(laneId.uuidString) otkId=\(headerOneTimeKeyId.uuidString) mlkemId=\(pendingMLKEMId?.uuidString ?? "nil")")
                }
            } else {
                confirmed = deviceKeys.removePendingOneTimeKeyConsumptions(for: laneId)
                mutated = !confirmed.isEmpty
            }

            for entry in confirmed {
                if let otkId = entry.oneTimeKeyId,
                   !deviceKeys.isOneTimeKeyStillPending(otkId) {
                    deviceKeys.oneTimePrivateKeys.removeAll { $0.id == otkId }
                }
                if let kemId = entry.mlKEMOneTimeKeyId,
                   !deviceKeys.isMLKEMOneTimeKeyStillPending(kemId) {
                    deviceKeys.mlKEMOneTimePrivateKeys.removeAll { $0.id == kemId }
                }
                let trigger = headerOneTimeKeyId == nil ? "reverseHandshake" : "laneRekey"
                audit(.recovery, "pqs.otk.consumedAfterConfirmation trigger=\(trigger) lane=\(laneId.uuidString) otkId=\(entry.oneTimeKeyId?.uuidString ?? "nil") mlkemId=\(entry.mlKEMOneTimeKeyId?.uuidString ?? "nil")")
            }

            guard mutated else { return }
            sessionContext.sessionUser.deviceKeys = deviceKeys
            sessionContext.updateSessionUser(sessionContext.sessionUser)
            await session.setSessionContext(sessionContext)
            let encodedData = try BinaryEncoder().encode(sessionContext)
            guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: session.getAppSymmetricKey()) else {
                throw PQSError.sessionEncryptionError
            }
            try await session.cache?.updateLocalSessionContext(encryptedConfig)
        } catch {
            logger.log(
                level: .error,
                message: "pqs.otk.deferredConsumptionBookkeepingFailed lane=\(laneId.uuidString) error=\(error)")
        }
    }

    private func acknowledgeAcceptedInbound(
        _ inboundTask: InboundTaskMessage,
        session: PQSSession
    ) async {
        let acceptedSharedId = inboundTask.sharedMessageId
        let acceptedDelegate = await session.sessionDelegate
        await session.scheduleTransportProtocolWork {
            await acceptedDelegate?.inboundCiphertextAccepted(sharedMessageId: acceptedSharedId)
        }
    }

    /// Enqueues a `.background` re-process of `inboundTask` that includes archived
    /// SessionIdentity rows. Pass ownership is tokenized by
    /// `(sender, device, envelope, fingerprint)` so a fresh orphan fingerprint
    /// cannot consume an older archive-only pass (T17).
    private func deferArchivedInboundFallback(
        inboundTask: InboundTaskMessage,
        session: PQSSession
    ) async {
        let sharedId = inboundTask.sharedMessageId
        let currentFingerprint = PQSSession.nackFrameFingerprint(for: inboundTask)
        let token = ArchivedInboundFallbackToken(
            senderSecretName: inboundTask.senderSecretName,
            senderDeviceId: inboundTask.senderDeviceId,
            envelopeMessageId: sharedId,
            fingerprint: currentFingerprint)
        guard InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
            token: token,
            exhausted: archivedInboundFallbackExhausted,
            pendingPass: archivedInboundFallbackPasses
        ) else {
            return
        }
        guard archivedInboundFallbackPasses.insert(token.storageKey).inserted else {
            return
        }
        audit(.recovery, "pqs.recovery.deferArchivedInboundFallback sharedId=\(sharedId) token=\(token.storageKey.prefix(64)) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
        do {
            try await enqueue(
                EncryptableTask(
                    task: .streamMessage(inboundTask),
                    priority: .background),
                session: session)
        } catch {
            archivedInboundFallbackPasses.remove(token.storageKey)
            logger.log(
                level: .warning,
                message: "pqs.recovery.deferArchivedInboundFallbackFailed sharedId=\(sharedId) error=\(error)")
        }
    }

    private func markArchivedInboundFallbackExhausted(
        sharedId: String,
        sender: String,
        deviceId: UUID,
        fingerprint: Data
    ) {
        let token = ArchivedInboundFallbackToken(
            senderSecretName: sender,
            senderDeviceId: deviceId,
            envelopeMessageId: sharedId,
            fingerprint: fingerprint)
        archivedInboundFallbackExhausted = InboundRecoveryStormPolicy.exhaustedAfterArchivePassCompleted(
            current: archivedInboundFallbackExhausted,
            token: token)
        archivedInboundFallbackExhaustedPeerKey[token.storageKey] = token.peerKey
        archivedInboundFallbackPasses.remove(token.storageKey)
    }

    func clearArchivedInboundFallbackExhausted(sender: String, deviceId: UUID) {
        let peerKey = "\(sender)|\(deviceId.uuidString)"
        let keys = archivedInboundFallbackExhaustedPeerKey
            .compactMap { $0.value == peerKey ? $0.key : nil }
        for key in keys {
            archivedInboundFallbackExhausted.remove(key)
            archivedInboundFallbackExhaustedPeerKey.removeValue(forKey: key)
        }
    }

    func restoreSessionIdentityData(
        _ identity: SessionIdentity,
        data: Data,
        session: PQSSession,
        reason: String
    ) async throws {
        identity.data = data
        // The ratchet manager persists working mutations during an attempt, so its
        // in-memory configuration now diverges from the restored row. Evict it so the
        // next attempt rebuilds from the committed row (blank rows re-run the PQXDH
        // bootstrap from the incoming header instead of reusing poisoned state).
        await ratchetManager.discardCachedLane(identity.id)
        guard let cache = await session.cache else { return }

        do {
            try await cache.updateSessionIdentity(identity)
        } catch SessionCache.CacheErrors.sessionIdentityNotFound {
            logger.log(
                level: .info,
                message: "Skipped restoring SessionIdentity after \(reason); identity no longer exists in cache")
        }
    }

    /// Initializes the recipient for a session based on the provided ratchet message.
    ///
    /// This method sets up the recipient side of the Double Ratchet protocol by
    /// selecting appropriate keys and initializing the ratchet state. It handles
    /// both initial session setup and subsequent message processing.
    ///
    /// ## Initialization Process
    /// 1. Validates session context and identity
    /// 2. Selects appropriate local keys based on ratchet message
    /// 3. Initializes ratchet state with remote and local keys
    /// 4. Removes used keys to maintain forward secrecy
    /// 5. Updates session state for future messages
    ///
    /// ## Key Selection
    /// - One-time keys are selected based on message header
    /// - PQ-KEM keys are selected for post-quantum security
    /// - Long-term keys are used for session establishment
    /// - Key rotation is handled automatically
    ///
    /// ## Security Considerations
    /// - Keys are validated before use to prevent attacks
    /// - Used keys are immediately removed to maintain forward secrecy
    /// - Session state is updated atomically
    /// - Failed initialization is handled gracefully
    ///
    /// - Parameters:
    ///   - sessionIdentity: The session identity of the recipient. Contains
    ///                      the cryptographic state and key information.
    ///   - session: The current crypto session providing context and keys.
    ///   - ratchetMessage: The ratchet message to initialize with. Contains
    ///                     the remote keys and initialization data.
    /// - Throws: An error if the initialization fails due to missing keys,
    ///           cryptographic errors, or invalid state.
    private func initializeRecipient(
        sessionIdentity: SessionIdentity,
        session: PQSSession,
        ratchetMessage: RatchetMessage
    ) async throws {
        self.session = session
        guard let sessionContext = await session.sessionContext else {
            throw PQSError.sessionNotInitialized
        }
        
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        
        var localOneTimePrivateKey: X25519PrivateKey?
        var localMLKEMPrivateKey: MLKEMPrivateKey
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw DoubleRatchetKit.CryptoError.propsError
        }
        
        let localPrivateKeys = sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys
        let localMLKEMPrivateKeys = sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys
        
        if let oneTimeKeyId = ratchetMessage.header.oneTimeKeyId {
            if let privateOneTimeKey = localPrivateKeys.first(where: { $0.id == oneTimeKeyId }) {
                localOneTimePrivateKey = privateOneTimeKey
            } else if let storedOTK = props.ratchetOneTimePrivateKey, storedOTK.id == oneTimeKeyId {
                localOneTimePrivateKey = storedOTK
            } else {
                if shouldEmitKeyPayloadLogs {
                    logger.log(level: .debug, message: """
                        OTK mismatch: headerOTK=\(oneTimeKeyId.uuidString) \
                        localPoolSize=\(localPrivateKeys.count) \
                        localPoolIDs=\(localPrivateKeys.prefix(5).map(\.id.uuidString)) \
                        hasState=\(props.hasRatchetState) \
                        stateOTK=\(props.ratchetOneTimePrivateKey?.id.uuidString ?? "nil") \
                        sender=\(props.secretName) deviceId=\(props.deviceId)
                        """)
                }
                throw RatchetError.missingOneTimeKey
            }
        } else {
            localOneTimePrivateKey = nil
        }
        
        if let mlKEMOneTimeKeyId = ratchetMessage.header.mlKEMOneTimeKeyId {
            if let privateMLKEMOneTimeKey = localMLKEMPrivateKeys.first(where: { $0.id == mlKEMOneTimeKeyId }) {
                localMLKEMPrivateKey = privateMLKEMOneTimeKey
            } else if sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey.id == mlKEMOneTimeKeyId {
                localMLKEMPrivateKey = sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
            } else if let storedKEM = props.ratchetMLKEMPrivateKey, storedKEM.id == mlKEMOneTimeKeyId {
                localMLKEMPrivateKey = storedKEM
            } else {
                if shouldEmitKeyPayloadLogs {
                    logger.log(level: .debug, message: """
                        MLKEM OTK mismatch: headerMLKEM=\(mlKEMOneTimeKeyId.uuidString) \
                        localPoolSize=\(localMLKEMPrivateKeys.count) \
                        finalMLKEM=\(sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey.id.uuidString) \
                        hasState=\(props.hasRatchetState) \
                        sender=\(props.secretName) deviceId=\(props.deviceId)
                        """)
                }
                throw RatchetError.missingOneTimeKey
            }
        } else {
            localMLKEMPrivateKey = sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
        }
        
        
        if shouldEmitKeyPayloadLogs {
            logger.log(level: .debug, message: """
                recipientInit: sender=\(props.secretName)\n
                headerOTK=\(ratchetMessage.header.oneTimeKeyId?.uuidString ?? "nil")\n
                headerMLKEM=\(ratchetMessage.header.mlKEMOneTimeKeyId?.uuidString ?? "nil")\n
                selectedLocalOTK=\(localOneTimePrivateKey?.id.uuidString ?? "nil")\n
                selectedLocalMLKEM=\(localMLKEMPrivateKey.id.uuidString)\n
                headerRemoteLTK=\(ratchetMessage.header.remoteLongTermPublicKey.prefix(10).base64EncodedString())
                """)
        }
        try await ratchetManager.respondToSession(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: databaseSymmetricKey,
            header: ratchetMessage.header,
            localKeys: .init(
                longTerm: .init(sessionContext.sessionUser.deviceKeys.longTermPrivateKey),
                oneTime: localOneTimePrivateKey,
                mlKEM: localMLKEMPrivateKey))
    }
    
    /// Handles the processing of a decoded message, specifically for private messages,
    /// regardless of their communication type. This method utilizes the recipient information
    /// for reference when looking up communication models, but the recipient itself is not persisted.
    ///
    /// On the initial creation of the communication model, necessary metadata must be provided.
    /// If the required metadata is not present in the decoded recipient and the communication model
    /// does not already exist, it should be included in the message metadata (e.g., members, admin, organizers).
    ///
    /// ## Message Processing Flow
    /// 1. Determines message recipient type (nickname, personal, channel, broadcast)
    /// 2. Looks up or creates appropriate communication model
    /// 3. Updates communication metadata and message count
    /// 4. Creates encrypted message model
    /// 5. Persists message and notifies delegates
    ///
    /// ## Communication Types
    /// - **Nickname**: Direct messages between two users with nickname routing
    /// - **Personal**: Direct messages between two users
    /// - **Channel**: Group messages with multiple participants
    /// - **Broadcast**: System-wide messages (not persisted)
    ///
    /// ## Security Considerations
    /// - All message content is encrypted before persistence
    /// - Communication metadata is validated and sanitized
    /// - Message sequence numbers prevent replay attacks
    /// - Sender identity is verified before processing
    ///
    /// - Parameters:
    ///   - decodedMessage: The decoded `CryptoMessage` that needs to be processed.
    ///                     Contains the actual message content and recipient information.
    ///   - inboundTask: The `InboundTaskMessage` associated with the incoming message.
    ///                  Contains sender information and transport metadata.
    ///   - session: The current `PQSSession` in which the message is being processed.
    ///              Provides context and cryptographic keys.
    ///   - sessionIdentity: The `SessionIdentity` associated with the recipient of the message.
    ///                      Contains sender's cryptographic identity.
    /// After the transport accepts an outbound ratchet payload, move the local persisted copy off `.sending`
    /// so clients can show a stable "sent" state without waiting for a peer receipt.
    func markPersistedOutboundPastSendingIfNeeded(session: PQSSession, localMessageId: UUID) async {
        guard let cache = await session.cache else { return }
        let persisted: EncryptedMessage
        do {
            persisted = try await cache.fetchMessage(id: localMessageId)
        } catch {
            return
        }
        do {
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            guard var props = await persisted.props(symmetricKey: symmetricKey) else { return }
            guard case .sending = props.deliveryState else { return }
            props.deliveryState = .waitingDelivery
            let updated = try await persisted.updateMessage(with: props, symmetricKey: symmetricKey)
            try await cache.updateMessage(updated, symmetricKey: symmetricKey)
            await session.receiverDelegate?.updatedMessage(updated)
        } catch {
            logger.log(level: .debug, message: "markPersistedOutboundPastSendingIfNeeded failed: \(error)")
        }
    }
    
    /// Lets the original sender advance their outbound delivery glyph once we've decrypted and stored the message.
    /// Skips channels (noise) and self-sent / multidevice echoes.
    private func sendAutomaticDeliveredReceiptIfNeeded(
        session: PQSSession,
        inboundTask: InboundTaskMessage,
        sharedId: String,
        conversationRecipient: MessageRecipient
    ) async {
        switch conversationRecipient {
        case .nickname, .personalMessage:
            break
        default:
            return
        }
        guard let mySecretName = await session.sessionContext?.sessionUser.secretName else { return }
        guard inboundTask.senderSecretName != mySecretName else { return }
        guard let sessionDelegate = await session.sessionDelegate else { return }
        guard await sessionDelegate.shouldSendAutomaticDeliveryReceipts() else { return }
        
        let metadata = DeliveryStateMetadata(state: .delivered, sharedId: sharedId)
        let encoded: Data
        do {
            encoded = try BinaryEncoder().encode(metadata)
        } catch {
            return
        }
        let receiptRecipient = MessageRecipient.nickname(inboundTask.senderSecretName)
        do {
            try await sessionDelegate.deliveryStateChanged(recipient: receiptRecipient, metadata: encoded)
        } catch {
            logger.log(level: .debug, message: "Automatic delivered receipt failed for sharedId=\(sharedId): \(error)")
        }
    }
    
    /// - Throws: An error if the message processing fails due to issues such as missing metadata,
    ///           session errors, or communication model errors.
    private func handleDecodedMessage(_ decodedMessage: CryptoMessage,
                                      
                                      inboundTask: InboundTaskMessage,
                                      session: PQSSession,
                                      sessionIdentity: SessionIdentity) async throws
    {
        guard let cache = await session.cache else { throw PQSError.databaseNotInitialized }
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()

        // Duplicate-persist guard: the same logical message can decrypt twice
        // (an orphan replay landing after the original, or a redelivery racing
        // the ingress guard). One sharedId from one sender tuple is one chat
        // row — persisting again would mint a second row with a fresh UUID and
        // notify the host twice. The sender-tuple match keeps this from ever
        // colliding with a *different* sender's frame or with our own outbound
        // record for the same conversation.
        // Recovery placeholders (waiting/failed) are replaced in place on heal.
        if let existing = try await cache.fetchMessageIfExists(
            sharedId: inboundTask.resolvedLogicalSharedId),
           let existingProps = await existing.props(symmetricKey: databaseSymmetricKey),
           existingProps.senderSecretName == inboundTask.senderSecretName,
           existingProps.senderDeviceId == inboundTask.senderDeviceId
        {
            if Self.isReplaceableInboundRecoveryPlaceholder(existingProps) {
                var healedProps = existingProps
                healedProps.message = decodedMessage
                healedProps.deliveryState = .received
                let healed = try await existing.updateMessage(
                    with: healedProps,
                    symmetricKey: databaseSymmetricKey)
                try await cache.updateMessage(healed, symmetricKey: databaseSymmetricKey)
                audit(.recovery, "pqs.recovery.placeholderHealed envelope=\(inboundTask.sharedMessageId) logical=\(inboundTask.resolvedLogicalSharedId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
                await session.receiverDelegate?.createdMessage(healed)
                await sendAutomaticDeliveredReceiptIfNeeded(
                    session: session,
                    inboundTask: inboundTask,
                    sharedId: healed.sharedId,
                    conversationRecipient: decodedMessage.recipient)
                return
            }
            audit(.recovery, "pqs.recovery.duplicateInboundPersistSkipped envelope=\(inboundTask.sharedMessageId) logical=\(inboundTask.resolvedLogicalSharedId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
            return
        }
        
        switch decodedMessage.recipient {
        case let .nickname(recipient):
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            // This can happen on multidevice support when a sender is also sending a message to it's master/child device.
            let isMe = await inboundTask.senderSecretName == session.sessionContext?.sessionUser.secretName
            do {
                // Need to flip recipient
                communicationModel = try await conversation(
                    cache: cache,
                    communicationType: .nickname(isMe ? recipient : inboundTask.senderSecretName),
                    session: session
                )
                
                var communication = try await communicationModel.makeDecryptedModel(of: Communication.self, symmetricKey: databaseSymmetricKey)
                communication.messageCount += 1
                
                _ = try await communicationModel.updateProps(
                    symmetricKey: databaseSymmetricKey,
                    props: BaseCommunication.UnwrappedProps(
                        sharedId: communication.sharedId,
                        messageCount: communication.messageCount,
                        administrator: communication.administrator,
                        operators: communication.operators,
                        members: communication.members,
                        metadata: communication.metadata,
                        blockedMembers: communication.blockedMembers,
                        communicationType: communication.communicationType
                    )
                )
                
                shouldUpdateCommunication = true
            } catch {
                // Need to flip recipient
                communicationModel = try await createCommunicationModel(
                    recipients: [recipient, inboundTask.senderSecretName],
                    communicationType: .nickname(isMe ? recipient : inboundTask.senderSecretName),
                    metadata: decodedMessage.metadata,
                    symmetricKey: databaseSymmetricKey
                )
                try await cache.createCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: [recipient, inboundTask.senderSecretName])
            }
            
            let messageModel = try await createInboundMessageModel(
                decodedMessage: decodedMessage,
                inboundTask: inboundTask,
                senderSecretName: inboundTask.senderSecretName,
                senderDeviceId: inboundTask.senderDeviceId,
                session: session,
                communication: communicationModel,
                sessionIdentity: sessionIdentity
            )
            
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
                if let members = await communicationModel.props(symmetricKey: databaseSymmetricKey)?.members {
                    await session.receiverDelegate?.updatedCommunication(communicationModel, members: members)
                }
            }
            
            try await cache.createMessage(messageModel, symmetricKey: databaseSymmetricKey)
            logger.log(level: .info, message: "Inbound message persisted with sharedId=\(messageModel.sharedId), recipient=\(decodedMessage.recipient), flag=\(decodedMessage.transportInfo != nil ? "hasTransportInfo" : "noTransportInfo")")
            audit(.recv, "pqs.recv.persisted sharedId=\(messageModel.sharedId) sender=\(inboundTask.senderSecretName) senderDeviceId=\(inboundTask.senderDeviceId.uuidString) recipient=\(decodedMessage.recipient.auditRecipientTag) sessionIdentityId=\(sessionIdentity.id.uuidString)",
                level: .info)
            
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
            await sendAutomaticDeliveredReceiptIfNeeded(
                session: session,
                inboundTask: inboundTask,
                sharedId: messageModel.sharedId,
                conversationRecipient: decodedMessage.recipient)
        case .personalMessage:
            let sender = inboundTask.senderSecretName
            guard let mySecretName = await session.sessionContext?.sessionUser.secretName else { return }
            
            let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            do {
                communicationModel = try await conversation(
                    cache: cache,
                    communicationType: decodedMessage.recipient,
                    session: session
                )
                
                var communication = try await communicationModel.makeDecryptedModel(of: Communication.self, symmetricKey: databaseSymmetricKey)
                communication.messageCount += 1
                
                _ = try await communicationModel.updateProps(
                    symmetricKey: databaseSymmetricKey,
                    props: BaseCommunication.UnwrappedProps(
                        sharedId: communication.sharedId,
                        messageCount: communication.messageCount,
                        administrator: communication.administrator,
                        operators: communication.operators,
                        members: communication.members,
                        metadata: communication.metadata,
                        blockedMembers: communication.blockedMembers,
                        communicationType: communication.communicationType
                    )
                )
                
                shouldUpdateCommunication = true
            } catch {
                communicationModel = try await createCommunicationModel(
                    recipients: [sender],
                    communicationType: decodedMessage.recipient,
                    metadata: decodedMessage.metadata,
                    symmetricKey: databaseSymmetricKey
                )
                
                try await cache.createCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: [mySecretName])
            }
            
            let messageModel = try await createInboundMessageModel(
                decodedMessage: decodedMessage,
                inboundTask: inboundTask,
                senderSecretName: sender,
                senderDeviceId: inboundTask.senderDeviceId,
                session: session,
                communication: communicationModel,
                sessionIdentity: sessionIdentity
            )
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: [mySecretName])
            }
            
            try await cache.createMessage(messageModel, symmetricKey: databaseSymmetricKey)
            logger.log(level: .info, message: "Inbound message persisted with sharedId=\(messageModel.sharedId), recipient=\(decodedMessage.recipient), flag=\(decodedMessage.transportInfo != nil ? "hasTransportInfo" : "noTransportInfo")")
            audit(.recv, "pqs.recv.persisted sharedId=\(messageModel.sharedId) sender=\(inboundTask.senderSecretName) senderDeviceId=\(inboundTask.senderDeviceId.uuidString) recipient=\(decodedMessage.recipient.auditRecipientTag) sessionIdentityId=\(sessionIdentity.id.uuidString)",
                level: .info)
            
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
            await sendAutomaticDeliveredReceiptIfNeeded(
                session: session,
                inboundTask: inboundTask,
                sharedId: messageModel.sharedId,
                conversationRecipient: decodedMessage.recipient)
        case .channel:
            let sender = inboundTask.senderSecretName
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            
            // Channel Models need to be created before a message is sent or received
            do {
                communicationModel = try await conversation(
                    cache: cache,
                    communicationType: decodedMessage.recipient,
                    session: session
                )
                
                guard var newProps = await communicationModel.props(symmetricKey: databaseSymmetricKey) else { return }
                newProps.messageCount += 1
                _ = try await communicationModel.updateProps(symmetricKey: databaseSymmetricKey, props: newProps)
                shouldUpdateCommunication = true
            } catch {
                // Create the communication if it doesn't exist for channel (only when metadata contains ChannelInfo)
                guard case let .channel(channelName) = decodedMessage.recipient else {
                    throw error
                }
                guard !decodedMessage.metadata.isEmpty else {
                    throw error
                }
                let info: ChannelInfo
                do {
                    info = try BinaryDecoder().decode(ChannelInfo.self, from: decodedMessage.metadata)
                } catch {
                    throw error
                }
                
                communicationModel = try await createCommunicationModel(
                    administrator: info.administrator,
                    operators: info.operators,
                    recipients: info.members,
                    communicationType: .channel(channelName),
                    metadata: decodedMessage.metadata,
                    symmetricKey: databaseSymmetricKey
                )
                try await cache.createCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: info.members)
                await session.receiverDelegate?.createdChannel(communicationModel)
            }
            
            let messageModel = try await createInboundMessageModel(
                decodedMessage: decodedMessage,
                inboundTask: inboundTask,
                senderSecretName: sender,
                senderDeviceId: inboundTask.senderDeviceId,
                session: session,
                communication: communicationModel,
                sessionIdentity: sessionIdentity
            )
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
            }
            try await cache.createMessage(messageModel, symmetricKey: databaseSymmetricKey)
            if shouldUpdateCommunication,
               let members = await communicationModel.props(symmetricKey: databaseSymmetricKey)?.members {
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: members)
            }
            logger.log(level: .info, message: "Inbound message persisted with sharedId=\(messageModel.sharedId), recipient=\(decodedMessage.recipient), flag=\(decodedMessage.transportInfo != nil ? "hasTransportInfo" : "noTransportInfo")")
            audit(.recv, "pqs.recv.persisted sharedId=\(messageModel.sharedId) sender=\(sender) senderDeviceId=\(inboundTask.senderDeviceId.uuidString) recipient=\(decodedMessage.recipient.auditRecipientTag) sessionIdentityId=\(sessionIdentity.id.uuidString)",
                level: .info)
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
        case .broadcast:
            // Outbound broadcast is fanned out as per-peer `.nickname` ciphertext; legacy `.broadcast` payloads are not used.
            break
        }
    }
    
    /// Verifies and decrypts an encrypted message received in an inbound task.
    ///
    /// This method extracts the ratchet message and the associated session identity
    /// from the inbound task, ensuring that the message is valid and can be processed.
    /// It performs signature verification to authenticate the sender and prevent
    /// impersonation attacks.
    ///
    /// ## Verification Process
    /// 1. Refreshes sender identities from the session
    /// 2. Finds the matching session identity for the sender
    /// 3. Extracts the signing public key from the identity
    /// 4. Verifies the message signature using the public key
    /// 5. Falls back to rotated keys if verification fails
    /// 6. Decodes the ratchet message for further processing
    ///
    /// ## Signature Verification
    /// - Primary verification uses the sender's current signing key
    /// - Fallback verification uses rotated keys if available
    /// - Invalid signatures result in authentication failure
    /// - Missing signatures are treated as security violations
    ///
    /// ## Security Considerations
    /// - Message signatures prevent impersonation and tampering
    /// - Key rotation is handled gracefully with fallback verification
    /// - Invalid messages are rejected to prevent attacks
    /// - Session identity validation ensures proper routing
    ///
    /// - Parameters:
    ///   - session: The current `PQSSession` in which the message verification is taking place.
    ///              Provides access to identity management and cryptographic keys.
    ///   - inboundTask: The `InboundTaskMessage` containing the encrypted message to be verified.
    ///                  Includes sender information and the signed message data.
    /// - Returns: A tuple containing the verified `RatchetMessage` and the associated `SessionIdentity`.
    /// - Throws: An error if the verification or decryption fails due to issues such as invalid message format,
    ///           session errors, or decryption errors.
    /// Host-inserted inbound recovery placeholders use `.waitingDelivery` / `.failed` until
    /// an orphan resend decrypts into the same logical sharedId.
    static func isReplaceableInboundRecoveryPlaceholder(
        _ props: EncryptedMessage.UnwrappedProps
    ) -> Bool {
        switch props.deliveryState {
        case .waitingDelivery, .failed:
            return true
        default:
            return false
        }
    }

    private func verifyEncryptedMessage(
        session: PQSSession,
        inboundTask: InboundTaskMessage
    ) async throws -> VerificationResult {
        var identities = try await session.refreshIdentities(secretName: inboundTask.senderSecretName)
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        
        let preferredDevice = await currentDeviceConfiguration(
            secretName: inboundTask.senderSecretName,
            deviceId: inboundTask.senderDeviceId,
            session: session)
        var sessionIdentity = await bestSessionIdentity(
            secretName: inboundTask.senderSecretName,
            deviceId: inboundTask.senderDeviceId,
            in: identities,
            symmetricKey: databaseSymmetricKey,
            preferredDevice: preferredDevice)
        
        if sessionIdentity == nil { // SessionIdentity shouldn't be nil, but in case refresh never occured force it.
            identities = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
            sessionIdentity = await bestSessionIdentity(
                secretName: inboundTask.senderSecretName,
                deviceId: inboundTask.senderDeviceId,
                in: identities,
                symmetricKey: databaseSymmetricKey,
                preferredDevice: preferredDevice)
        }
        
        guard let sessionIdentity else {
            throw JobProcessorErrors.missingIdentity
        }
        
        // Unwrap properties and retrieve the public signing key
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw JobProcessorErrors.missingIdentity
        }
        let currentKey = try Curve25519.Signing.PublicKey(rawRepresentation: props.signingPublicKey)
        
        // Verify the signature
        guard let signedMessage = inboundTask.message.signed else {
            throw PQSError.missingSignature
        }
        
        if try signedMessage.verifySignature(using: currentKey) {
            return try decode(signedMessage)
        } else {
            // Signature verification failed with current key, likely due to key rotation
            let refreshedIdentities = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
            
            // Find the refreshed identity with updated keys
            guard let refreshed = await bestSessionIdentity(
                secretName: inboundTask.senderSecretName,
                deviceId: inboundTask.senderDeviceId,
                in: refreshedIdentities,
                symmetricKey: databaseSymmetricKey,
                preferredDevice: preferredDevice)
            else {
                throw PQSError.invalidSignature
            }
            
            guard let refreshedProps = await refreshed.props(symmetricKey: databaseSymmetricKey) else {
                throw JobProcessorErrors.missingIdentity
            }
            let refreshedKey = try Curve25519.Signing.PublicKey(rawRepresentation: refreshedProps.signingPublicKey)
            
            guard try signedMessage.verifySignature(using: refreshedKey) else {
                let archivedIdentities = try await session.fetchArchivedSessionIdentities(
                    secretName: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)
                for archived in archivedIdentities {
                    guard let archivedProps = await archived.props(symmetricKey: databaseSymmetricKey) else {
                        continue
                    }
                    guard let archivedKey = try? Curve25519.Signing.PublicKey(rawRepresentation: archivedProps.signingPublicKey) else {
                        continue
                    }
                    if try signedMessage.verifySignature(using: archivedKey) {
                        logger.log(
                            level: .info,
                            message: "Verified inbound message from archived SessionIdentity for \(inboundTask.senderSecretName) (\(inboundTask.senderDeviceId))")
                        return try decode(signedMessage, identity: archived)
                    }
                }
                throw PQSError.invalidSignature
            }
            
            return try decode(signedMessage, identity: refreshed)
        }
        func decode(_
                    signedMessage: SignedRatchetMessage.Signed,
                    identity: SessionIdentity? = nil
        ) throws -> VerificationResult {
            let message = try BinaryDecoder().decode(RatchetMessage.self, from: signedMessage.data)
            return VerificationResult(
                ratchetMessage: message,
                sessionIdentity: identity ?? sessionIdentity)
        }
    }
    
    /// The data need to result in from a message verification
    private struct VerificationResult: Sendable {
        let ratchetMessage: RatchetMessage
        let sessionIdentity: SessionIdentity //Still will be the old session identity, this will get updated in the Double Ratchet.
    }
    
    private enum SessionReestablishmentDisposition {
        case ignore
        case refreshOnly
        case rotateCurrentDevice
        case compromiseObserved
    }
    
    private func sessionReestablishmentDisposition(
        for kind: SessionReestablishmentKind,
        inboundTask: InboundTaskMessage,
        decodedMessage: CryptoMessage,
        context: SessionContext
    ) throws -> SessionReestablishmentDisposition {
        switch kind {
        case .peerRefresh:
            return .refreshOnly
        case .linkedDeviceRepair, .linkedDeviceCompromiseObserved:
            guard decodedMessage.recipient == .personalMessage else { return .ignore }
            guard inboundTask.senderSecretName == context.sessionUser.secretName else { return .ignore }
            guard inboundTask.senderDeviceId != context.sessionUser.deviceId else { return .ignore }
            
            let verifiedDevices = try context.activeUserConfiguration.getVerifiedDevices()
            guard verifiedDevices.contains(where: { $0.deviceId == inboundTask.senderDeviceId }) else {
                return .ignore
            }
            
            switch kind {
            case .linkedDeviceRepair:
                return .rotateCurrentDevice
            case .linkedDeviceCompromiseObserved:
                return .compromiseObserved
            case .peerRefresh:
                return .refreshOnly
            }
        }
    }

    private func shouldAcceptLinkedDeviceReprovisioning(
        bundle: LinkedDeviceReprovisioningBundle,
        inboundTask: InboundTaskMessage,
        decodedMessage: CryptoMessage,
        context: SessionContext
    ) throws -> Bool {
        guard decodedMessage.recipient == .personalMessage else { return false }
        guard inboundTask.senderSecretName == context.sessionUser.secretName else { return false }
        guard inboundTask.senderDeviceId == bundle.issuedByDeviceId else { return false }
        guard bundle.targetDeviceId == context.sessionUser.deviceId else { return false }

        let verifiedDevices = try context.activeUserConfiguration.getVerifiedDevices()
        guard let senderDevice = verifiedDevices.first(where: { $0.deviceId == inboundTask.senderDeviceId }) else {
            return false
        }
        return senderDevice.isMasterDevice
    }

    private func performPendingLinkedDeviceRepair(session: PQSSession) async throws {
        guard let refreshedContext = await session.sessionContext else { return }
        guard let currentDevice = try refreshedContext.activeUserConfiguration
            .getVerifiedDevices()
            .first(where: { $0.deviceId == refreshedContext.sessionUser.deviceId }) else {
            throw PQSError.invalidDeviceIdentity
        }
        if currentDevice.isMasterDevice {
            logger.log(level: .info, message: "Master device received linked-device repair request; refreshing identities only")
            await session.setPendingLinkedDeviceRepair(false)
        } else {
            try await session.rotateCurrentDeviceKeys()
            await session.setPendingLinkedDeviceRepair(false)
        }
    }
    
    /// Signs a ratchet message using the cryptographic session's signing capabilities.
    ///
    /// This method ensures the integrity and authenticity of the ratchet message by applying
    /// a digital signature using the device's signing private key. The signature prevents
    /// tampering and impersonation attacks during message transmission.
    ///
    /// ## Signing Process
    /// 1. Extracts the device's signing private key from session context
    /// 2. Creates a `SignedRatchetMessage` containing the original message and signature
    /// 3. Returns the signed message ready for transmission
    ///
    /// ## Security Considerations
    /// - Signing keys are stored encrypted in session context
    /// - Signatures use Curve25519 for strong cryptographic security
    /// - Message integrity is preserved through the signing process
    /// - Signing failures indicate serious cryptographic issues
    ///
    /// ## Usage Context
    /// Called during outbound message processing to ensure message authenticity
    /// before transmission through the transport layer.
    ///
    /// - Parameters:
    ///   - message: The `RatchetMessage` that needs to be signed. Contains the
    ///              encrypted message data and ratchet headers.
    ///   - session: The current `PQSSession` used to access the signing keys and
    ///              perform the signing operation.
    /// - Returns: A `SignedRatchetMessage` that contains the original ratchet message
    ///            along with its digital signature.
    /// - Throws: An error if the signing process fails due to issues such as missing signing keys,
    ///           session errors, or cryptographic errors.
    func signRatchetMessage(message: RatchetMessage, session: PQSSession) async throws -> SignedRatchetMessage {
        guard let deviceKeys = await session.sessionContext?.sessionUser.deviceKeys else {
            throw PQSError.sessionNotInitialized
        }
        return try SignedRatchetMessage(
            message: message,
            signingPrivateKey: deviceKeys.signingPrivateKey
        )
    }
}

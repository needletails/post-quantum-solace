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
        // A waiting token makes this job the frame's archive pass. It is spent before
        // any exit: a frame dropped below never reaches the pass, and the evidence the
        // token carries must not outlive the job.
        let frameFingerprint = PQSSession.nackFrameFingerprint(for: inboundTask)
        let carriedFailures = archivedInboundFallbackPasses.removeValue(forKey: ArchivedInboundFallbackToken(
            senderSecretName: inboundTask.senderSecretName,
            senderDeviceId: inboundTask.senderDeviceId,
            envelopeMessageId: inboundTask.sharedMessageId,
            fingerprint: frameFingerprint).storageKey)

        // T13: accepted-envelope ledger covers non-persisted successes (nudgeLocal).
        // Re-emit spool ACK; never re-enter ratchet / NACK / remint.
        // The envelope id is transport metadata and a replay can carry a fresh
        // one, so the ledger is also asked by the signed payload: an accepted
        // frame must never reach lane selection again, where its still-valid
        // PQXDH header could bootstrap a blank and demote the established lane.
        // The ledger knows these bytes, not the chat row they name, so a resend
        // pending for the logical id stays for the drain to settle.
        if try await session.hasAcceptedEnvelope(
            senderSecretName: inboundTask.senderSecretName,
            senderDeviceId: inboundTask.senderDeviceId,
            envelopeMessageId: inboundTask.sharedMessageId,
            frameFingerprint: PQSSession.frameFingerprintDigest(for: inboundTask)
        ) {
            audit(.recovery, "pqs.recovery.redeliveryDropped reason=alreadyAccepted sharedId=\(inboundTask.sharedMessageId) logical=\(inboundTask.resolvedLogicalSharedId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
            await acknowledgeAcceptedInbound(inboundTask, session: session)
            return
        }

        let verificationResult = try await verifyEncryptedMessage(session: session, inboundTask: inboundTask)
        let inboundHeader = verificationResult.ratchetMessage.header
        let rollbackSymmetricKey = try await session.getDatabaseSymmetricKey()
        var laneStats = InboundLaneSelectionStats(
            sharedId: inboundTask.sharedMessageId,
            pass: .activeFirst,
            fingerprint: frameFingerprint)

        // One store read and one props decrypt per row for the whole frame. The
        // rollback set, the active/archived split, the blank dedupe and the header
        // match all read from this list instead of re-decrypting per filter.
        var peerLanes: [InboundLane] = []
        for identity in try await session.cache?.fetchSessionIdentities() ?? [] {
            laneStats.identityRowsScanned += 1
            laneStats.propsDecrypts += 1
            guard let props = await identity.props(symmetricKey: rollbackSymmetricKey),
                  props.secretName == inboundTask.senderSecretName,
                  props.deviceId == inboundTask.senderDeviceId
            else { continue }
            peerLanes.append(InboundLane(identity: identity, props: props, header: inboundHeader))
        }
        let rollbackPeerIdentities = peerLanes.map(\.identity)
        // The host store owns row uniqueness; a duplicate id must not trap inbound.
        let rollbackIdentityData = Dictionary(
            rollbackPeerIdentities.map { ($0.id, $0.data) },
            uniquingKeysWith: { _, last in last })
        
        // Set when no lane can open this frame and no pass is left to try.
        var decryptFailedTerminally = false

        // Everything up until this point delt with message recovery, meaning if a message was in a state of non recovery then we tried to recover that message stored in the SessionWorkCoordinator(via 2 different enqueue methods scheduleTransportProtocolWork and scheduleBackgroundWork messages use scheduleBackgroundWork via setConnectivity which reloads the job queue) ran on the background if we are a new message all of that recovery work is skipped and we start here.
        do {
            // Inbound decrypt: try the preferred/current session if it has state,
            // then other actives, inactive sessions, then state-less rows. Whichever
            // decrypts becomes current (activate = promote inactive / demote sibling
            // actives).
            let preferredSessionIdentity = verificationResult.sessionIdentity
            let preferredLane: InboundLane
            if let lane = peerLanes.first(where: { $0.identity.id == preferredSessionIdentity.id }) {
                preferredLane = lane
            } else {
                laneStats.propsDecrypts += 1
                guard let props = await preferredSessionIdentity.props(symmetricKey: rollbackSymmetricKey) else {
                    throw DoubleRatchetKit.CryptoError.propsError
                }
                preferredLane = InboundLane(identity: preferredSessionIdentity, props: props, header: inboundHeader)
            }
            var decryptionSessionIdentity = preferredSessionIdentity
            // Per-candidate failure classes for the rollback audit and terminal
            // error. Without this the try-all loop swallows every alternate.
            var attemptFailures: [InboundAttemptFailure] = []
            let frameEpochHolders = (peerLanes + [preferredLane]).filter(\.holdsFrameEpoch)

            var decryptedData: Data
            if preferredLane.hasRatchetState, let data = await attemptInboundDecrypt(
                preferredLane, kind: "preferred", frame: verificationResult, fingerprint: frameFingerprint,
                frameEpochHolders: frameEpochHolders, session: session, stats: &laneStats, failures: &attemptFailures)
            {
                decryptedData = data
            } else {
                // Inbound try-all: stateful Active → archived rows that belong to the
                // frame → state-less rows, the preferred one included → ensured blank.
                // Blank PQXDH runs only on state-less rows already in (or ensured into)
                // the device record — not a gated post-failure matching mint.
                //
                // Within each tier, lanes whose stored remote keys match the frame
                // header go first (stable), so the common case decrypts on the first
                // or second attempt. Tiers never reorder against each other.
                //
                // activeFirstInboundPass: try actives, the archived rows holding the
                // frame's epoch and state-less rows first. The full archive walk is
                // deferred to a `.background` job via deferArchivedInboundFallback so
                // fresher `.urgent` ciphertext is not HOL-blocked on the single consumer.
                let alternates = peerLanes.filter { !$0.isArchived && $0.identity.id != preferredSessionIdentity.id }
                let statefulAlternates = InboundLaneSelectionPolicy.orderedByHeaderMatch(
                    alternates.filter(\.hasRatchetState), rank: \.headerMatch.rank)
                let stateLessAlternates = InboundLaneSelectionPolicy.orderedByHeaderMatch(
                    alternates.filter { !$0.hasRatchetState }, rank: \.headerMatch.rank)
                // Archives newest-first (sessionContextId desc), then header match.
                let archivedLanes = InboundLaneSelectionPolicy.orderedByHeaderMatch(
                    peerLanes.filter(\.isArchived).sorted { $0.props.sessionContextId > $1.props.sessionContextId },
                    rank: \.headerMatch.rank)
                let archivedBlanks = archivedLanes.filter { !$0.hasRatchetState }
                let stateLessPreferred = preferredLane.hasRatchetState ? [] : [(lane: preferredLane, kind: "preferred")]
                // Active-first never walks full archives, but blankForHeaderExists
                // counts archived blanks. Include the single header-matched archived
                // blank in the active pass so demoted blanks are not invisible until
                // a (possibly exhausted) archive defer.
                let headerMatchedArchivedBlank = archivedBlanks.first(where: \.matchesHeaderKeys)

                let includeArchivedFallback = carriedFailures != nil
                if includeArchivedFallback {
                    laneStats.pass = .archived
                }
                // Mark exhausted when this pass actually walks archives (success or
                // total failure). Prevents re-defer on the same ciphertext.
                let shouldMarkArchivePassExhausted = includeArchivedFallback

                var fallbackData: Data?
                let candidates: [(lane: InboundLane, kind: String)]
                if includeArchivedFallback {
                    // Background pass: archives only (actives already failed), and
                    // every stateful row before a blank can be judged against it.
                    candidates = (archivedLanes.filter(\.hasRatchetState) + archivedBlanks)
                        .map { (lane: $0, kind: "archived") } + stateLessPreferred
                } else {
                    // activeFirstInboundPass — decryptInboundActiveOnly candidates,
                    // the archived rows that belong to this frame (holders of its epoch,
                    // then the header-matched archived blank when policy allows), then
                    // state-less rows.
                    var activeFirstCandidates =
                        statefulAlternates.map { (lane: $0, kind: "active") }
                        + archivedLanes.filter(\.holdsFrameEpoch).map { (lane: $0, kind: "archivedHolder") }
                    if let matched = headerMatchedArchivedBlank,
                       InboundInitiatingSlotPolicy.shouldTryArchivedHeaderMatchBeforeEnsureSkip(
                           blankForHeaderExists: true,
                           matchedIsArchived: true,
                           includeArchivedFallback: false)
                    {
                        activeFirstCandidates.append((lane: matched, kind: "archivedHeaderMatch"))
                    }
                    candidates = activeFirstCandidates
                        + stateLessPreferred
                        + stateLessAlternates.map { (lane: $0, kind: "stateLess") }
                }
                for candidate in candidates {
                    guard let data = await attemptInboundDecrypt(
                        candidate.lane, kind: candidate.kind, frame: verificationResult, fingerprint: frameFingerprint,
                        frameEpochHolders: frameEpochHolders, session: session, stats: &laneStats, failures: &attemptFailures)
                    else { continue }
                    logger.log(
                        level: .info,
                        message: "\(candidate.kind) identity fallback succeeded for \(inboundTask.senderSecretName) (\(inboundTask.senderDeviceId))")
                    decryptionSessionIdentity = candidate.lane.identity
                    fallbackData = data
                    break
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
                    let preferredProps = preferredLane.props
                    var blankRows = stateLessAlternates
                    if !preferredProps.hasRatchetState {
                        blankRows.append(preferredLane)
                    }
                    // Archived blanks count too: a prior ensured blank demoted by a
                    // sibling's activation is still in the try-all set above, so a
                    // fresh mint for the same header would fail identically. Without
                    // this, every activate-then-fail cycle mints a new blank whose
                    // archival evicts a real stateful snapshot at the retention cap.
                    blankRows.append(contentsOf: archivedBlanks)
                    let blankForHeaderExists = blankRows.contains(where: \.matchesHeaderKeys)
                    if !InboundInitiatingSlotPolicy.shouldEnsureInboundBlank(
                        blankForHeaderExists: blankForHeaderExists)
                    {
                        audit(.recovery, "pqs.recovery.inboundInitiatingSlotEnsureSkipped reason=blankForHeaderExists peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
                    } else {
                        do {
                            let ensured = try await session.ensureInboundInitiatingSessionIdentity(
                                secretName: inboundTask.senderSecretName,
                                deviceId: inboundTask.senderDeviceId,
                                longTermPublicKey: inboundHeader.remoteLongTermPublicKey,
                                signingPublicKey: preferredProps.signingPublicKey,
                                oneTimePublicKey: inboundHeader.remoteOneTimePublicKey,
                                mlKEMPublicKey: inboundHeader.remoteMLKEMPublicKey,
                                deviceNameHint: preferredProps.deviceName)
                            audit(.recovery, "pqs.recovery.inboundInitiatingSlotEnsured peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) sessionId=\(ensured.id.uuidString)")
                            laneStats.identityRowsScanned += 1
                            laneStats.propsDecrypts += 1
                            if let ensuredProps = await ensured.props(symmetricKey: rollbackSymmetricKey),
                               let data = await attemptInboundDecrypt(
                                   InboundLane(identity: ensured, props: ensuredProps, header: inboundHeader),
                                   kind: "ensured", frame: verificationResult, fingerprint: frameFingerprint,
                                   frameEpochHolders: frameEpochHolders, session: session, stats: &laneStats, failures: &attemptFailures)
                            {
                                logger.log(
                                    level: .info,
                                    message: "stateLess identity fallback succeeded for \(inboundTask.senderSecretName) (\(inboundTask.senderDeviceId))")
                                decryptionSessionIdentity = ensured
                                fallbackData = data
                            }
                        } catch {
                            logger.log(
                                level: .warning,
                                message: "pqs.recovery.inboundInitiatingSlotEnsureFailed peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) error=\(error)")
                            audit(.recovery, "pqs.recovery.inboundInitiatingSlotEnsureFailed peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) error=\(error)")
                        }
                    }
                }

                guard let data = fallbackData else {
                    if shouldMarkArchivePassExhausted {
                        markArchivedInboundFallbackExhausted(
                            sharedId: inboundTask.sharedMessageId,
                            sender: inboundTask.senderSecretName,
                            deviceId: inboundTask.senderDeviceId,
                            fingerprint: frameFingerprint)
                    }
                    // Active-first miss with archives remaining: defer archive try-all
                    // to a background job so urgent inbound can proceed.
                    var archivePassQueued = false
                    if !includeArchivedFallback, !archivedLanes.isEmpty {
                        archivePassQueued = await deferArchivedInboundFallback(
                            inboundTask: inboundTask,
                            failures: attemptFailures,
                            session: session)
                    }
                    // The pass cannot learn again what active-first learned (the ensured
                    // blank left with that job), so its verdicts join the pass's. A lane
                    // tried in both passes speaks once, with the newer verdict.
                    if let carriedFailures {
                        let retriedLanes = Set(attemptFailures.map(\.laneId))
                        attemptFailures += carriedFailures.filter { !retriedLanes.contains($0.laneId) }
                    }
                    // Inbound decrypt: no session decrypted. Every failed lane was
                    // already rolled back by `attemptInboundDecrypt`; nothing else was mutated.
                    recordInboundLaneSelectionStats(laneStats)
                    let headerAudit = RatchetHeaderAudit(inboundHeader)
                    let deviceKeys = await session.sessionContext?.sessionUser.deviceKeys
                    audit(.recovery, "pqs.recovery.laneRolledBack reason=active and archived inbound decrypt attempts failed peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) \(headerAudit.inboundFields) \(deviceKeys.map { headerAudit.heldFields(deviceKeys: $0, rows: peerLanes.map(\.props) + [preferredLane.props]) } ?? "otkHeld=unknown mlkemHeld=unknown") attempts=[\(attemptFailures.map { "\($0.label):\($0.error)" }.joined(separator: "; "))] negativeCacheSkips=\(laneStats.negativeCacheSkips)")
                    // The queued pass owns this frame's outcome; see `InboundDecryptDeferral`.
                    if archivePassQueued {
                        throw InboundDecryptDeferral.archivePassQueued
                    }
                    // Do NOT write the failed try-first id into the preference map here.
                    // Dogfood 2026-07-25: that armed preferredFailedInTryAll on every
                    // poison redelivery, and the demote it drove walked unique session
                    // ids (nudge primary: 92 demotes / 4k blankForHeader skips against
                    // linked). Preference stays success-only.
                    decryptFailedTerminally = true
                    throw InboundRecoveryStormPolicy.terminalTryAllError(attempts: attemptFailures)
                }
                if shouldMarkArchivePassExhausted {
                    markArchivedInboundFallbackExhausted(
                        sharedId: inboundTask.sharedMessageId,
                        sender: inboundTask.senderSecretName,
                        deviceId: inboundTask.senderDeviceId,
                        fingerprint: frameFingerprint)
                }
                decryptedData = data
            }
            // The winning lane's ratchet advanced: its recorded rejections are stale.
            inboundNegativeDecryptCache.invalidate(laneId: decryptionSessionIdentity.id)
            laneStats.winningLaneId = decryptionSessionIdentity.id
            recordInboundLaneSelectionStats(laneStats)

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

            // A copy of content this device holds has done its work on the ratchet. The
            // host saw the message when it landed, so it must not run a second time.
            let contentHeld = try await holdsInboundContent(inboundTask, session: session)
            var canSaveMessage = true
            
            if !contentHeld, let sessionDelegate = await session.sessionDelegate {
                canSaveMessage = await sessionDelegate.processMessage(
                    decodedMessage,
                    senderSecretName: inboundTask.senderSecretName,
                    senderDeviceId: inboundTask.senderDeviceId)
            }

            if !contentHeld,
               let transportInfo = decodedMessage.transportInfo,
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
                                headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId,
                                headerEpochDigest: verificationResult.ratchetMessage.header.ratchetEpochDigest)
                            return
                        }

                        // Decrypt path already activated the proven session (inbound decrypt).

                        // Receiver-side coalescing: drop duplicates and stale-epoch replays from
                        // an offline mailbox before any expensive work or delegate dispatch.
                        let dedupDecision = await session.recordReceivedSessionReestablishment(
                            envelope: envelope,
                            senderDeviceId: inboundTask.senderDeviceId,
                            senderSecretName: inboundTask.senderSecretName)

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
                                headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId,
                                headerEpochDigest: verificationResult.ratchetMessage.header.ratchetEpochDigest)
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
                                headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId,
                                headerEpochDigest: verificationResult.ratchetMessage.header.ratchetEpochDigest)
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
                            // One sibling must not be able to churn our keys (and every
                            // contact's lanes) on every frame: honor one repair per
                            // sibling per cooldown window.
                            guard await session.shouldHonorLinkedDeviceRepair(from: inboundTask.senderDeviceId) else {
                                logger.log(level: .info, message: "Linked-device repair from \(inboundTask.senderDeviceId) coalesced (cooldown)")
                                break
                            }
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
                                        headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId,
                                        headerEpochDigest: verificationResult.ratchetMessage.header.ratchetEpochDigest)
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
                                        senderDeviceId: inboundTask.senderDeviceId,
                                        senderSecretName: inboundTask.senderSecretName)
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
                                headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId,
                                headerEpochDigest: verificationResult.ratchetMessage.header.ratchetEpochDigest)
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
                        // The payload ids are peer-supplied. Only the one-time keys
                        // the verified ratchet header actually cites are retired, and
                        // only their published halves: the private halves stay until
                        // deferred consumption confirms the reverse handshake.
                        try await retireCitedOneTimeKeys(
                            session: session,
                            headerOneTimeKeyId: verificationResult.ratchetMessage.header.oneTimeKeyId,
                            headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId,
                            claimed: info,
                            senderSecretName: inboundTask.senderSecretName,
                            senderDeviceId: inboundTask.senderDeviceId)
                        canSaveMessage = false
                    case .refreshOneTimeKeys:
                        canSaveMessage = false
                        // Any contact can ask; a flood must not cost a keygen + upload
                        // per frame. Within the cooldown the pool is still fresh from the
                        // previous replenish, so just acknowledge.
                        guard await session.shouldHonorInboundOneTimeKeyRefresh(from: inboundTask.senderSecretName) else {
                            logger.log(level: .info, message: "refreshOneTimeKeys from \(inboundTask.senderSecretName) coalesced (cooldown); acknowledging")
                            try await session.ackPublishedOneTimeKeysReplenished(to: inboundTask.senderSecretName)
                            break
                        }
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
                            senderDeviceId: inboundTask.senderDeviceId,
                            senderSecretName: inboundTask.senderSecretName)
                    }
                    logger.log(level: .error, message: "Error handling transport event from \(inboundTask.senderSecretName): \(error)")
                    throw error
                }
            }

            var didAcceptInbound = false
            if canSaveMessage {
                if contentHeld {
                    audit(.recovery, "pqs.recovery.duplicateInboundPersistSkipped envelope=\(inboundTask.sharedMessageId) logical=\(inboundTask.resolvedLogicalSharedId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
                } else {
                    /// Now we can handle the message
                    try await handleDecodedMessage(
                        decodedMessage,
                        inboundTask: inboundTask,
                        session: session,
                        sessionIdentity: decryptionSessionIdentity)
                }
                // A held copy can be stale: the row that opened it may be one the sender
                // has left, so it takes no lane back. A state-less row is different, the
                // frame just bootstrapped it and the sender is on that lane.
                let bootstrappedLane = !(peerLanes + [preferredLane]).contains {
                    $0.identity.id == decryptionSessionIdentity.id && $0.hasRatchetState
                }
                decryptionSessionIdentity = try await finalizeAcceptedInbound(
                    decryptionSessionIdentity,
                    inboundTask: inboundTask,
                    session: session,
                    headerOneTimeKeyId: verificationResult.ratchetMessage.header.oneTimeKeyId,
                    headerMLKEMOneTimeKeyId: verificationResult.ratchetMessage.header.mlKEMOneTimeKeyId,
                    headerEpochDigest: verificationResult.ratchetMessage.header.ratchetEpochDigest,
                    activateLane: !contentHeld || bootstrappedLane,
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
                    headerEpochDigest: verificationResult.ratchetMessage.header.ratchetEpochDigest,
                    acknowledgeTransport: false)
                didAcceptInbound = true
                // Persist branch settles pending resend under `if canSaveMessage`
                // below. Non-persist accepts must clear this frame's own NACK too,
                // or later drains re-NACK an already-accepted envelope until
                // the resend cap. Match by logical id as well: a sender
                // resend of a failed control frame arrives under a new envelope id.
                await session.settlePendingResendsForAcceptedInbound(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    envelopeMessageId: inboundTask.sharedMessageId,
                    logicalSharedId: inboundTask.resolvedLogicalSharedId)
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

                // Settle the deferred NACK this frame satisfies *before* taking the
                // lane for drain. A sender resend (S12) carries the original logical
                // id under a new envelope id; matching only `satisfiedSharedMessageId`
                // (envelope) re-drained the original envelope's NACK on every
                // successful decrypt and every replay boundary.
                await session.settlePendingResendsForAcceptedInbound(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    envelopeMessageId: inboundTask.sharedMessageId,
                    logicalSharedId: inboundTask.resolvedLogicalSharedId)
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
                            logicalSharedId: pendingRequest.logicalSharedId,
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
            // No lane opens this copy, but the content is here, so the sender owes
            // nothing: every NACK still pending for it is answered, whichever envelope
            // carried this copy. A sender resend arrives under a new envelope id, and a
            // host re-arm is keyed by the chat row's logical id. Left pending, the id was
            // re-NACKed at every drain boundary until the cap wrote it off and told the
            // author "failed" (dogfood 2026-10-28, C653BE44 on the master). Only a
            // terminal decrypt failure lands here: a queued pass still owns the frame,
            // and a failure after a decrypt must stay retryable.
            if decryptFailedTerminally, (try? await holdsInboundContent(inboundTask, session: session)) == true {
                audit(.recovery, "pqs.recovery.redeliveryDropped reason=alreadyPersisted sharedId=\(inboundTask.sharedMessageId) logical=\(inboundTask.resolvedLogicalSharedId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
                try await session.markEnvelopeAccepted(inboundTask)
                await session.settlePendingResendsForAcceptedInbound(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    envelopeMessageId: inboundTask.sharedMessageId,
                    logicalSharedId: inboundTask.resolvedLogicalSharedId)
                await acknowledgeAcceptedInbound(inboundTask, session: session)
                return
            }
#if DEBUG
            logger.log(
                level: .debug,
                message: "pqs.recovery.decryptAttemptFailed sharedId=\(inboundTask.sharedMessageId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) action=handOffToRecoveryPolicy error=\(error)")
#endif
            throw error
        }
    }

    /// Whether this device already holds the content `inboundTask` carries: a chat row
    /// for its logical id from this sender tuple that the host does not call a recovery
    /// placeholder. It is asked after decrypt, never in place of it: the id is
    /// unauthenticated wire metadata, and a frame dropped before the ratchet leaves a
    /// header gap and throws away a resend opening a new lane. With no delegate the row
    /// is not known to be content, so nothing is dropped on its account.
    private func holdsInboundContent(
        _ inboundTask: InboundTaskMessage,
        session: PQSSession
    ) async throws -> Bool {
        guard let existing = try await session.cache?.fetchMessageIfExists(sharedId: inboundTask.resolvedLogicalSharedId),
              let props = await existing.props(symmetricKey: try await session.getDatabaseSymmetricKey()),
              props.senderSecretName == inboundTask.senderSecretName,
              props.senderDeviceId == inboundTask.senderDeviceId
        else { return false }
        return await session.sessionDelegate?.isInboundRecoveryPlaceholder(
            transportInfo: props.message.transportInfo) == false
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
        headerEpochDigest: Data? = nil,
        activateLane: Bool = true,
        acknowledgeTransport: Bool = true
    ) async throws -> SessionIdentity {
        // A frame from an epoch the row has since moved past is a late frame opened from the
        // row's stash. It proves the row could open it, not that the peer sends on the row
        // now, so it neither promotes the row nor makes it the outbound preference. Without
        // this, frames a peer sent before our rotation steered our next send back onto the
        // lane the peer had dropped.
        var rowEpochDigest: Data?
        if let headerEpochDigest, let cache = await session.cache,
           let row = try await cache.fetchSessionIdentities().first(where: { $0.id == decryptionSessionIdentity.id }) {
            rowEpochDigest = try await row.props(symmetricKey: session.getDatabaseSymmetricKey())?.ratchetEpochDigest
        }
        let frameOnRowEpoch = headerEpochDigest == nil || rowEpochDigest == nil || headerEpochDigest == rowEpochDigest
        if !frameOnRowEpoch {
            audit(.recovery, "pqs.recovery.laneNotProvenByEarlierEpochFrame sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) sessionId=\(decryptionSessionIdentity.id)")
        }
        let activated = activateLane && frameOnRowEpoch
            ? try await session.activateSessionIdentityAfterInboundDecrypt(decryptionSessionIdentity)
            : decryptionSessionIdentity
        // Do not publish preference / clear recovery state until the durable
        // accepted ledger write succeeds. The outer catch restores identity
        // inventory if persistence fails.
        try await session.markEnvelopeAccepted(inboundTask)
        // Deferred OTK consumption is driven only by committed frames, so a
        // rolled-back decrypt can neither record nor confirm a consumption.
        await noteAcceptedInboundForDeferredOneTimeKeyConsumption(
            laneId: activated.id,
            headerOneTimeKeyId: headerOneTimeKeyId,
            headerMLKEMOneTimeKeyId: headerMLKEMOneTimeKeyId,
            session: session)
        // Only an active lane may become the outbound preference; a decrypt-only
        // archive (promotion refused) must not capture general outbound.
        let activatedIsActive = try await activated.props(symmetricKey: session.getDatabaseSymmetricKey())
            .map { !$0.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) } ?? false
        if activatedIsActive, frameOnRowEpoch {
            preferredSessionIdentityIdByPeerDevice[
                peerDeviceIdentityPreferenceKey(
                    secretName: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)
            ] = activated.id
        }
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
            // The ledger rules live in `DeviceKeys.applyCommittedInboundFrame`;
            // they run inside the exclusive session-context commit so a
            // concurrent one-time-key batch commit is never rolled back.
            guard let outcome = try await session.commitDeferredOneTimeKeyConsumption(
                laneId: laneId,
                headerOneTimeKeyId: headerOneTimeKeyId,
                headerMLKEMOneTimeKeyId: headerMLKEMOneTimeKeyId)
            else { return }
            if let recorded = outcome.recordedPending {
                audit(.recovery, "pqs.otk.consumptionPending lane=\(laneId.uuidString) otkId=\(recorded.oneTimeKeyId?.uuidString ?? "nil") mlkemId=\(recorded.mlKEMOneTimeKeyId?.uuidString ?? "nil")")
            }
            for entry in outcome.confirmed {
                let trigger = headerOneTimeKeyId == nil ? "reverseHandshake" : "laneRekey"
                audit(.recovery, "pqs.otk.consumedAfterConfirmation trigger=\(trigger) lane=\(laneId.uuidString) otkId=\(entry.oneTimeKeyId?.uuidString ?? "nil") mlkemId=\(entry.mlKEMOneTimeKeyId?.uuidString ?? "nil")")
            }
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
    /// cannot consume an older archive-only pass (T17). The token carries `failures`,
    /// this pass's verdicts, to the pass that decides the frame's class.
    ///
    /// - Returns: `true` when this call queued the pass, which then owns this
    ///   ciphertext's outcome. `false` when the pass already ran for this token or
    ///   the enqueue failed; the caller's failure then stands as the frame's outcome.
    private func deferArchivedInboundFallback(
        inboundTask: InboundTaskMessage,
        failures: [InboundAttemptFailure],
        session: PQSSession
    ) async -> Bool {
        let sharedId = inboundTask.sharedMessageId
        let currentFingerprint = PQSSession.nackFrameFingerprint(for: inboundTask)
        let token = ArchivedInboundFallbackToken(
            senderSecretName: inboundTask.senderSecretName,
            senderDeviceId: inboundTask.senderDeviceId,
            envelopeMessageId: sharedId,
            fingerprint: currentFingerprint)
        guard InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
            token: token,
            exhausted: archivedInboundFallbackExhausted
        ) else {
            return false
        }
        archivedInboundFallbackPasses[token.storageKey] = failures
        audit(.recovery, "pqs.recovery.deferArchivedInboundFallback sharedId=\(sharedId) token=\(token.storageKey.prefix(64)) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
        do {
            try await enqueue(
                EncryptableTask(
                    task: .streamMessage(inboundTask),
                    priority: .background),
                session: session)
            return true
        } catch {
            archivedInboundFallbackPasses.removeValue(forKey: token.storageKey)
            logger.log(
                level: .warning,
                message: "pqs.recovery.deferArchivedInboundFallbackFailed sharedId=\(sharedId) error=\(error)")
            return false
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

    /// Appends per-frame lane-selection accounting (DEBUG test seam, bounded).
    func recordInboundLaneSelectionStats(_ stats: InboundLaneSelectionStats) {
#if DEBUG
        inboundLaneSelectionStatsLog.append(stats)
        if inboundLaneSelectionStatsLog.count > 256 {
            inboundLaneSelectionStatsLog.removeFirst(inboundLaneSelectionStatsLog.count - 256)
        }
#endif
    }

    /// The one attempt path for every inbound candidate. A lane that already
    /// rejected this ciphertext under the same ratchet state is skipped with its
    /// recorded failure; a fresh failure is recorded and rolled back only if the
    /// attempt changed the row (the ratchet manager's lane is always evicted).
    /// A frame a state-less row decrypts is authentic under keys derived from the
    /// frame's own header and this device's keys, so with no row holding the
    /// frame's epoch it becomes the lane whatever the frame's position in the
    /// sender's chain, with the skipped keys stashed for the frames before it.
    /// Refusing it past the first frame kept authenticated content from the user
    /// and NACKed a lane that worked (dogfood 2026-10-28: 105 refusals across three
    /// devices, a channel message held 59 minutes). With a holder it must also
    /// pass `InboundLaneSelectionPolicy.blankMayBecomeLane`; refused, it rolls back
    /// to blank and the frame takes the resend path as `decryptionFailed`.
    private func attemptInboundDecrypt(
        _ lane: InboundLane,
        kind: String,
        frame: VerificationResult,
        fingerprint: Data,
        frameEpochHolders: [InboundLane],
        session: PQSSession,
        stats: inout InboundLaneSelectionStats,
        failures: inout [InboundAttemptFailure]
    ) async -> Data? {
        let laneId = lane.identity.id
        let dataBeforeAttempt = lane.identity.data
        let stateToken = lane.ratchetStateToken
        let label = "\(kind):\(laneId.uuidString.prefix(8))"
        let failure = { (error: Error) in
            InboundAttemptFailure(
                laneId: laneId,
                label: label,
                error: error,
                stateLess: !lane.hasRatchetState,
                holdsFrameEpoch: lane.holdsFrameEpoch,
                isPreferred: laneId == frame.sessionIdentity.id)
        }
        if let cached = inboundNegativeDecryptCache.cachedFailure(
            laneId: laneId, fingerprint: fingerprint, laneState: stateToken)
        {
            failures.append(failure(cached))
            stats.attempts.append(.init(laneId: laneId, kind: kind, outcome: .skippedNegativeCache, failure: "\(cached)"))
            return nil
        }
        do {
            try await initializeRecipient(
                sessionIdentity: lane.identity,
                props: lane.props,
                session: session,
                ratchetMessage: frame.ratchetMessage)
            let data = try await ratchetManager.decrypt(frame.ratchetMessage, sessionId: laneId)
            if !lane.hasRatchetState {
                let status = try await ratchetManager.sessionStatus(sessionId: laneId)
                guard InboundLaneSelectionPolicy.blankMayBecomeLane(
                    receivedMessagesCount: status.receivedMessagesCount,
                    remoteRatchetPublicKey: status.remoteRatchetPublicKey,
                    holders: frameEpochHolders.map { holder in
                        // Every failed attempt lands in the cache, whichever pass made it.
                        (rejectedFrame: inboundNegativeDecryptCache.cachedFailure(
                            laneId: holder.identity.id, fingerprint: fingerprint, laneState: holder.ratchetStateToken) != nil,
                         receivedMessagesCount: holder.props.ratchetReceivedMessagesCount,
                         remoteRatchetPublicKey: holder.props.ratchetRemotePublicKey)
                    })
                else {
                    audit(.recovery, "pqs.recovery.blankBootstrapRefused reason=replayOfConsumedFrame messageNumber=\(status.receivedMessagesCount - 1) lane=\(laneId.uuidString) kind=\(kind)")
                    throw RatchetError.decryptionFailed
                }
            }
            stats.attempts.append(.init(laneId: laneId, kind: kind, outcome: .decrypted))
            return data
        } catch {
            failures.append(failure(error))
            stats.attempts.append(.init(laneId: laneId, kind: kind, outcome: .failed, failure: "\(error)"))
            inboundNegativeDecryptCache.recordFailure(
                laneId: laneId, fingerprint: fingerprint, laneState: stateToken, error: error)
            if await rollBackFailedAttempt(
                lane.identity,
                dataBeforeAttempt: dataBeforeAttempt,
                session: session,
                reason: "inbound \(kind) decrypt attempt failed")
            {
                stats.restoreStoreWrites += 1
            } else {
                stats.restoresSkippedUnchanged += 1
            }
            return nil
        }
    }

    /// Rolls back a failed decrypt attempt. The ratchet manager's in-memory lane is
    /// always evicted; the row is written back only when the attempt changed its
    /// bytes. Returns whether a store write ran. Store errors are logged, as the
    /// fallback loop always treated them.
    func rollBackFailedAttempt(
        _ identity: SessionIdentity,
        dataBeforeAttempt: Data,
        session: PQSSession,
        reason: String
    ) async -> Bool {
        guard InboundLaneSelectionPolicy.shouldRestoreIdentityData(
            before: dataBeforeAttempt, after: identity.data)
        else {
            await ratchetManager.discardCachedLane(identity.id)
            return false
        }
        do {
            try await restoreSessionIdentityData(identity, data: dataBeforeAttempt, session: session, reason: reason)
            return true
        } catch {
            logger.log(level: .warning, message: "Failed restoring SessionIdentity after \(reason): \(error)")
            return true
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
        props frameProps: SessionIdentity.UnwrappedProps? = nil,
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
        // Lane selection already decrypted this row's props for the frame.
        var resolvedProps = frameProps
        if resolvedProps == nil {
            resolvedProps = await sessionIdentity.props(symmetricKey: databaseSymmetricKey)
        }
        guard let props = resolvedProps else {
            throw DoubleRatchetKit.CryptoError.propsError
        }
        
        let localPrivateKeys = sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys
        let localMLKEMPrivateKeys = sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys
        
        if let oneTimeKeyId = ratchetMessage.header.oneTimeKeyId {
            if let privateOneTimeKey = localPrivateKeys.first(where: { $0.id == oneTimeKeyId }) {
                localOneTimePrivateKey = privateOneTimeKey
            } else if let storedOTK = props.ratchetOneTimePrivateKey, storedOTK.id == oneTimeKeyId {
                localOneTimePrivateKey = storedOTK
            } else if props.hasRatchetState {
                // Established lane citing an id this device no longer holds. Keep the
                // lane's own copy (if any) untouched and let the ratchet decide: a
                // chain frame decrypts without the private half, only a handshake or
                // epoch re-key fails fast.
                localOneTimePrivateKey = props.ratchetOneTimePrivateKey
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
            } else if let finalKey = sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey(matching: mlKEMOneTimeKeyId) {
                // Current final key, or the single generation retired by the last routine
                // rotation (a bootstrap encapsulated to the bundle the sender held then).
                localMLKEMPrivateKey = finalKey
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
        let mySecretName = await session.sessionContext?.sessionUser.secretName
        let conversationType = Self.inboundConversationType(
            recipient: decodedMessage.recipient,
            sender: inboundTask.senderSecretName,
            mySecretName: mySecretName)

        // Held content stopped in `handleStreamMessage`, so a row here for this logical
        // id and sender tuple is not known to be content: it is a recovery placeholder,
        // or no delegate was there to say. One sharedId from one sender tuple is one chat
        // row, so the frame replaces it in place on heal: inserting would mint a second
        // row with a fresh UUID. The sender-tuple match keeps this from ever colliding
        // with a *different* sender's frame or with our own outbound record for the same
        // conversation.
        var misfiledPlaceholder: EncryptedMessage?
        if let existing = try await cache.fetchMessageIfExists(
            sharedId: inboundTask.resolvedLogicalSharedId),
           let existingProps = await existing.props(symmetricKey: databaseSymmetricKey),
           existingProps.senderSecretName == inboundTask.senderSecretName,
           existingProps.senderDeviceId == inboundTask.senderDeviceId
        {
            let target = try? await conversation(
                cache: cache,
                communicationType: conversationType,
                session: session)
            if target?.id == existing.communicationId {
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
            misfiledPlaceholder = existing
        }

        // Content first: until it exists the placeholder is the only durable record of
        // the message, and any exit below this point has to leave it in place.
        func persist(_ messageModel: EncryptedMessage) async throws {
            try await cache.createMessage(messageModel, symmetricKey: databaseSymmetricKey)
            guard let misfiledPlaceholder else { return }
            try await cache.deleteMessage(misfiledPlaceholder)
            audit(.recovery, "pqs.recovery.placeholderRefiled envelope=\(inboundTask.sharedMessageId) logical=\(inboundTask.resolvedLogicalSharedId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
        }
        
        switch decodedMessage.recipient {
        case let .nickname(recipient):
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            do {
                communicationModel = try await conversation(
                    cache: cache,
                    communicationType: conversationType,
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
                    recipients: [recipient, inboundTask.senderSecretName],
                    communicationType: conversationType,
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
            
            try await persist(messageModel)
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
            
            try await persist(messageModel)
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
            try await persist(messageModel)
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

    /// Conversation a decrypted inbound row belongs to. Same-account copies key on
    /// the addressed peer; other senders key on the sender; personal/channel pass through.
    static func inboundConversationType(
        recipient: MessageRecipient,
        sender: String,
        mySecretName: String?
    ) -> MessageRecipient {
        guard case .nickname(let peer) = recipient else { return recipient }
        return .nickname(sender == mySecretName ? peer : sender)
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
        
        if sessionIdentity == nil {
            // No row for this device id. That is evidence the directory changed
            // (a just-linked device), so the refresh must bypass any host lookup
            // cache: the memo it writes decides whether a still-missing row is a
            // retired install or a mint lag.
            identities = try await session.refreshIdentities(
                secretName: inboundTask.senderSecretName,
                forceRefresh: true,
                lookup: .bypassCache)
            sessionIdentity = await bestSessionIdentity(
                secretName: inboundTask.senderSecretName,
                deviceId: inboundTask.senderDeviceId,
                in: identities,
                symmetricKey: databaseSymmetricKey,
                preferredDevice: preferredDevice)
        }
        
        guard let sessionIdentity else {
            // No row after the force refresh that wrote the verified-device memo.
            // A props unwrap failure below stays `missingIdentity` so it keeps
            // the resend path.
            throw JobProcessorErrors.missingSessionRow
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
            // Signature verification failed with current key, likely due to key rotation.
            // The refresh runs under the peer pin and is throttled: a stream of garbage
            // signatures must not cost one directory lookup each.
            guard await session.shouldForceIdentityRefresh(secretName: inboundTask.senderSecretName) else {
                throw PQSError.invalidSignature
            }
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
                // No archived-key fallback. A per-device signing key only changes on
                // compromise rotation, so a frame that verifies under a retired key
                // is exactly the frame that rotation exists to reject; accepting it
                // (and promoting its lane) would hand outbound back to the old keys.
                audit(.recovery, "pqs.inbound.signatureRejected sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) reason=notCurrentDeviceKey")
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

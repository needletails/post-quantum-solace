//
//  FriendshipFlowSourceTests.swift
//  post-quantum-solace
//
//  Source-level regression guards for friendship state conflict handling.
//

import Foundation
import Testing

private enum PQSFriendshipSource {
    static func packageRoot(fromFile file: StaticString = #filePath) throws -> URL {
        var url = URL(fileURLWithPath: "\(file)", isDirectory: false).deletingLastPathComponent()
        for _ in 0..<24 {
            let manifest = url.appendingPathComponent("Package.swift")
            if FileManager.default.fileExists(atPath: manifest.path),
               let source = try? String(contentsOf: manifest, encoding: .utf8),
               source.contains("name: \"post-quantum-solace\"") {
                return url
            }
            guard url.path != "/" else { break }
            url.deleteLastPathComponent()
        }
        throw sourceError("Could not locate post-quantum-solace package root.")
    }

    static func read(_ relativePath: String) throws -> String {
        let root = try packageRoot()
        return try String(contentsOf: root.appendingPathComponent(relativePath), encoding: .utf8)
    }

    static func functionBody(named signature: String, in source: String) throws -> String {
        guard let signatureRange = source.range(of: signature) else {
            throw sourceError("Could not find function signature containing '\(signature)'.")
        }
        guard let openBrace = source[signatureRange.upperBound...].firstIndex(of: "{") else {
            throw sourceError("Could not find opening brace for '\(signature)'.")
        }

        var depth = 0
        var index = openBrace
        while index < source.endIndex {
            switch source[index] {
            case "{":
                depth += 1
            case "}":
                depth -= 1
                if depth == 0 {
                    return String(source[openBrace...index])
                }
            default:
                break
            }
            index = source.index(after: index)
        }

        throw sourceError("Could not find closing brace for '\(signature)'.")
    }

    private static func sourceError(_ message: String) -> NSError {
        NSError(
            domain: "FriendshipFlowSourceTests",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}

@Suite("Friendship flow source guards")
struct FriendshipFlowSourceTests {

    @Test("contact synchronization repairs communication shells on every linked device")
    func contactSynchronizationRepairsCommunicationShells() throws {
        let source = try PQSFriendshipSource.read("Sources/SessionEvents/SessionEvents.swift")
        let communicationBody = try PQSFriendshipSource.functionBody(
            named: "private func updateOrCreateCommunication",
            in: source)

        #expect(source.contains("Linked-device sync is also a repair event"))
        #expect(source.contains("if contactAlreadyExists"))
        #expect(source.contains("preferredSharedIdentifier: contactInfo.sharedCommunicationId"))
        #expect(source.contains("Repair the communication shell before notifying the UI"))
        #expect(source.contains("preferredSharedIdentifier: UUID? = nil"))
        #expect(communicationBody.contains("preferredSharedIdentifier ?? UUID()"))
        #expect(communicationBody.contains("return props.sharedId?.uuidString"))
    }

    @Test("explicit friendship packets can override settled stored metadata")
    func explicitFriendshipPacketsCanOverrideSettledStoredMetadata() throws {
        let source = try PQSFriendshipSource.read("Sources/SessionEvents/SessionEvents.swift")

        #expect(source.contains("enum FriendshipMetadataConflictPolicy"))
        #expect(source.contains("friendshipMetadataConflictPolicy: FriendshipMetadataConflictPolicy = .preferSettled"))
        #expect(source.contains("case .incoming:"))
        #expect(source.contains("case inboundFriendship"))
        #expect(source.contains("preferInboundFriendshipMetadata"))
    }

    @Test("inbound friendship defers until peer OTK handshake is ready")
    func inboundFriendshipDefersUntilPeerOTKHandshakeIsReady() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        #expect(sequenceSource.contains("isAwaitingInboundPeerRatchetHandshake"))
        #expect(sequenceSource.contains("tryDeferInboundUntilPeerRatchetReady"))
        #expect(sequenceSource.contains("isAwaitingInboundPeerRatchetHandshake"))
        #expect(sequenceSource.contains("Re-queueing inbound message until peer OTK handshake completes"))
        #expect(sequenceSource.contains("failureClass: \"crypto.bodyDecryptionFailed\""))
        #expect(!sequenceSource.contains("delayedUntil = Date().addingTimeInterval(0.25)"))
        #expect(sequenceSource.contains("return .deferredToBack"))

        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        #expect(identitySource.contains("func hasActiveInboundSessionIdentity"))
        #expect(identitySource.contains("props.state != nil"))
        #expect(identitySource.contains("func hasInitializedOutboundRatchetForPeer"))
        #expect(identitySource.contains("func peerNeedsOutboundBootstrap"))
    }

    @Test("Recovery baseline: promote, resend-then-escalate, no wipe or outbound park")
    func recoveryBaselineIsLocked() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let controlSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+ControlEventCoalescing.swift")
        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")

        #expect(ratchetSource.contains("promoteArchivedSessionIdentityToActive("))
        #expect(identitySource.contains("pqs.recovery.lanePromotedFromArchive"))
        #expect(sequenceSource.contains("handleUndecryptableInboundResendThenEscalate("))
        #expect(controlSource.contains("do not pre-reset the peer lane"))
        #expect(!controlSource.contains("peerRefreshEmitPreReset"))
        #expect(!sessionSource.contains("prepareInboundPeerRefreshBootstrap"))
        #expect(!sessionSource.contains("bootstrapPrepared"))
        #expect(!sequenceSource.contains("tryDeferOutboundUntilPeerRefreshSettles"))
        #expect(!sequenceSource.contains("pqs.recovery.outboundHeld"))
        #expect(!sequenceSource.contains("parkedWaitingForPeerRefresh"))
    }

    @Test("session background work uses cancellable session work tree")
    func sessionBackgroundWorkUsesCancellableSessionWorkTree() throws {
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let cacheSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Cache.swift")

        #expect(sessionSource.contains("func scheduleBackgroundWork("))
        #expect(sessionSource.contains("cancelSessionWorkTree("))
        #expect(sessionSource.contains("withTaskGroup(of: Void.self)"))
        let shutdownBody = try PQSFriendshipSource.functionBody(
            named: "public func shutdown",
            in: sessionSource)
        #expect(shutdownBody.contains("cancelSessionWorkTree("))
        #expect(shutdownBody.contains("refreshOTKeysTask?.cancel()"))
        #expect(shutdownBody.contains("refreshMLKEMOTKeysTask?.cancel()"))
        #expect(shutdownBody.contains("cancelBackgroundKeyTasks("))

        // Offloaded sites must not use bare fire-and-forget Task {
        #expect(sequenceSource.contains("scheduleBackgroundWork"))
        #expect(!sequenceSource.contains("Task {\n                    let curveReplaced"))
        #expect(ratchetSource.contains("scheduleBackgroundWork"))
        #expect(!ratchetSource.contains("Task {\n                await acceptedDelegate"))
        #expect(cacheSource.contains("scheduleBackgroundWork"))
        #expect(!cacheSource.contains("Task {\n                await session.receiverDelegate"))

        // Signing-key recovery runs inline on the refresh path, not as a detach.
        let openCircuit = try PQSFriendshipSource.functionBody(
            named: "private func openOTKUploadCircuitAndScheduleRecovery",
            in: sessionSource)
        #expect(openCircuit.contains("try await recoverFromSigningKeyMismatch("))
        #expect(!openCircuit.contains("Task {"))
    }

    @Test("Inactive session retention supports multi-device offline lag")
    func inactiveSessionRetentionSupportsMultiDeviceOfflineLag() throws {
        let constants = try PQSFriendshipSource.read("Sources/PQSSession/Constants.swift")
        #expect(constants.contains("inactiveSessionMaxCountPerDevice = 40"))
        #expect(constants.contains("60 * 60 * 24 * 30"))
        #expect(constants.contains("outboundDeviceSendRecordMaxCount = 2_000"))
    }

    @Test("Chat fan-out uses verified-device helper for persistable DMs")
    func chatFanoutUsesVerifiedDeviceHelper() throws {
        let processor = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor.swift")
        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        #expect(identitySource.contains("func sessionIdentitiesForChatFanout"))
        #expect(processor.contains("sessionIdentitiesForChatFanout(secretName:"))
        #expect(processor.contains("pqs.send.deviceSkipped"))
        // Friendship / OTK bootstrap must not use the chat fan-out helper.
        let nicknameCase = try #require(processor.range(of: "case .nickname(let nickname):"))
        let afterNickname = processor[nicknameCase.lowerBound...]
        #expect(afterNickname.contains("forceIdentityRefresh || sendOneTimeIdentities || !createIdentity"))
        #expect(afterNickname.contains("gatherPrivateMessageIdentities("))
    }

    @Test("Outbound device-send ledger records per-device encrypt and orphan resend")
    func outboundDeviceSendLedgerRecordsPerDeviceEncryptAndOrphanResend() throws {
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")
        let modelSource = try PQSFriendshipSource.read("Sources/SessionModels/OutboundDeviceSendRecord.swift")
        #expect(modelSource.contains("struct OutboundDeviceSendRecord"))
        #expect(sessionSource.contains("func recordOutboundDeviceSend("))
        #expect(sessionSource.contains("func outboundDeviceSendRecord("))
        #expect(ratchetSource.contains("recordOutboundDeviceSend("))
        #expect(ratchetSource.contains("reason: \"orphanResend\""))
        #expect(ratchetSource.contains("pqs.recovery.orphanResend"))
    }

    @Test("undecryptable inbound uses resend-then-escalate for CryptoKit, desync, and sessionDecryptionError")
    func undecryptableInboundUsesResendThenEscalateForCryptoKitAndDesync() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        #expect(sequenceSource.contains("handleUndecryptableInboundResendThenEscalate("))
        #expect(sequenceSource.contains("Undecryptable inbound policy"))

        // CryptoKit body auth failure and session-desync errors share the
        // decryptionFailed policy: resend first, peerRefresh only on repeat.
        let cryptoCatch = try #require(sequenceSource.range(of: "catch let cryptoError as CryptoKitError"))
        let afterCrypto = sequenceSource[cryptoCatch.lowerBound...]
        let escalateIdx = try #require(afterCrypto.range(of: "handleUndecryptableInboundResendThenEscalate("))
        #expect(afterCrypto[..<escalateIdx.lowerBound].contains("crypto.bodyDecryptionFailed")
            || afterCrypto[escalateIdx.lowerBound...].contains("crypto.bodyDecryptionFailed"))
        // Must not jump straight to fresh-session repair on first CryptoKit hit.
        let cryptoBlockEnd = afterCrypto.range(of: "} catch let sessionError as PQSSession.SessionErrors where sessionError == .sessionDecryptionError")
        if let cryptoBlockEnd {
            let cryptoBlock = afterCrypto[..<cryptoBlockEnd.lowerBound]
            #expect(!cryptoBlock.contains("handleFreshSessionRepair("))
        }

        let desyncCatch = try #require(sequenceSource.range(of: "isInboundSessionDesyncError(ratchetError)"))
        let afterDesync = sequenceSource[desyncCatch.lowerBound...]
        #expect(afterDesync.contains("handleUndecryptableInboundResendThenEscalate("))

        let sessionDecryptCatch = try #require(
            sequenceSource.range(of: "sessionError == .sessionDecryptionError"))
        let afterSessionDecrypt = sequenceSource[sessionDecryptCatch.lowerBound...]
        let sessionEscalate = try #require(
            afterSessionDecrypt.range(of: "handleUndecryptableInboundResendThenEscalate("))
        #expect(afterSessionDecrypt[..<sessionEscalate.upperBound]
            .contains("payload.sessionDecryptionError")
            || afterSessionDecrypt[sessionEscalate.lowerBound...]
            .contains("payload.sessionDecryptionError"))
    }

    @Test("peer contact bootstrap gates on ratchet state not identity row count")
    func peerContactBootstrapGatesOnRatchetStateNotIdentityRowCount() throws {
        let pqsSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")
        let bootstrapBody = try PQSFriendshipSource.functionBody(
            named: "public func bootstrapPeerContactSession",
            in: pqsSource)
        #expect(bootstrapBody.contains("case .friendshipReply"))
        #expect(bootstrapBody.contains("case .newOutbound"))
        #expect(bootstrapBody.contains("preparePeerIdentitiesForFriendshipReply"))
        #expect(bootstrapBody.contains("preparePeerIdentitiesForOutboundBootstrap"))
        #expect(pqsSource.contains("enum PeerContactBootstrapPurpose"))
        #expect(bootstrapBody.contains("hasInitializedOutboundRatchetForPeer"))
        #expect(bootstrapBody.contains("deliveredOneTimeNotifyPeers"))
        #expect(bootstrapBody.contains("forceRefresh: true"))
        #expect(bootstrapBody.contains("peerCanAcceptFriendship"))
        #expect(bootstrapBody.contains("repairPeerPublishedOneTimeKeysIfPossible"))
        #expect(bootstrapBody.contains("peerCanSupplyCurveOneTimeKey"))
        #expect(!bootstrapBody.contains("restoreEncryptablePeerSessionFromArchiveIfNeeded"))
        #expect(!bootstrapBody.contains("ensurePeerSessionIdentityRow"))
        #expect(bootstrapBody.contains("deliverPeerHandshakeNotifyBeforeOutboundSenderInit"))
        #expect(bootstrapBody.contains("sendOneTimeIdentities: false"))
        #expect(bootstrapBody.contains("preparePeerIdentitiesForFriendshipReply(secretName: secretName)"))
        #expect(bootstrapBody.contains("skipping fresh OTK reply lane before friendship accept"))
        #expect(bootstrapBody.contains("peerNeedsOutboundBootstrap(secretName)"))
        #expect(bootstrapBody.contains("no published curve OTK for outbound bootstrap"))
        // Re-add must not blanket-notify every published device (ghost fan-out).
        #expect(!bootstrapBody.contains("sendOneTimeIdentities: true"))
        let skipFreshOTK = try #require(bootstrapBody.range(of: "skipping fresh OTK reply lane before friendship accept"))
        let prepareIndex = try #require(bootstrapBody.range(of: "preparePeerIdentitiesForFriendshipReply(secretName: secretName)"))
        #expect(skipFreshOTK.lowerBound < prepareIndex.lowerBound)
        let otkGate = try #require(bootstrapBody.range(of: "peerCanSupplyCurveOneTimeKey"))
        #expect(otkGate.lowerBound < prepareIndex.lowerBound)
        #expect(bootstrapBody.contains("cannotFindOneTimeKey"))

        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        #expect(identitySource.contains("wipePeerRelationshipState"))
        #expect(identitySource.contains("repairPeerPublishedOneTimeKeysIfPossible"))
        #expect(identitySource.contains("requestPeerToReplenishPublishedOneTimeKeys"))
        let friendshipSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+Friendship.swift")
        #expect(friendshipSource.contains("markPeerInboundFriendshipConfirmed"))
        #expect(pqsSource.contains("shouldSuppressInboundRecoveryFromSender"))
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        #expect(sequenceSource.contains("dropDeletedPeer"))
        let prepareBody = try PQSFriendshipSource.functionBody(
            named: "internal func preparePeerIdentitiesForOutboundBootstrap",
            in: identitySource)
        #expect(prepareBody.contains("clearOutboundReconciliationCooldown"))
        #expect(prepareBody.contains("forceHandshakeReplay"))
        #expect(prepareBody.contains("reset identity for"))
        #expect(prepareBody.contains("sendOneTimeIdentities: false"))

        let replyBody = try PQSFriendshipSource.functionBody(
            named: "internal func preparePeerIdentitiesForFriendshipReply",
            in: identitySource)
        #expect(replyBody.contains("resetSessionIdentityForFreshSession"))
        #expect(replyBody.contains("sendOneTimeIdentities: false"))
        #expect(!replyBody.contains("peerNeedsOutboundBootstrap"))

        let taskSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor.swift")
        #expect(taskSource.contains("peerNeedsOutboundBootstrap(nickname)"))
        #expect(!taskSource.contains("existingPeerIdentities.isEmpty"))
        #expect(taskSource.contains("forceIdentityRefresh = true"))
        #expect(taskSource.contains("forceRefresh: forceIdentityRefresh"))
        #expect(taskSource.contains("if sendOneTimeIdentities"))
        #expect(taskSource.contains("restrictPeerFanoutToMasterDevices"))
        #expect(taskSource.contains("isMasterDevice == false"))
        #expect(taskSource.contains("case .synchronizeOneTimeKeys = event"))
        #expect(taskSource.contains("OTK handshake: scoped to bootstrap target"))
        #expect(taskSource.contains("peerMasterDevice(for: nickname)"))
        // Normal DM / channel / sibling fan-out must not strip linked child devices.
        #expect(taskSource.contains("Prune peer ghosts before appending sibling identities"))

        let refreshBody = try PQSFriendshipSource.functionBody(
            named: "internal func refreshSessionIdentities",
            in: identitySource)
        #expect(refreshBody.contains("deliverOneTimeIdentityNotifyIfNeeded"))
        #expect(refreshBody.contains("oneTimeNotifiedDeviceIds"))
        #expect(refreshBody.contains("attachPublishedPeerOneTimeKeys"))
        #expect(refreshBody.contains("sendOneTimeIdentities"))
        #expect(refreshBody.contains("device.isMasterDevice"))

        let notifyHelper = try PQSFriendshipSource.functionBody(
            named: "private func deliverOneTimeIdentityNotifyIfNeeded",
            in: identitySource)
        #expect(notifyHelper.contains("guard device.isMasterDevice else"))

        let peerMasterBody = try PQSFriendshipSource.functionBody(
            named: "internal func peerMasterDevice",
            in: identitySource)
        #expect(peerMasterBody.contains("peerCanSupplyCurveOneTimeKey"))
        #expect(peerMasterBody.contains("preferredOnlinePeerDeviceId"))

        let outboundReadyBody = try PQSFriendshipSource.functionBody(
            named: "internal func hasInitializedOutboundRatchetForPeer",
            in: identitySource)
        #expect(outboundReadyBody.contains("peerMasterDevice(for: secretName)"))

        let attachBody = try PQSFriendshipSource.functionBody(
            named: "internal func attachPublishedPeerOneTimeKeys",
            in: identitySource)
        #expect(attachBody.contains("fetchOneTimeKeyIdentities"))
        #expect(attachBody.contains("resolvePublishedCurveOneTimeKey"))

        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        #expect(ratchetSource.contains("Received refreshOneTimeKeys from"))
        #expect(ratchetSource.contains("refreshOneTimeKeysTask(policy: .replenishBatch)"))
        #expect(ratchetSource.contains("ackPublishedOneTimeKeysReplenished"))
        #expect(ratchetSource.contains("publishedOneTimeKeysReplenished"))
        #expect(identitySource.contains("ensurePublishedOneTimeKeysOnServerIfNeeded"))
        #expect(identitySource.contains("deferring until session transport is viable"))
        #expect(identitySource.contains("refreshOneTimeKeysTask(policy: .replenishBatch)"))

        let sequenceSourceForOTK = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let recoveryCriticalBody = try PQSFriendshipSource.functionBody(
            named: "private func isRecoveryCriticalControlMessage",
            in: sequenceSourceForOTK)
        #expect(recoveryCriticalBody.contains("case .synchronizeOneTimeKeys:"))
        #expect(recoveryCriticalBody.contains("return true"))
    }

    @Test("legacy inverse block metadata still sends server unblock packet")
    func legacyInverseBlockMetadataStillSendsServerUnblockPacket() throws {
        let source = try PQSFriendshipSource.read("Sources/SessionEvents/SessionEvents.swift")
        let body = try PQSFriendshipSource.functionBody(named: "func requestFriendshipStateChange", in: source)

        #expect(body.contains("priorTheirState"))
        #expect(body.contains("priorMyState == .blocked || priorTheirState == .blocked"))
        #expect(body.contains("case .requested, .accepted, .pending:"))
        #expect(body.contains("blockUnblockData = convertBoolToData(false)"))
        #expect(body.contains("senderCanDeliver"))
        #expect(body.contains("nudge `.requested`"))

        let mergeSource = try PQSFriendshipSource.read("Sources/SessionEvents/SessionEvents.swift")
        let inboundMerge = try PQSFriendshipSource.functionBody(
            named: "func preferInboundFriendshipMetadata",
            in: mergeSource)
        #expect(inboundMerge.contains("passed.myState == .blockedByOther || passed.theirState == .blocked"))
    }

    @Test("inbound decrypt recovery emits peerRefresh without pre-decrypt wipe")
    func inboundDecryptRecoveryCoordinatesResetAfterPeerRefreshResponse() throws {
        let source = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let controlSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+ControlEventCoalescing.swift")
        let repairBody = try PQSFriendshipSource.functionBody(
            named: "private func handleFreshSessionRepair",
            in: source)
        let emitBody = try PQSFriendshipSource.functionBody(
            named: "func emitSessionReestablishment",
            in: controlSource)
        #expect(source.contains("action=freshSessionRepairThenDeferredResend"))
        #expect(source.contains("tryBeginReestablishmentEpisode"))
        #expect(source.contains("hasOpenReestablishmentEpisode"))
        // Multi-session: peerRefresh rides the still-shared ratchet; no pre-emit wipe.
        #expect(!repairBody.contains("resetSessionIdentityForFreshSession"))
        #expect(!emitBody.contains("resetSessionIdentityForFreshSession"))
        #expect(!emitBody.contains("peerRefreshEmitPreReset"))
        #expect(emitBody.contains("registerExpectedPeerRefreshResponse"))
        #expect(ratchetSource.contains("Completed responder peerRefresh on device lane"))
        #expect(ratchetSource.contains("outOfBandResendReusingCoordinatedIdentity"))
        #expect(source.contains("ratchet.maxSkippedHeadersExceeded"))
        #expect(source.contains("Preserve the\n                // still-shared outbound ratchet"))
    }

    @Test("open peerRefresh episode coalesces competing resets")
    func simultaneousRecoveryConvergesOnOneLaneOwner() throws {
        let controlSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+ControlEventCoalescing.swift")
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")

        let emitBody = try PQSFriendshipSource.functionBody(
            named: "func emitSessionReestablishment",
            in: controlSource)
        #expect(emitBody.contains("registerExpectedPeerRefreshResponse"))
        #expect(emitBody.contains("unregisterExpectedPeerRefreshResponse"))
        #expect(!emitBody.contains("resetSessionIdentityForFreshSession"))

        // While an episode is open, local failure events coalesce into deferred resends.
        let repairBody = try PQSFriendshipSource.functionBody(
            named: "private func handleFreshSessionRepair",
            in: sequenceSource)
        #expect(repairBody.contains("hasOpenReestablishmentEpisode"))
        #expect(repairBody.contains("pendingPeerRefresh"))
        #expect(!repairBody.contains("hasRecentInboundPeerRefreshBootstrap"))
        #expect(!repairBody.contains("responderBootstrapHold"))

        // Outbound encrypt failure repairs even during an open episode (open reestablishment episode);
        // do not silent-delete user jobs because peerRefresh is in flight.
        let outboundRepairBody = try PQSFriendshipSource.functionBody(
            named: "private func handleFreshOutboundRepair",
            in: sequenceSource)
        #expect(outboundRepairBody.contains("resetSessionIdentityForFreshSession"))
        #expect(outboundRepairBody.contains("reason: \"outboundRepair\""))
        #expect(!outboundRepairBody.contains("outboundRepairSkipped"))
        #expect(!outboundRepairBody.contains("hasOpenReestablishmentEpisode"))
        #expect(!outboundRepairBody.contains("hasRecentInboundPeerRefreshBootstrap"))
    }

    @Test("terminal peerRefresh emit failures close the episode and gate identity")
    func terminalPeerRefreshEmitFailuresCloseEpisodeAndGateIdentity() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")
        let repairBody = try PQSFriendshipSource.functionBody(
            named: "private func handleFreshSessionRepair",
            in: sequenceSource)

        #expect(repairBody.contains("blockedAccountIdentity"))
        #expect(repairBody.contains("blockedRecoveryDependency"))
        #expect(repairBody.contains("setAccountIdentityRequiresAcknowledgement(true)"))
        #expect(repairBody.contains("markRecoveryEmitBlocked"))
        #expect(repairBody.contains("endReestablishmentEpisode"))
        // Non-leaders must not emit or close the open leader episode.
        let nonLeaderSkip = try #require(repairBody.range(of: "Skipping duplicate peerRefresh leader"))
        let emitIndex = try #require(repairBody.range(of: "emitSessionReestablishment"))
        #expect(nonLeaderSkip.lowerBound < emitIndex.lowerBound)
        #expect(repairBody.contains("return .deleted"))

        #expect(sessionSource.contains("accountIdentityRequiresAcknowledgement"))
        #expect(sessionSource.contains("recoveryEmitBlockedLanes"))
        #expect(sessionSource.contains("noteRecoveryDependenciesBecameReady"))
        #expect(sessionSource.contains("reestablishmentEpisodeDidEnd"))
    }

    @Test("decrypt-driven peerRefresh leader forces emit and keeps episode open on suppress")
    func decryptDrivenPeerRefreshLeaderForcesEmitAndKeepsEpisodeOpenOnSuppress() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let repairBody = try PQSFriendshipSource.functionBody(
            named: "private func handleFreshSessionRepair",
            in: sequenceSource)

        // Winning the episode must put peerRefresh on the wire even when deferred
        // resend ids already exist (pending TTL is 10m; cooldown is 30s).
        #expect(repairBody.contains("forceReemit: true"))
        #expect(!repairBody.contains("forceReemit: !hadPendingRecovery"))

        // A suppressed emit must not close the episode — that was the thrash loop.
        let suppressedLog = try #require(
            repairBody.range(of: "pqs.recovery.reestablishmentSuppressed reason=coalescedPending"))
        let suppressedRegion = repairBody[suppressedLog.lowerBound...]
        let nextCatch = suppressedRegion.range(of: "} catch")
        let suppressedBranch = nextCatch.map { String(suppressedRegion[..<$0.lowerBound]) }
            ?? String(suppressedRegion.prefix(400))
        #expect(!suppressedBranch.contains("endReestablishmentEpisode"))

        // Repeated redelivery of an already-accepted failure must audit distinctly
        // so production logs do not look like fresh-repair thrash.
        #expect(repairBody.contains("action: \"suppressedRepeatedFailure\""))
    }

    @Test("OTK and invalidSignature recovery align terminal emit failure handling")
    func otkAndInvalidSignatureRecoveryAlignTerminalEmitFailureHandling() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")

        #expect(sequenceSource.contains("replaceOTKBatchThenPeerRefresh"))
        // OTK detached continuation must mark blocked + close on emit throw.
        let otkFailedMarker = try #require(
            sequenceSource.range(of: "reason=otkBatchReplacementFailed"))
        let afterOTK = sequenceSource[otkFailedMarker.upperBound...]
        let otkCatchWindow = String(afterOTK.prefix(3_200))
        #expect(otkCatchWindow.contains("markRecoveryEmitBlocked"))
        #expect(otkCatchWindow.contains("endReestablishmentEpisode"))
        #expect(otkCatchWindow.contains("forceReemit: true"))

        // invalidSignature path uses the same leader-force / keep-open treatment.
        let invalidSigBody = try PQSFriendshipSource.functionBody(
            named: "private func handleInvalidSignature",
            in: sequenceSource)
        #expect(invalidSigBody.contains("forceReemit: true"))
        #expect(invalidSigBody.contains("tryBeginReestablishmentEpisode"))
        let suppressedLog = try #require(
            invalidSigBody.range(of: "pqs.recovery.reestablishmentSuppressed reason=coalescedPending"))
        let suppressedRegion = invalidSigBody[suppressedLog.lowerBound...]
        let nextCatch = suppressedRegion.range(of: "} catch")
        let suppressedBranch = nextCatch.map { String(suppressedRegion[..<$0.lowerBound]) }
            ?? String(suppressedRegion.prefix(400))
        #expect(!suppressedBranch.contains("endReestablishmentEpisode"))
    }

    @Test("episode TTL expiry and pending-resend TTL drop are audited and notify the host")
    func episodeTTLExpiryAndPendingResendTTLDropAreAuditedAndNotifyTheHost() throws {
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")
        let cleanupBody = try PQSFriendshipSource.functionBody(
            named: "func cleanupOpenReestablishmentEpisodes",
            in: sessionSource)
        #expect(cleanupBody.contains("pqs.recovery.episodeExpired"))
        #expect(cleanupBody.contains("reestablishmentEpisodeDidEnd"))

        let endBody = try PQSFriendshipSource.functionBody(
            named: "func endReestablishmentEpisode",
            in: sessionSource)
        #expect(endBody.contains("pqs.recovery.episodeEnded"))

        let pendingCleanup = try PQSFriendshipSource.functionBody(
            named: "private func cleanupPendingResendAfterReestablishment",
            in: sessionSource)
        #expect(pendingCleanup.contains("pqs.recovery.pendingResendExpired"))
        // TTL expiry is terminal content loss for the sharedId; the host must be
        // told (same contract as the attempt-cap path) so the UI can mark it failed.
        #expect(pendingCleanup.contains("inboundContentUnrecoverable("))

        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        #expect(ratchetSource.contains("pqs.recovery.recovered"))
        #expect(ratchetSource.contains("pqs.recovery.resendDrainSubmitted"))
        #expect(ratchetSource.contains("pqs.recovery.resendDrainFailed"))
        #expect(ratchetSource.contains("reason=noReplayableMessages"))
        #expect(ratchetSource.contains("unrecoverable by design"))
    }

    @Test("outbound user ciphertext is prioritized over control frames")
    func outboundUserCiphertextIsPrioritizedOverControlFrames() throws {
        let taskSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor.swift")
        #expect(taskSource.contains("return isSelfRecipient ? .standard : .urgent"))
        #expect(taskSource.contains("return .background"))
        #expect(taskSource.contains("Sibling identity gather failed"))
        let consumerSource = try PQSFriendshipSource.read(
            "Sources/PQSSession/Utilities/NeedleTailAsyncConsumer+Extension.swift")
        #expect(consumerSource.contains("feedConsumer(typedJob, priority: props.task.priority)"))
        #expect(!consumerSource.contains("priority: .standard)"))
    }

    @Test("fresh session reset preserves at-most-once one-time prekeys")
    func freshSessionResetPreservesAtMostOnceOneTimePrekeys() throws {
        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        let resetBody = try PQSFriendshipSource.functionBody(
            named: "internal func resetSessionIdentityForFreshSession",
            in: identitySource)
        // Repair lane (`sendOneTimeIdentities == false`) gets a nil curve OTK; it must
        // never bind a published, un-consumed OTK to the fresh row (two initiators can
        // race onto the same key -> ratchet.missingOneTimeKey at the peer).
        #expect(!resetBody.contains("attachPublishedPeerOneTimeKeys"))
        #expect(resetBody.contains("at-most-once"))
        // Reuse of an existing state-less row is repair-lane only; consume-lane callers
        // must always reach the atomic server consume.
        #expect(resetBody.contains("if !sendOneTimeIdentities,"))
        // Key material is acquired before the active row is torn down.
        let consumeIndex = try #require(resetBody.range(of: "createOneTimeKeys"))
        let deleteIndex = try #require(resetBody.range(of: "deleteSessionIdentity"))
        #expect(consumeIndex.lowerBound < deleteIndex.lowerBound)
    }

    @Test("out-of-band resend reuses the coordinated device identity")
    func outOfBandResendReusesIdentityForRecentControlReplay() throws {
        let source = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let body = try PQSFriendshipSource.functionBody(named: "func handleOutOfBandResendRequest", in: source)

        #expect(body.contains("onlyRecentControls"))
        #expect(body.contains("activeSessionIdentityForPeer"))
        #expect(body.contains("permanentlyUnavailableIds"))
        #expect(body.contains("isFriendshipStateControlMessage"))
        #expect(body.contains("staleFriendshipControl"))
        #expect(body.contains("outOfBandResendReusingCoordinatedIdentity"))
        #expect(body.contains("emitResendUnavailableNotice"))
        #expect(body.contains("isKnownUnavailableResend"))
        #expect(!body.contains("resetSessionIdentityForFreshSession"))
    }

    @Test("deferred resend drain caps submissions and handles unavailable notice")
    func deferredResendDrainCapsAndHandlesUnavailableNotice() throws {
        let source = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let drainBody = try PQSFriendshipSource.functionBody(
            named: "private func sendDeferredResendRequests",
            in: source)
        #expect(drainBody.contains("peerResendRequestMaxSubmissions"))
        #expect(drainBody.contains("pendingResendExhausted"))
        #expect(drainBody.contains("resendRequestSubmissionCount"))
        #expect(drainBody.contains("inboundContentUnrecoverable("))

        #expect(source.contains("case .messageResendUnavailable(let notice):"))
        #expect(source.contains("clearPendingResends("))
        #expect(source.contains("contentUnrecoverable"))
        #expect(source.contains("inboundContentUnrecoverable"))
        #expect(source.contains("outboundMessageUnrecoverable("))
        #expect(source.contains("emitResendUnavailableNotice("))
    }

    @Test("successful inbound does not close episode while peerRefresh response is still expected")
    func successfulInboundDoesNotCloseEpisodeWhileAwaitingPeerRefreshResponse() throws {
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")

        // The premature close that sent Echo's resends onto a lane Nudge never
        // accepted: ordinary inbound decrypt must not end the episode or drain
        // while hasActiveLocalPeerRefreshRequest is true.
        #expect(ratchetSource.contains("hasActiveLocalPeerRefreshRequest("))
        #expect(ratchetSource.contains("resendDrainDeferred"))
        #expect(ratchetSource.contains("awaitingPeerRefreshResponse"))
        // Archived success must promote the proven lane (activate proven lane), not
        // rematerialize the failed active via laneReplaced.
        #expect(ratchetSource.contains("promoteArchivedSessionIdentityToActive("))
        #expect(ratchetSource.contains("lanePromotedAfterArchivedDecrypt"))
        #expect(!ratchetSource.contains(
            "archived inbound fallback succeeded after active decrypt failure"))
        #expect(identitySource.contains("pqs.recovery.lanePromotedFromArchive"))

        // Do not park ordinary outbound while peerRefresh is in flight.
        // Encrypt on the active session; repair only when encrypt actually fails.
        #expect(!sequenceSource.contains("tryDeferOutboundUntilPeerRefreshSettles"))
        #expect(!sequenceSource.contains("pqs.recovery.outboundHeld"))
        #expect(!sequenceSource.contains("waitingForPeerRefresh"))
        #expect(!sequenceSource.contains("resumeJobsAfterPeerRefreshSettle("))
        #expect(!sequenceSource.contains("parkedWaitingForPeerRefresh"))
    }

    @Test("resend request/replay loop is transport-confirmed and fully audited")
    func resendLoopIsTransportConfirmedAndFullyAudited() throws {
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")

        // Requester: queue-time marking arms only the cooldown; attempts are spent
        // when the request frame is handed to the transport. Counting at queue time
        // exhausted the cap on requests that never left the device.
        let markSentBody = try PQSFriendshipSource.functionBody(
            named: "func markPeerResendRequestSent",
            in: sessionSource)
        #expect(!markSentBody.contains("resendRequestAttemptsByKey"))
        #expect(sessionSource.contains("func markPeerResendRequestTransported"))
        #expect(ratchetSource.contains("markPeerResendRequestTransported("))
        #expect(ratchetSource.contains("pqs.recovery.resendRequestTransported"))

        // Responder: request arrival and every replay outcome are in the audit file,
        // so a silent servicing path is attributable from production logs.
        #expect(ratchetSource.contains("pqs.recovery.resendRequestReceived requester="))
        #expect(ratchetSource.contains("rememberResendReplayQueued("))
        #expect(ratchetSource.contains("noteResendReplayTransported(sharedId:"))
        #expect(ratchetSource.contains("pqs.recovery.resendReplayQueued sharedId="))
        #expect(ratchetSource.contains("pqs.recovery.resendReplayTransported sharedId="))
        #expect(ratchetSource.contains("pqs.recovery.resendReplayDropped sharedId="))
        #expect(ratchetSource.contains("pqs.recovery.resendReplayCoalescedAll requester="))

        // Responder servicing cooldown is armed only when the replay reaches the
        // transport. Arming at queue time let a replay that died before the wire
        // coalesce the requester's next ask into silence. The only call site of
        // markPeerResendRequestServiced in the processor is the transported hook.
        let transportedBody = try PQSFriendshipSource.functionBody(
            named: "func noteResendReplayTransported",
            in: ratchetSource)
        #expect(transportedBody.contains("markPeerResendRequestServiced("))
        #expect(transportedBody.contains("servicedFromPersistedStore"))
        let servicedCallSites = ratchetSource.components(
            separatedBy: "markPeerResendRequestServiced(").count - 1
        #expect(servicedCallSites == 1)
        let droppedBody = try PQSFriendshipSource.functionBody(
            named: "func noteResendReplayDropped",
            in: ratchetSource)
        #expect(!droppedBody.contains("markPeerResendRequestServiced"))

        // Replay jobs that die in outbound failure handling must audit the drop.
        #expect(sequenceSource.contains("noteResendReplayDropped("))
        #expect(sequenceSource.contains("outboundRepairSuppressed"))
        #expect(!sequenceSource.contains("outboundRepairSkipped.openEpisode"))
    }

    @Test("session cache delete is idempotent when row is already absent")
    func sessionCacheDeleteIsIdempotentWhenRowIsAlreadyAbsent() throws {
        let source = try PQSFriendshipSource.read("Sources/PQSSession/Cache/SessionCache.swift")
        let body = try PQSFriendshipSource.functionBody(named: "public func deleteSessionIdentity", in: source)
        #expect(body.contains("guard identities.contains(where: { $0.id == id }) else"))
    }

    @Test("every lane teardown is audited with a caller reason")
    func everyLaneTeardownIsAuditedWithACallerReason() throws {
        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")
        let coalescingSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+ControlEventCoalescing.swift")

        // The reset primitive audits both exit paths with the caller's reason so a
        // decrypt failure right after a laneReset entry identifies the clobbering caller.
        #expect(identitySource.contains("reason: String = \"unspecified\""))
        #expect(identitySource.contains("pqs.recovery.laneReset outcome=reset reason="))
        #expect(identitySource.contains("pqs.recovery.laneReset outcome=reusedStateLessRow reason="))

        // Every production caller tags its reason; none may fall back to "unspecified".
        // Clear-before-decrypt bootstrap reasons are gone (try-all sessions + promote).
        #expect(ratchetSource.contains("reason: \"stateLessPersonalOutboundRefresh\""))
        #expect(!sessionSource.contains("reason: \"inboundPeerRefreshBootstrap\""))
        #expect(sequenceSource.contains("reason: \"outboundRepair\""))
        #expect(!coalescingSource.contains("reason: \"peerRefreshEmitPreReset\""))
        #expect(identitySource.contains("reason: \"friendshipOutboundBootstrap\""))
        #expect(identitySource.contains("reason: \"friendshipReplyPrepare\""))
        #expect(identitySource.contains("reason: \"rotatedIdentityKeysDetected\""))

        // The remaining lane mutations are audited too.
        #expect(ratchetSource.contains("pqs.recovery.laneReplaced reason="))
        #expect(identitySource.contains("pqs.recovery.laneRestoredFromArchive"))
        #expect(identitySource.contains("pqs.recovery.lanePromotedFromArchive"))
        #expect(identitySource.contains("pqs.recovery.laneWiped"))
        #expect(identitySource.contains("pqs.recovery.laneStalePruned"))
    }
}

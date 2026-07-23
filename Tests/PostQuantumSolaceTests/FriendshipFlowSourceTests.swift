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

        #expect(identitySource.contains("activateSessionIdentityAfterInboundDecrypt("))
        #expect(identitySource.contains("promoteArchivedSessionIdentityToActive("))
        #expect(identitySource.contains("demoteActiveSessionIdentityToInactive("))
        #expect(identitySource.contains("pqs.recovery.lanePromotedFromArchive"))
        #expect(!identitySource.contains("lanePromoteDeferredOrphanResend"))
        #expect(identitySource.contains("demotedActive="))
        #expect(identitySource.contains("demoteZombieStateLessActives("))
        #expect(identitySource.contains("zombieStateLessDemoted"))
        #expect(sessionSource.contains("markOrphanResendInitiatingSession("))
        // Serial recovery mailbox: orphan encrypt is inline; no inbound defer adapter.
        #expect(!sequenceSource.contains("tryDeferInboundDuringOrphanResendWave("))
        #expect(!sequenceSource.contains("inboundDeferredOrphanResendWave"))
        #expect(ratchetSource.contains("handleWriteMessage("))
        #expect(ratchetSource.contains("pendingOrphanEncrypts"))
        #expect(ratchetSource.contains("orphanResendMessageRecordUpdated"))
        #expect(ratchetSource.contains("activateSessionIdentityAfterInboundDecrypt("))
        #expect(ratchetSource.contains("laneSelectedAfterInboundDecrypt"))
        #expect(ratchetSource.contains("orphanResendReused"))
        #expect(ratchetSource.contains("orphanResendWaveDrained"))
        #expect(!ratchetSource.contains("lanePromoteDeferredOpenRepair"))
        #expect(!ratchetSource.contains("laneDroppedLosingActive"))
        #expect(!ratchetSource.contains("laneDemotedLosingActive"))
        #expect(sequenceSource.contains("handleUndecryptableInboundResend("))
        // Healthy orphan-resend audit baseline (dogfood when decrypt works).
        #expect(sequenceSource.contains("resendRequested") || sequenceSource.contains("\"resendRequested\""))
        #expect(ratchetSource.contains("pqs.recovery.orphanResend"))
        #expect(ratchetSource.contains("pqs.recovery.messageRecordSessionId="))
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
        #expect(ratchetSource.contains("pqs.recovery.orphanResendReused"))
        #expect(ratchetSource.contains("markOrphanResendInitiatingSession("))
        #expect(ratchetSource.contains("pendingOrphanEncrypts"))
        #expect(ratchetSource.contains("orphanResendMessageRecordUpdated"))
        #expect(ratchetSource.contains("orphanResendWaveDrained"))
        #expect(ratchetSource.contains("pqs.recovery.messageRecordSessionId="))
        // Orphan-resend match: insert initiating only when active SessionID == MessageRecord.
        #expect(ratchetSource.contains("record.sessionIdentityId == replayIdentity.id"))
        #expect(sessionSource.contains("func markOrphanResendInitiatingSession("))
        #expect(sessionSource.contains("clearOutboundReconciliationCooldown("))
    }

    @Test("Recovery invariants: zombie demote, serial orphan encrypt, no inbound defer")
    func recoveryInvariantsAreLocked() throws {
        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let zombieBody = try PQSFriendshipSource.functionBody(
            named: "internal func demoteZombieStateLessActives",
            in: identitySource)
        #expect(zombieBody.contains("isOrphanResendInitiatingSession("))
        #expect(!zombieBody.contains("clearOrphanResendInitiatingSession("))
        #expect(!zombieBody.contains("removeIdentity(with:"))
        #expect(zombieBody.contains("sessionIdentities.remove(secretName)"))
        #expect(sequenceSource.contains("demoteZombieStateLessActives("))
        #expect(!sequenceSource.contains("tryDeferInboundDuringOrphanResendWave("))
        #expect(ratchetSource.contains("handleWriteMessage("))
        #expect(ratchetSource.contains("pendingOrphanEncrypts"))
        #expect(!sequenceSource.contains("private func handleFreshSessionRepair("))
        #expect(sequenceSource.contains("replaceOTKBatchThenPeerRefresh"))
        #expect(sequenceSource.contains("validatePeerAccountSigningKeyAgainstRemote("))
        #expect(identitySource.contains("func validatePeerAccountSigningKeyAgainstRemote("))
    }

    @Test("undecryptable inbound uses resend-then-escalate for CryptoKit, desync, and sessionDecryptionError")
    func undecryptableInboundUsesResendThenEscalateForCryptoKitAndDesync() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        #expect(sequenceSource.contains("handleUndecryptableInboundResend("))
        #expect(sequenceSource.contains("Undecryptable inbound policy"))

        // CryptoKit body auth failure and session-desync errors share the
        // Orphan-resend policy (sender orphanResend; no receive-side ASR).
        let cryptoCatch = try #require(sequenceSource.range(of: "catch let cryptoError as CryptoKitError"))
        let afterCrypto = sequenceSource[cryptoCatch.lowerBound...]
        let escalateIdx = try #require(afterCrypto.range(of: "handleUndecryptableInboundResend("))
        #expect(afterCrypto[..<escalateIdx.lowerBound].contains("crypto.bodyDecryptionFailed")
            || afterCrypto[escalateIdx.lowerBound...].contains("crypto.bodyDecryptionFailed"))
        // Must never jump to fresh-session repair on CryptoKit undecryptable.
        let cryptoBlockEnd = afterCrypto.range(of: "} catch let sessionError as PQSSession.SessionErrors where sessionError == .sessionDecryptionError")
        if let cryptoBlockEnd {
            let cryptoBlock = afterCrypto[..<cryptoBlockEnd.lowerBound]
            #expect(!cryptoBlock.contains("handleFreshSessionRepair("))
        }
        let undecryptableBody = try PQSFriendshipSource.functionBody(
            named: "private func handleUndecryptableInboundResend",
            in: sequenceSource)
        #expect(!undecryptableBody.contains("handleFreshSessionRepair("))
        #expect(undecryptableBody.contains("resendAwaitingSender"))
        #expect(undecryptableBody.contains("awaitingSenderOrphanResend"))

        let desyncCatch = try #require(sequenceSource.range(of: "isInboundSessionDesyncError(ratchetError)"))
        let afterDesync = sequenceSource[desyncCatch.lowerBound...]
        #expect(afterDesync.contains("handleUndecryptableInboundResend("))

        let sessionDecryptCatch = try #require(
            sequenceSource.range(of: "sessionError == .sessionDecryptionError"))
        let afterSessionDecrypt = sequenceSource[sessionDecryptCatch.lowerBound...]
        let sessionEscalate = try #require(
            afterSessionDecrypt.range(of: "handleUndecryptableInboundResend("))
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
        #expect(!pqsSource.contains("restoreEncryptablePeerSessionFromArchiveIfNeeded"))
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

    @Test("inbound decrypt failures use orphan-resend; ASR only for OTK bootstrap")
    func inboundDecryptFailuresUseOrphanResendNotReceiveASR() throws {
        let source = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")
        let controlSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+ControlEventCoalescing.swift")
        let emitBody = try PQSFriendshipSource.functionBody(
            named: "func emitSessionReestablishment",
            in: controlSource)
        // Decrypt-failure ASR helper is gone; OTK bootstrap is the named exception.
        #expect(!source.contains("private func handleFreshSessionRepair("))
        #expect(!source.contains("action=freshSessionRepairThenDeferredResend"))
        #expect(!source.contains("reason: \"freshSessionRepair\""))
        #expect(source.contains("replaceOTKBatchThenPeerRefresh"))
        #expect(source.contains("tryBeginReestablishmentEpisode"))
        #expect(source.contains("hasOpenReestablishmentEpisode"))
        #expect(!emitBody.contains("resetSessionIdentityForFreshSession"))
        #expect(!emitBody.contains("peerRefreshEmitPreReset"))
        #expect(emitBody.contains("registerExpectedPeerRefreshResponse"))
        #expect(ratchetSource.contains("Completed responder peerRefresh on device lane"))
        #expect(ratchetSource.contains("outOfBandResendReusingCoordinatedIdentity"))
        #expect(ratchetSource.contains("activateSessionIdentityAfterInboundDecrypt("))
        // Orphan-resend: maxSkipped requests resend only; sender orphanResend heals.
        let maxSkippedCatch = try #require(
            source.range(of: "ratchetError == .maxSkippedHeadersExceeded"))
        let afterMaxSkipped = source[maxSkippedCatch.lowerBound...]
        #expect(afterMaxSkipped.contains("handleUndecryptableInboundResend("))
        // Poisoned try-all (`stateUninitialized` on a state-less preferred row) is
        // the same orphan-resend path — not receive-side freshSessionRepair / peerRefresh.
        #expect(source.contains("ratchetError == .stateUninitialized"))
        let stateUninitCatch = try #require(
            source.range(of: "ratchetError == .stateUninitialized"))
        let afterStateUninit = source[stateUninitCatch.lowerBound...]
        #expect(afterStateUninit.contains("handleUndecryptableInboundResend("))
        let freshCatch = try #require(source.range(of: "isFreshSessionRepairError(ratchetError)"))
        let afterFresh = source[freshCatch.lowerBound...]
        #expect(afterFresh.contains("handleUndecryptableInboundResend("))
        #expect(!source.contains("handleFreshSessionRepair("))

        // Dogfood 883B532C: after orphan-resend owns a sharedId, missingOneTimeKey must not
        // open replaceOTKBatchThenPeerRefresh for that same tuple.
        #expect(sessionSource.contains("func isAwaitingSenderOrphanResend("))
        let otkCatch = try #require(source.range(of: "ratchetError == .missingOneTimeKey"))
        let otkBlock = String(source[otkCatch.lowerBound...].prefix(5_500))
        #expect(otkBlock.contains("isAwaitingSenderOrphanResend("))
        #expect(otkBlock.contains("resendAwaitingSender"))
        #expect(otkBlock.contains("otkBootstrapDeferredToOrphanResend")
            || otkBlock.contains("orphanResendOwnsSharedId"))
        let deferIdx = try #require(otkBlock.range(of: "isAwaitingSenderOrphanResend("))
        let asrIdx = try #require(otkBlock.range(of: "replaceOTKBatchThenPeerRefresh"))
        #expect(deferIdx.lowerBound < asrIdx.lowerBound)
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

        // Documented receive-side ASR: missingOneTimeKey coalesces into one episode.
        let otkCatch = try #require(sequenceSource.range(of: "ratchetError == .missingOneTimeKey"))
        let otkBlock = String(sequenceSource[otkCatch.lowerBound...].prefix(5_500))
        #expect(otkBlock.contains("hasOpenReestablishmentEpisode"))
        #expect(otkBlock.contains("pendingPeerRefresh") || otkBlock.contains("coalescedPendingPeerRecovery"))
        #expect(otkBlock.contains("replaceOTKBatchThenPeerRefresh"))
        #expect(!otkBlock.contains("hasRecentInboundPeerRefreshBootstrap"))
        #expect(!otkBlock.contains("responderBootstrapHold"))

        // Outbound encrypt failure repairs even during an open episode;
        // do not silent-delete user jobs because peerRefresh is in flight.
        let outboundRepairBody = try PQSFriendshipSource.functionBody(
            named: "private func handleFreshOutboundRepair",
            in: sequenceSource)
        #expect(outboundRepairBody.contains("resetSessionIdentityForFreshSession"))
        #expect(outboundRepairBody.contains("reason: \"outboundRepair\""))
        #expect(outboundRepairBody.contains("demoteZombieStateLessActives("))
        #expect(!outboundRepairBody.contains("outboundRepairSkipped"))
        #expect(!outboundRepairBody.contains("hasOpenReestablishmentEpisode"))
        #expect(!outboundRepairBody.contains("hasRecentInboundPeerRefreshBootstrap"))
    }

    @Test("terminal peerRefresh emit failures close the episode and gate identity")
    func terminalPeerRefreshEmitFailuresCloseEpisodeAndGateIdentity() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")
        let invalidSigBody = try PQSFriendshipSource.functionBody(
            named: "private func handleInvalidSignature",
            in: sequenceSource)

        // Terminal emit failures on remaining ASR paths close the episode and gate.
        #expect(invalidSigBody.contains("markRecoveryEmitBlocked"))
        #expect(invalidSigBody.contains("endReestablishmentEpisode"))
        #expect(invalidSigBody.contains("forceReemit: true"))
        let otkFailed = try #require(sequenceSource.range(of: "reason=otkBatchReplacementFailed"))
        let afterOTK = String(sequenceSource[otkFailed.upperBound...].prefix(800))
        #expect(afterOTK.contains("endReestablishmentEpisode"))
        #expect(sequenceSource.contains("markRecoveryEmitBlocked"))

        #expect(sessionSource.contains("accountIdentityRequiresAcknowledgement"))
        #expect(sessionSource.contains("recoveryEmitBlockedLanes"))
        #expect(sessionSource.contains("noteRecoveryDependenciesBecameReady"))
        #expect(sessionSource.contains("reestablishmentEpisodeDidEnd"))
    }

    @Test("decrypt-driven peerRefresh leader forces emit and keeps episode open on suppress")
    func decryptDrivenPeerRefreshLeaderForcesEmitAndKeepsEpisodeOpenOnSuppress() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let invalidSigBody = try PQSFriendshipSource.functionBody(
            named: "private func handleInvalidSignature",
            in: sequenceSource)

        // Winning the episode must put peerRefresh on the wire even when deferred
        // resend ids already exist (pending TTL is 10m; cooldown is 30s).
        #expect(invalidSigBody.contains("forceReemit: true"))
        #expect(!invalidSigBody.contains("forceReemit: !hadPendingRecovery"))

        // A suppressed emit must not close the episode — that was the thrash loop.
        let suppressedLog = try #require(
            invalidSigBody.range(of: "pqs.recovery.reestablishmentSuppressed reason=coalescedPending"))
        let suppressedRegion = invalidSigBody[suppressedLog.lowerBound...]
        let nextCatch = suppressedRegion.range(of: "} catch")
        let suppressedBranch = nextCatch.map { String(suppressedRegion[..<$0.lowerBound]) }
            ?? String(suppressedRegion.prefix(400))
        #expect(!suppressedBranch.contains("endReestablishmentEpisode"))

        // OTK path also force-emits after batch replacement.
        #expect(sequenceSource.contains("replaceOTKBatchThenPeerRefresh"))
        let otkForce = try #require(sequenceSource.range(of: "forceReemit: true"))
        #expect(otkForce.lowerBound > sequenceSource.startIndex)
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
        // Key material is acquired before the previous current is demoted.
        let consumeIndex = try #require(resetBody.range(of: "createOneTimeKeys"))
        let demoteIndex = try #require(resetBody.range(of: "demoteActiveSessionIdentityToInactive"))
        #expect(consumeIndex.lowerBound < demoteIndex.lowerBound)
        #expect(!resetBody.contains("deleteSessionIdentity"))
        #expect(!resetBody.contains("archiveActiveSessionIdentitySnapshot"))
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
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let drainBody = try PQSFriendshipSource.functionBody(
            named: "private func sendDeferredResendRequests",
            in: source)
        #expect(drainBody.contains("peerResendRequestMaxSubmissions"))
        #expect(drainBody.contains("pendingResendExhausted"))
        #expect(drainBody.contains("resendRequestSubmissionCount"))
        #expect(drainBody.contains("inboundContentUnrecoverable("))
        #expect(drainBody.contains("clearPendingResends("))
        #expect(drainBody.contains("reason=resendSubmissionCap"))

        #expect(source.contains("case .messageResendUnavailable(let notice):"))
        #expect(source.contains("clearPendingResends("))
        #expect(source.contains("contentUnrecoverable"))
        #expect(source.contains("inboundContentUnrecoverable"))
        #expect(source.contains("outboundMessageUnrecoverable("))
        #expect(source.contains("emitResendUnavailableNotice("))

        // Hot-path submission cap terminalizes sharedId without receive ASR.
        let requestBody = try PQSFriendshipSource.functionBody(
            named: "private func requestPeerResendIfAllowed",
            in: sequenceSource)
        #expect(requestBody.contains("peerResendRequestMaxSubmissions"))
        #expect(requestBody.contains("clearPendingResends("))
        #expect(requestBody.contains("reason=resendSubmissionCap"))
        #expect(!requestBody.contains("emitSessionReestablishment("))
        #expect(!requestBody.contains("peerRefresh"))
        #expect(!requestBody.contains("handleFreshSessionRepair("))

        let undecryptableBody = try PQSFriendshipSource.functionBody(
            named: "private func handleUndecryptableInboundResend",
            in: sequenceSource)
        #expect(undecryptableBody.contains("resendRequestExhausted"))
        #expect(undecryptableBody.contains("contentUnrecoverable"))
        #expect(!undecryptableBody.contains("emitSessionReestablishment("))
    }

    @Test("unavailable NACK uses initiating delivery distinct from orphanResend")
    func unavailableNACKUsesInitiatingDeliveryDistinctFromOrphanResend() throws {
        // Dogfood closeout (post-implement): backlog should end in
        // orphanResend→recovered/lanePromoted OR resendUnavailable*/contentUnrecoverable —
        // not unbounded resendAwaitingSender + Resuming N pending multipart.
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let emitBody = try PQSFriendshipSource.functionBody(
            named: "private func emitResendUnavailableNotice",
            in: ratchetSource)
        #expect(emitBody.contains("orphanResendInitiatingSessionId("))
        #expect(emitBody.contains("resolveResendUnavailableDeliveryIdentity("))
        #expect(emitBody.contains("resendUnavailableSameAccountNoRemint"))
        #expect(emitBody.contains("resendUnavailableUsingOrphanInitiating"))
        #expect(emitBody.contains("resendUnavailableOrphanMarkStaleUsingFallback"))
        #expect(emitBody.contains("outboundSessionIdentity("))
        #expect(emitBody.contains("handleWriteMessage("))
        #expect(emitBody.contains("resendUnavailableQueued"))
        #expect(emitBody.contains("resendUnavailableSent"))
        #expect(emitBody.contains("resendUnavailableEmitFailed"))
        #expect(emitBody.contains("resendUnavailableReused"))
        #expect(!emitBody.contains("feedTask("))
        #expect(!emitBody.contains("markOrphanResendInitiatingSession("))
        #expect(!emitBody.contains("reason: \"orphanResend\""))
        // When orphan mark is set but row is stale, NACK must not mint (demote heal).
        let emitAfterOrphanMark = try #require(
            emitBody.range(of: "else if let protectedId = await session.orphanResendInitiatingSessionId"))
        let orphanMarkBranch = emitBody[emitAfterOrphanMark.lowerBound...]
        let staleAudit = try #require(
            orphanMarkBranch.range(of: "resendUnavailableOrphanMarkStaleUsingFallback"))
        #expect(orphanMarkBranch[..<staleAudit.lowerBound].contains("deliveryIdentity = fallbackIdentity"))
        #expect(!orphanMarkBranch[..<staleAudit.lowerBound].contains("resolveResendUnavailableDeliveryIdentity("))

        // Retry-request discard rule: an unanswerable resend request must never
        // tear down session state. The NACK rides the existing active; a mint is
        // allowed only when no active exists (reset with no actives demotes nothing),
        // and the NACK row must never capture general outbound via a preferred stamp.
        let deliveryBody = try PQSFriendshipSource.functionBody(
            named: "private func resolveResendUnavailableDeliveryIdentity",
            in: ratchetSource)
        #expect(deliveryBody.contains("outboundSessionIdentity("))
        #expect(deliveryBody.contains("resendUnavailableUsingActive"))
        #expect(deliveryBody.contains("reason: \"resendUnavailable\""))
        #expect(deliveryBody.contains("sendOneTimeIdentities: false"))
        #expect(!deliveryBody.contains("preferredSessionIdentityIdByPeerDevice"))
        #expect(!deliveryBody.contains("markOrphanResendInitiatingSession("))
        // Active reuse must be checked before any reset: the existing-active return
        // precedes resetSessionIdentityForFreshSession in the body.
        let activeReturn = try #require(deliveryBody.range(of: "return active"))
        let resetCall = try #require(deliveryBody.range(of: "resetSessionIdentityForFreshSession("))
        #expect(activeReturn.lowerBound < resetCall.lowerBound)

        // Idempotence: repeat requests for known-unavailable ids re-notify from
        // memory without re-running the DB pass; the first NACK's minted row is an
        // active, so delivery resolution reuses it instead of minting again.
        #expect(ratchetSource.contains("isKnownUnavailableResend("))
        #expect(ratchetSource.contains("resendReplayShortCircuited"))
        #expect(ratchetSource.contains("markResendUnavailable("))

        // Anti-cascade: unavailable notices are recent-replayable.
        let replayableBody = try PQSFriendshipSource.functionBody(
            named: "private func isReplayableNonPersistentControl",
            in: ratchetSource)
        #expect(replayableBody.contains("case .messageResendUnavailable:"))
        #expect(replayableBody.contains("return true"))
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
        // rematerialize the failed active via laneReplaced. Total inbound failure
        // rolls back ratchet mutations on the same row (discard).
        #expect(ratchetSource.contains("activateSessionIdentityAfterInboundDecrypt("))
        #expect(ratchetSource.contains("laneSelectedAfterInboundDecrypt"))
        #expect(ratchetSource.contains("pqs.recovery.laneRolledBack reason="))
        #expect(!ratchetSource.contains("lanePromoteDeferredOpenRepair"))
        #expect(!ratchetSource.contains("lanePromotedAfterArchivedDecrypt"))
        #expect(!ratchetSource.contains("laneDroppedLosingActive"))
        #expect(!ratchetSource.contains(
            "archived inbound fallback succeeded after active decrypt failure"))
        #expect(identitySource.contains("activateSessionIdentityAfterInboundDecrypt("))
        #expect(identitySource.contains("pqs.recovery.lanePromotedFromArchive"))
        #expect(!identitySource.contains("lanePromoteDeferredOrphanResend"))
        #expect(identitySource.contains("demoteActiveSessionIdentityToInactive("))
        #expect(!sequenceSource.contains("tryDeferInboundDuringOrphanResendWave("))
        #expect(!sequenceSource.contains("inboundDeferredOrphanResendWave"))
        // Inbound decrypt: activate demotes previous current; promote must not delete actives.
        let promoteBody = try PQSFriendshipSource.functionBody(
            named: "internal func promoteArchivedSessionIdentityToActive",
            in: identitySource)
        #expect(promoteBody.contains("demoteActiveSessionIdentityToInactive("))
        #expect(!promoteBody.contains("deleteSessionIdentity("))
        let activateBody = try PQSFriendshipSource.functionBody(
            named: "internal func activateSessionIdentityAfterInboundDecrypt",
            in: identitySource)
        #expect(activateBody.contains("promoteArchivedSessionIdentityToActive("))
        #expect(activateBody.contains("demoteActiveSessionIdentityToInactive("))
        #expect(!activateBody.contains("lanePromoteDeferredOrphanResend"))
        // Sticky orphan: protect intentional blank from zombie demote; do not settle on activate.
        #expect(activateBody.contains("isOrphanResendInitiatingSession("))
        // Proven decrypt demotes orphan sibling (one active); clears mark when demoted.
        #expect(activateBody.contains("clearOrphanResendInitiatingSession("))
        #expect(activateBody.contains("demotingOrphan"))
        #expect(!activateBody.contains("orphanResendSettled"))
        #expect(!activateBody.contains("removeIdentity(with:"))
        #expect(promoteBody.contains("isOrphanResendInitiatingSession("))
        #expect(promoteBody.contains("clearOrphanResendInitiatingSession("))
        #expect(promoteBody.contains("demotingOrphan"))
        #expect(!promoteBody.contains("orphanResendSettled"))
        #expect(!promoteBody.contains("removeIdentity(with:"))
        // Try-all includes state-less Active; ensure one blank slot into the peer
        // device when none exists (not post-failure matching mint).
        #expect(!ratchetSource.contains("tryDecryptWithMatchingInitiatingSession("))
        #expect(!ratchetSource.contains("matchingInitiatingSessionAccepted"))
        #expect(!ratchetSource.contains("matchingInitiatingSessionRejected"))
        #expect(!ratchetSource.contains("isHandshakeEligibleMatchingError("))
        #expect(!ratchetSource.contains("isMaxSkippedOnlyPreferredError("))
        #expect(!ratchetSource.contains("matchingInitiatingDespiteMaxSkipped"))
        #expect(!ratchetSource.contains("decryptWithMatchingBlankIdentity("))
        #expect(!identitySource.contains("createMatchingInitiatingSessionIdentity("))
        #expect(identitySource.contains("ensureInboundInitiatingSessionIdentity("))
        let streamBody = try PQSFriendshipSource.functionBody(
            named: "private func handleStreamMessage",
            in: ratchetSource)
        #expect(streamBody.contains("kind: \"stateLess\""))
        #expect(streamBody.contains("ensureInboundInitiatingSessionIdentity("))
        #expect(streamBody.contains("inboundInitiatingSlotEnsured"))
        // Ensure gate: a stale blank must not block minting the matching blank for
        // a new initiating frame. Dedupe is on the frame header's key material,
        // not on "any blank exists" / "preferred is blank".
        #expect(streamBody.contains("blankForHeaderExists"))
        #expect(streamBody.contains("inboundInitiatingSlotEnsureSkipped reason=blankForHeaderExists"))
        #expect(streamBody.contains("header.remoteLongTermPublicKey"))
        #expect(streamBody.contains("header.remoteOneTimePublicKey?.id"))
        #expect(!streamBody.contains("stateLessAlternates.isEmpty"))
        #expect(!streamBody.contains("preferredIsBlank"))
        #expect(!streamBody.contains("tryDecryptWithMatchingInitiatingSession("))
        // Orphan remint consumes OTK so receiver blank PQXDH can salt-match.
        #expect(ratchetSource.contains("reason: \"orphanResend\""))
        let orphanRemintIdx = try #require(ratchetSource.range(of: "reason: \"orphanResend\""))
        let orphanRemintWindow = ratchetSource[
            ratchetSource.index(orphanRemintIdx.lowerBound, offsetBy: -200)..<orphanRemintIdx.upperBound]
        #expect(orphanRemintWindow.contains("sendOneTimeIdentities: true"))

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
        #expect(sequenceSource.contains("isPendingResendReplay"))
        #expect(sequenceSource.contains("clearOutboundReconciliationCooldown("))
        #expect(sequenceSource.contains("outboundRepairReusedOrphanResend"))
        #expect(sequenceSource.contains("demoteZombieStateLessActives("))
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
        #expect(sequenceSource.contains("reason: \"orphanResend\"")
            || ratchetSource.contains("reason: \"orphanResend\""))
        #expect(ratchetSource.contains("reason: \"resendUnavailable\""))
        #expect(!sequenceSource.contains("reason: \"freshSessionRepair\""))
        #expect(!coalescingSource.contains("reason: \"peerRefreshEmitPreReset\""))
        #expect(identitySource.contains("reason: \"friendshipOutboundBootstrap\""))
        #expect(identitySource.contains("reason: \"friendshipReplyPrepare\""))
        #expect(identitySource.contains("reason: \"rotatedIdentityKeysDetected\""))

        // The remaining lane mutations are audited too.
        #expect(!ratchetSource.contains("pqs.recovery.laneReplaced reason="))
        #expect(!ratchetSource.contains("replaceRestoredSessionIdentityObject("))
        #expect(ratchetSource.contains("pqs.recovery.laneRolledBack reason="))
        #expect(!identitySource.contains("pqs.recovery.laneRestoredFromArchive"))
        #expect(!identitySource.contains("archiveActiveSessionIdentitySnapshot("))
        #expect(identitySource.contains("pqs.recovery.lanePromotedFromArchive"))
        #expect(identitySource.contains("demotedActive="))
        #expect(identitySource.contains("zombieStateLessDemoted"))
        #expect(identitySource.contains("pqs.recovery.laneWiped"))
        #expect(identitySource.contains("pqs.recovery.laneStalePruned"))
    }

    @Test("undecryptable lane saturation stays on sender orphanResend path")
    func undecryptableLaneSaturationStaysOnSenderOrphanResendPath() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")
        let constants = try PQSFriendshipSource.read("Sources/PQSSession/Constants.swift")

        #expect(constants.contains("undecryptableLaneEscalateThreshold = 3"))
        #expect(sessionSource.contains("func noteUndecryptableLaneFailure("))
        #expect(sessionSource.contains("func clearUndecryptableLaneFailures("))
        #expect(sequenceSource.contains("noteUndecryptableLaneFailure("))
        #expect(sequenceSource.contains("undecryptableLaneSaturated"))
        #expect(sequenceSource.contains("awaitingSenderOrphanResend"))
        let undecryptableBody = try PQSFriendshipSource.functionBody(
            named: "private func handleUndecryptableInboundResend",
            in: sequenceSource)
        #expect(!undecryptableBody.contains("handleFreshSessionRepair("))
        // Saturation coalesces further distinct ids via the existing open-episode /
        // defer path — not a new NACK type and not receive ASR.
        #expect(undecryptableBody.contains("hasTransportedPeerResendRequest("))
        #expect(undecryptableBody.contains("tryBeginReestablishmentEpisode("))
        #expect(undecryptableBody.contains("coalescedPendingPeerRecovery"))
        #expect(undecryptableBody.contains("deferPeerResendUntilReestablished("))
        #expect(undecryptableBody.contains("reason=undecryptableLaneSaturated"))
        #expect(!undecryptableBody.contains("emitSessionReestablishment("))
        #expect(!undecryptableBody.contains("kind: .peerRefresh"))
        #expect(sessionSource.contains("func hasTransportedPeerResendRequest("))
        #expect(ratchetSource.contains("reason: \"orphanResend\""))
        #expect(ratchetSource.contains("pqs.recovery.orphanResend"))
        #expect(ratchetSource.contains("pqs.recovery.orphanResendReused"))
        #expect(ratchetSource.contains("orphanResendWaveDrained"))
        #expect(ratchetSource.contains("pendingOrphanEncrypts"))
        #expect(sessionSource.contains("markOrphanResendInitiatingSession("))
        #expect(!sequenceSource.contains("tryDeferInboundDuringOrphanResendWave("))
        #expect(!sequenceSource.contains("inboundDeferredOrphanResendWave"))
        // Decrypt-failure classes (including former fresh-session repair errors) are
        // Orphan-resend on inbound; receive-side ASR is not used for them.
        let freshRepairErrors = try PQSFriendshipSource.functionBody(
            named: "private func isFreshSessionRepairError",
            in: sequenceSource)
        #expect(!freshRepairErrors.contains(".stateUninitialized"))
        #expect(sequenceSource.contains("ratchetError == .stateUninitialized"))
        let freshCatch = try #require(sequenceSource.range(of: "isFreshSessionRepairError(ratchetError)"))
        let afterFresh = sequenceSource[freshCatch.lowerBound...]
        #expect(afterFresh.contains("handleUndecryptableInboundResend("))
        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        #expect(!identitySource.contains("lanePromoteDeferredOrphanResend"))
        #expect(identitySource.contains("demoteZombieStateLessActives("))
        #expect(sequenceSource.contains("clearPreferredSessionIdentity(")
            || ratchetSource.contains("clearPreferredSessionIdentity("))
        // Wave drain / activate must not settle the orphan mark (false settle on control).
        #expect(!identitySource.contains("orphanResendSettled"))
        #expect(sessionSource.contains("orphanResendRecoverySessionByPeer")
            || sessionSource.contains("isOrphanResendRecoverySession("))
    }

    @Test("orphan remint does not capture general outbound fan-out")
    func orphanRemintDoesNotCaptureGeneralOutboundFanout() throws {
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")

        #expect(ratchetSource.contains("func outboundSessionIdentity("))
        #expect(ratchetSource.contains("return await bestSessionIdentity("))

        let outboundBody = try PQSFriendshipSource.functionBody(
            named: "func outboundSessionIdentity(",
            in: ratchetSource)
        // Stale-mark cleanup + one-active: never send on orphan when another
        // initialized active exists. Remint encrypt uses explicit recipientIdentity.
        #expect(outboundBody.contains("orphanResendInitiatingSessionId("))
        #expect(outboundBody.contains("clearOrphanResendInitiatingSession("))
        #expect(outboundBody.contains("nonOrphanInitialized"))
        #expect(outboundBody.contains("bestSessionIdentity("))
        #expect(outboundBody.contains("clearPreferredSessionIdentity("))
        #expect(!outboundBody.contains("return orphan"))
        #expect(!outboundBody.contains("orphanAdvanced"))

        let fanoutBody = try PQSFriendshipSource.functionBody(
            named: "func sessionIdentitiesForChatFanout",
            in: identitySource)
        #expect(fanoutBody.contains("taskProcessor.outboundSessionIdentity("))
        #expect(!fanoutBody.contains("existingProps.state != nil"))

        let resolveOutboundBody = try PQSFriendshipSource.functionBody(
            named: "private func resolveSessionIdentityForOutbound",
            in: ratchetSource)
        #expect(resolveOutboundBody.contains("outboundSessionIdentity("))
        #expect(!resolveOutboundBody.contains("bestSessionIdentity("))

        #expect(sessionSource.contains("func markOrphanResendInitiatingSession("))
        #expect(ratchetSource.contains("clearPreferredSessionIdentity("))
    }

    @Test("requestMessageResend uses control delivery selector not max sessionContextId")
    func requestMessageResendUsesControlDeliverySelectorNotMaxSessionContextId() throws {
        let eventsSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+Events.swift")
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")

        let resendBody = try PQSFriendshipSource.functionBody(
            named: "func requestMessageResend(sharedMessageIds:",
            in: eventsSource)
        #expect(resendBody.contains("resolveControlDeliverySessionIdentity("))
        #expect(!resendBody.contains("sessionContextId >"))
        #expect(!resendBody.contains("sessionContextId > selected"))

        let controlBody = try PQSFriendshipSource.functionBody(
            named: "func resolveControlDeliverySessionIdentity(",
            in: ratchetSource)
        #expect(controlBody.contains("outboundSessionIdentity("))
        // No-active fallback mints exactly once (reset with no actives demotes
        // nothing); the old path reset and then minted again on top of it.
        #expect(controlBody.contains("reason: \"resendRequestControlDelivery\""))
        #expect(!controlBody.contains("resolveResendUnavailableDeliveryIdentity("))
        #expect(controlBody.components(separatedBy: "resetSessionIdentityForFreshSession(").count - 1 == 1)
        #expect(!controlBody.contains("markOrphanResendInitiatingSession("))
    }

    @Test("warm chat fan-out avoids blocking findConfiguration when cache suffices")
    func warmChatFanoutAvoidsBlockingFindConfigurationWhenCacheSuffices() throws {
        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")

        #expect(sessionSource.contains("lastVerifiedDeviceIdsBySecretName"))

        let fanoutBody = try PQSFriendshipSource.functionBody(
            named: "func sessionIdentitiesForChatFanout",
            in: identitySource)
        #expect(fanoutBody.contains("lastVerifiedDeviceIdsBySecretName[secretName]"))
        #expect(fanoutBody.contains("if forceRefresh {"))
        // Must not unconditionally fetch configuration before comparing local lanes.
        let firstFind = fanoutBody.range(of: "findConfiguration(for: secretName)")
        let cacheRead = fanoutBody.range(of: "lastVerifiedDeviceIdsBySecretName[secretName]")
        #expect(firstFind != nil)
        #expect(cacheRead != nil)
        #expect(cacheRead!.lowerBound < firstFind!.lowerBound)
    }

    @Test("sticky orphan: wave drain does not clear mark; remint guarded")
    func stickyOrphanWaveDrainDoesNotClearMarkAndRemintIsGuarded() throws {
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let identitySource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")

        let drainBody = try PQSFriendshipSource.functionBody(
            named: "private func clearOrphanResendWaveIfDrained",
            in: ratchetSource)
        #expect(drainBody.contains("orphanResendWaveDrained"))
        #expect(!drainBody.contains("clearOrphanResendInitiatingSession("))

        #expect(sessionSource.contains("not when the local replay queue drains"))
        #expect(sessionSource.contains("not on generic inbound activate/promote")
            || sessionSource.contains("control frames falsely settled"))
        #expect(sessionSource.contains("orphanResendRecoverySessionByPeer"))
        #expect(sessionSource.contains("isOrphanResendRecoverySession("))
        #expect(sessionSource.contains("clearOrphanResendRecoveryState("))

        #expect(ratchetSource.contains("orphanResendRearmed"))
        #expect(sessionSource.contains("isOrphanResendRecoverySession("))
        #expect(ratchetSource.contains("outboundSessionIdentity("))
        // Sticky reuse only while marked row is still state-less (msg0 initiating).
        // Advanced sticky → remint; per-sharedId remint before encrypt if state set.
        #expect(ratchetSource.contains("protectedProps.state == nil"))
        #expect(ratchetSource.contains("orphanResendPerSharedIdInitiating"))
        #expect(ratchetSource.contains("reason=stateLess"))
        #expect(!ratchetSource.contains("reason=recoverySession"))
        #expect(!ratchetSource.contains("alreadyRecovery"))

        let activateBody = try PQSFriendshipSource.functionBody(
            named: "internal func activateSessionIdentityAfterInboundDecrypt",
            in: identitySource)
        #expect(activateBody.contains("isOrphanResendInitiatingSession("))
        #expect(activateBody.contains("clearOrphanResendInitiatingSession("))
        #expect(activateBody.contains("demotingOrphan"))
        #expect(!activateBody.contains("orphanResendSettled"))
        #expect(!activateBody.contains("endReestablishmentEpisode("))
        #expect(!drainBody.contains("endReestablishmentEpisode("))

        let promoteBody = try PQSFriendshipSource.functionBody(
            named: "internal func promoteArchivedSessionIdentityToActive",
            in: identitySource)
        #expect(promoteBody.contains("isOrphanResendInitiatingSession("))
        #expect(promoteBody.contains("clearOrphanResendInitiatingSession("))
        #expect(promoteBody.contains("demotingOrphan"))
        #expect(!promoteBody.contains("orphanResendSettled"))
        #expect(!promoteBody.contains("endReestablishmentEpisode("))
        #expect(!promoteBody.contains("removeIdentity(with:"))
        #expect(promoteBody.contains("sessionIdentities.remove("))

        let resetBody = try PQSFriendshipSource.functionBody(
            named: "internal func resetSessionIdentityForFreshSession",
            in: identitySource)
        #expect(resetBody.contains("clearOrphanResendRecoveryState("))
        #expect(resetBody.contains("reason != \"orphanResend\""))
    }

    @Test("non-viable transport parks recovery outbound for event wake")
    func nonViableTransportParksRecoveryOutboundForEventWake() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let deferBody = try PQSFriendshipSource.functionBody(
            named: "private func deferPendingOutboundTransportRetry",
            in: sequenceSource)
        #expect(deferBody.contains("parkForViability"))
        #expect(deferBody.contains("isConnectionNonViableError("))
        #expect(deferBody.contains("shouldLogOutboundTransportRetry("))
        // Event wake: do not short-timer requeue while non-viable.
        #expect(deferBody.contains("if !parkForViability"))
        #expect(deferBody.contains("loadAndOrganizeTasks(job, symmetricKey: symmetricKey)"))

        let undecryptableBody = try PQSFriendshipSource.functionBody(
            named: "private func handleUndecryptableInboundResend",
            in: sequenceSource)
        #expect(undecryptableBody.contains("resendParkedNonViable"))
        #expect(undecryptableBody.contains("return .paused"))
    }

    @Test("failed orphan replay re-arms bounded NACK; personal refresh cannot stomp orphan lane")
    func failedOrphanReplayRearmsBoundedNackAndProtectsPersonalRefresh() throws {
        let sequenceSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        let sessionSource = try PQSFriendshipSource.read("Sources/PQSSession/PQSSession.swift")
        let ratchetSource = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")

        #expect(sessionSource.contains("func armPeerResendRetryAfterFailedReplay("))
        #expect(sessionSource.contains("orphanReplayStillUndecryptable"))
        #expect(sessionSource.contains("action=rearmNack"))
        #expect(sessionSource.contains("peerResendRequestMaxSubmissions"))

        let undecryptableBody = try PQSFriendshipSource.functionBody(
            named: "private func handleUndecryptableInboundResend",
            in: sequenceSource)
        #expect(undecryptableBody.contains("armPeerResendRetryAfterFailedReplay("))
        #expect(undecryptableBody.contains("rearmedAfterFailedReplay"))
        // Re-armed sharedIds must NACK, not coalesce away.
        #expect(undecryptableBody.contains("if !rearmedAfterFailedReplay"))
        #expect(!undecryptableBody.contains("handleFreshSessionRepair("))
        #expect(!undecryptableBody.contains("kind: .peerRefresh"))

        let personalRefreshBody = try PQSFriendshipSource.functionBody(
            named: "private func prepareStateLessPersonalSessionIdentityForOutbound",
            in: ratchetSource)
        #expect(personalRefreshBody.contains("orphanResendInitiatingSessionId("))
        #expect(personalRefreshBody.contains("orphanResendProtectsPersonalRefresh"))
        #expect(personalRefreshBody.contains("return identity"))
        #expect(personalRefreshBody.contains("stateLessPersonalOutboundRefresh"))
    }
}

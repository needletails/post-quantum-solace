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

    @Test("inbound decrypt recovery resets without consuming server OTKs")
    func inboundDecryptRecoveryResetsWithoutConsumingServerOTKs() throws {
        let source = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        #expect(source.contains("action=freshSessionRepairThenDeferredResend"))
        #expect(source.contains("Repair must not consume a server OTK per decrypt failure"))
        #expect(source.contains("sendOneTimeIdentities: false"))
        // Cooldown is recorded only after a successful reset so a failed OTK/repair
        // attempt can retry instead of being silenced for 15s.
        #expect(source.contains("markReconciliationAttempt(\n                    sender: message.senderSecretName,\n                    deviceId: message.senderDeviceId,\n                    flow: .inbound)"))
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

    @Test("out-of-band resend reuses identity for recent control replay")
    func outOfBandResendReusesIdentityForRecentControlReplay() throws {
        let source = try PQSFriendshipSource.read("Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let body = try PQSFriendshipSource.functionBody(named: "func handleOutOfBandResendRequest", in: source)

        #expect(body.contains("onlyRecentControls"))
        #expect(body.contains("activeSessionIdentityForPeer"))
        #expect(body.contains("permanentlyUnavailableIds"))
        #expect(body.contains("flow: .outbound"))
        #expect(body.contains("isFriendshipStateControlMessage"))
        #expect(body.contains("staleFriendshipControl"))
        #expect(body.contains("sendOneTimeIdentities: false"))
        #expect(!body.contains("sendOneTimeIdentities: true)"))
    }

    @Test("session cache delete is idempotent when row is already absent")
    func sessionCacheDeleteIsIdempotentWhenRowIsAlreadyAbsent() throws {
        let source = try PQSFriendshipSource.read("Sources/PQSSession/Cache/SessionCache.swift")
        let body = try PQSFriendshipSource.functionBody(named: "public func deleteSessionIdentity", in: source)
        #expect(body.contains("guard identities.contains(where: { $0.id == id }) else"))
    }
}

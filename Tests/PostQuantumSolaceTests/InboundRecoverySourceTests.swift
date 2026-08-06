//
//  InboundRecoverySourceTests.swift
//  post-quantum-solace
//
//  Source-level contract for inbound decrypt recovery:
//  drain deferred NACKs on real events, event-driven terminality, and
//  pending-recovery host notification. Written red-first against the
//  coalesce-and-rot design.
//

import Foundation
import Testing

private enum InboundRecoverySource {
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
            url = url.deletingLastPathComponent()
        }
        throw NSError(
            domain: "InboundRecoverySourceTests",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Could not locate post-quantum-solace package root."]
        )
    }

    static func read(_ relativePath: String) throws -> String {
        let root = try packageRoot()
        return try String(contentsOf: root.appendingPathComponent(relativePath), encoding: .utf8)
    }

    static func functionBody(named signature: String, in source: String) throws -> String {
        guard let signatureRange = source.range(of: signature) else {
            throw NSError(
                domain: "InboundRecoverySourceTests",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Could not find function signature containing '\(signature)'."]
            )
        }
        guard let openBrace = source[signatureRange.upperBound...].firstIndex(of: "{") else {
            throw NSError(
                domain: "InboundRecoverySourceTests",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Could not find opening brace for '\(signature)'."]
            )
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

        throw NSError(
            domain: "InboundRecoverySourceTests",
            code: 4,
            userInfo: [NSLocalizedDescriptionKey: "Could not find closing brace for '\(signature)'."]
        )
    }
}

@Suite("Inbound recovery source guards")
struct InboundRecoverySourceTests {

    @Test("episode end drains deferred resends (expiry and explicit end)")
    func episodeEndDrainsDeferredResends() throws {
        let sessionSource = try InboundRecoverySource.read("Sources/PQSSession/PQSSession.swift")
        let cleanupBody = try InboundRecoverySource.functionBody(
            named: "func cleanupOpenReestablishmentEpisodes",
            in: sessionSource)
        #expect(cleanupBody.contains("flushPendingResends(")
            || cleanupBody.contains("drainPendingResends(")
            || cleanupBody.contains("takePendingResendsAfterReestablishment("))
        #expect(
            cleanupBody.contains("episodeExpired")
            || cleanupBody.contains("reason: \"episodeExpired\"")
            || cleanupBody.contains("reason: \"episode expiry\""))

        let endBody = try InboundRecoverySource.functionBody(
            named: "func endReestablishmentEpisode",
            in: sessionSource)
        #expect(endBody.contains("flushPendingResends(")
            || endBody.contains("drainPendingResends(")
            || endBody.contains("takePendingResendsAfterReestablishment("))
    }

    @Test("offline replay complete flush API exists and is public")
    func offlineReplayCompleteFlushAPIExists() throws {
        let sessionSource = try InboundRecoverySource.read("Sources/PQSSession/PQSSession.swift")
        #expect(
            sessionSource.contains("func flushPendingResendsAfterOfflineReplay(")
            || sessionSource.contains("public func flushPendingResendsAfterOfflineReplay("))
    }

    @Test("pending-resend cleanup is not wall-clock terminal")
    func pendingResendCleanupIsNotWallClockTerminal() throws {
        let sessionSource = try InboundRecoverySource.read("Sources/PQSSession/PQSSession.swift")
        let pendingCleanup = try InboundRecoverySource.functionBody(
            named: "private func cleanupPendingResendAfterReestablishment",
            in: sessionSource)
        #expect(!pendingCleanup.contains("pendingResendExpired"))
        #expect(!pendingCleanup.contains("pendingResendTTL"))
        #expect(!pendingCleanup.contains("inboundContentUnrecoverable("))
        #expect(!pendingCleanup.contains("markInboundContentUnrecoverable("))
        // LRU overflow eviction remains the only bound.
        #expect(pendingCleanup.contains("recoveryTrackingMaxEntries"))
    }

    @Test("pending recovery host event exists on the delegate")
    func pendingRecoveryHostEventExists() throws {
        let delegateSource = try InboundRecoverySource.read(
            "Sources/SessionEvents/PQSSessionDelegate.swift")
        #expect(delegateSource.contains("func inboundMessagePendingRecovery("))
        #expect(delegateSource.contains("senderSecretName: String"))
        #expect(delegateSource.contains("sharedMessageId: String"))

        let sessionSource = try InboundRecoverySource.read("Sources/PQSSession/PQSSession.swift")
        #expect(
            sessionSource.contains("inboundMessagePendingRecovery(")
            || sessionSource.contains("noteInboundMessagePendingRecovery("))
    }

    @Test("write-only recoveryEmitBlockedLanes is removed")
    func writeOnlyRecoveryEmitBlockedLanesIsRemoved() throws {
        let sessionSource = try InboundRecoverySource.read("Sources/PQSSession/PQSSession.swift")
        #expect(!sessionSource.contains("recoveryEmitBlockedLanes"))
        #expect(!sessionSource.contains("markRecoveryEmitBlocked"))
        #expect(!sessionSource.contains("isRecoveryEmitBlocked"))
    }

    @Test("orphan resend can heal inbound recovery placeholders")
    func orphanResendCanHealInboundRecoveryPlaceholders() throws {
        let ratchet = try InboundRecoverySource.read(
            "Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        #expect(ratchet.contains("isReplaceableInboundRecoveryPlaceholder"))
        #expect(ratchet.contains("placeholderHealed"))
        #expect(ratchet.contains("!Self.isReplaceableInboundRecoveryPlaceholder(existingProps)"))
    }

    @Test("resend-request attempt window outlives the failure-policy cooldown")
    func resendRequestAttemptWindowOutlivesFailurePolicyCooldown() throws {
        // The 3-submission terminality cap only binds if attempt history spans
        // more than one drain event. Drain boundaries (episode end, offline
        // replay complete) are routinely further apart than the 10-minute
        // failure-policy TTL; pruning attempts on that cooldown resets the cap
        // between events, so a dead lane NACKs forever and never terminalizes.
        let sessionSource = try InboundRecoverySource.read("Sources/PQSSession/PQSSession.swift")
        let pruneBody = try InboundRecoverySource.functionBody(
            named: "private func pruneResendRequestAttempts",
            in: sessionSource)
        #expect(pruneBody.contains("resendRequestAttemptWindowSeconds"))
        #expect(!pruneBody.contains("inboundFailurePolicyTTL"))

        let constants = try InboundRecoverySource.read("Sources/PQSSession/Constants.swift")
        #expect(constants.contains("resendRequestAttemptWindowSeconds"))
    }

    @Test("host re-arm API repopulates deferred NACK lanes after relaunch")
    func hostRearmAPIRepopulatesDeferredNACKLanes() throws {
        // PQS pending-resend state is in-memory; the host's placeholder rows are
        // the durable ledger. After process restart the host must be able to
        // repopulate the deferred NACK lane so drain events can retry, without
        // re-firing purge / pending-recovery delegates for rows it already owns.
        let sessionSource = try InboundRecoverySource.read("Sources/PQSSession/PQSSession.swift")
        #expect(sessionSource.contains("public func rearmInboundRecoveryPendingResend("))
        let rearmBody = try InboundRecoverySource.functionBody(
            named: "public func rearmInboundRecoveryPendingResend",
            in: sessionSource)
        #expect(rearmBody.contains("deferPeerResendUntilReestablished("))
        #expect(rearmBody.contains("notifyDelegate: false"))
    }
}

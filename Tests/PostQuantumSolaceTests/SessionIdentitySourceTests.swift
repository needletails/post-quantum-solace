//
//  SessionIdentitySourceTests.swift
//  post-quantum-solace
//
//  Source-level regression guards for identity refresh hardening.
//

import Foundation
import Testing

private enum PQSSessionIdentitySource {
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
        throw NSError(domain: "PQSSessionIdentitySource", code: 1)
    }

    static func read(_ relativePath: String) throws -> String {
        try String(contentsOf: packageRoot().appendingPathComponent(relativePath), encoding: .utf8)
    }
}

@Suite("Session identity source guards")
struct SessionIdentitySourceTests {
    @Test("identity refresh skips malformed provisional devices")
    func identityRefreshSkipsMalformedProvisionalDevices() throws {
        let source = try PQSSessionIdentitySource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")

        #expect(source.contains("verifiedDevicesWithUsableKeyMaterial"))
        #expect(source.contains("Skipping malformed \\(source) device during identity refresh"))
        #expect(source.contains("Curve25519.Signing.PublicKey(rawRepresentation: device.signingPublicKey)"))
        #expect(source.contains("Curve25519.KeyAgreement.PublicKey(rawRepresentation: currentDevice.longTermPublicKey)"))
    }

    @Test("full identity refresh prunes ghost devices via shared helper")
    func fullIdentityRefreshPrunesGhostDevicesViaSharedHelper() throws {
        let source = try PQSSessionIdentitySource.read("Sources/PQSSession/PQSSession+SessionIdentity.swift")
        #expect(source.contains("pruneStaleSessionIdentities"))
        #expect(source.contains("Will remove stale session identity for recipient"))

        let refreshBody = try {
            guard let range = source.range(of: "internal func refreshSessionIdentities(") else {
                throw NSError(domain: "SessionIdentitySourceTests", code: 1)
            }
            guard let open = source[range.upperBound...].firstIndex(of: "{") else {
                throw NSError(domain: "SessionIdentitySourceTests", code: 2)
            }
            var depth = 0
            var index = open
            while index < source.endIndex {
                switch source[index] {
                case "{": depth += 1
                case "}":
                    depth -= 1
                    if depth == 0 {
                        return String(source[open...index])
                    }
                default: break
                }
                index = source.index(after: index)
            }
            throw NSError(domain: "SessionIdentitySourceTests", code: 3)
        }()
        #expect(refreshBody.contains("pruneStaleSessionIdentities"))
    }

    @Test("device-local reset never performs account-wide transient cleanup")
    func deviceLocalResetUsesCacheOnlyInvalidation() throws {
        let source = try PQSSessionIdentitySource.read(
            "Sources/PQSSession/PQSSession+SessionIdentity.swift")
        let resetStart = try #require(
            source.range(of: "internal func resetSessionIdentityForFreshSession("))
        let resetWindow = String(source[resetStart.lowerBound...].prefix(12_000))
        #expect(resetWindow.contains("clearOrphanResendRecoveryState("))
        #expect(resetWindow.contains("invalidateSessionIdentityCache(secretName: secretName)"))
        #expect(!resetWindow.contains("removeIdentity(with: secretName)"))
    }

    @Test("startup does not prune archives before mailbox settlement")
    func archiveMaintenanceRequiresReplaySettlement() throws {
        let source = try PQSSessionIdentitySource.read(
            "Sources/PQSSession/PQSSession.swift")
        let startSession = try #require(source.range(of: "public func startSession("))
        let startWindow = String(source[startSession.lowerBound...].prefix(16_000))
        #expect(!startWindow.contains("cleanupAllInactiveSessionSnapshots()"))
        #expect(source.contains("public func offlineReplayDidSettle() async"))
        #expect(source.contains("if $0.hasState != $1.hasState"))
    }

    @Test("prepared outbound commits job and ratchet checkpoint together")
    func preparedOutboundUsesAtomicCacheCommit() throws {
        let ratchet = try PQSSessionIdentitySource.read(
            "Sources/PQSSession/Task/TaskProcessor+Ratchet.swift")
        let cache = try PQSSessionIdentitySource.read(
            "Sources/PQSSession/Cache/SessionCache.swift")
        let sequence = try PQSSessionIdentitySource.read(
            "Sources/PQSSession/Task/TaskProcessor+Sequence.swift")
        #expect(ratchet.contains("atomicOutboundPreparationIdentityIds"))
        #expect(ratchet.contains("cache.commitPreparedOutbound("))
        #expect(ratchet.contains("JobModel.PreparedOutbound("))
        #expect(cache.contains("andPreparedJob: job"))
        #expect(sequence.contains("await job.props(symmetricKey: symmetricKey) ?? props"))
        #expect(sequence.contains("updatedProps.delayedUntil = nil"))
    }
}

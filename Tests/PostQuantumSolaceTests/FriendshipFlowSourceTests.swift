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
    }

    @Test("legacy inverse block metadata still sends server unblock packet")
    func legacyInverseBlockMetadataStillSendsServerUnblockPacket() throws {
        let source = try PQSFriendshipSource.read("Sources/SessionEvents/SessionEvents.swift")
        let body = try PQSFriendshipSource.functionBody(named: "func requestFriendshipStateChange", in: source)

        #expect(body.contains("priorTheirState"))
        #expect(body.contains("priorMyState == .blocked || priorTheirState == .blocked"))
    }

    @Test("unblock restores pre-block relationship metadata when available")
    func unblockRestoresPreBlockRelationshipMetadataWhenAvailable() throws {
        let source = try PQSFriendshipSource.read("Sources/SessionModels/FriendshipMetadata.swift")

        #expect(source.contains("blockedPreviousMyState"))
        #expect(source.contains("blockedPreviousTheirState"))
        #expect(source.contains("let restoredMyState = blockedPreviousMyState?.restorableAfterUnblock ?? .pending"))
        #expect(source.contains("(blockedPreviousMyState, blockedPreviousTheirState) = (blockedPreviousTheirState, blockedPreviousMyState)"))
    }
}

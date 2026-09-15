//
//  DeliveryStateHandoffContractTests.swift
//  PostQuantumSolaceTests
//
//  Source-level guard: external receipt handoff happens before local mutation.
//

import Foundation
import Testing

#if !os(Android)
private enum DeliveryStateHandoffSource {
    static func packageRoot(fromFile file: StaticString = #filePath) throws -> URL {
        var url = URL(fileURLWithPath: "\(file)", isDirectory: false).deletingLastPathComponent()
        for _ in 0..<24 {
            let manifest = url.appendingPathComponent("Package.swift")
            if FileManager.default.fileExists(atPath: manifest.path),
               let source = try? String(contentsOf: manifest, encoding: .utf8),
               source.contains("name: \"post-quantum-solace\"") || source.contains("name: \"PQSSession\"") {
                return url
            }
            guard url.path != "/" else { break }
            url.deleteLastPathComponent()
        }
        throw NSError(
            domain: "DeliveryStateHandoffContractTests",
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
                domain: "DeliveryStateHandoffContractTests",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Missing signature \(signature)"]
            )
        }
        guard let openBrace = source[signatureRange.upperBound...].firstIndex(of: "{") else {
            throw NSError(
                domain: "DeliveryStateHandoffContractTests",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Missing opening brace for \(signature)"]
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
            domain: "DeliveryStateHandoffContractTests",
            code: 4,
            userInfo: [NSLocalizedDescriptionKey: "Missing closing brace for \(signature)"]
        )
    }
}

@Suite("Delivery state handoff contracts")
struct DeliveryStateHandoffContractTests {
    @Test("external update is handed off before local mutation")
    func handoffBeforeLocalCommit() throws {
        let source = try DeliveryStateHandoffSource.read(
            "Sources/SessionEvents/SessionEvents.swift"
        )
        let body = try DeliveryStateHandoffSource.functionBody(
            named: "allowExternalUpdate: Bool = false,",
            in: source
        )
        let handoff = try #require(body.range(of: "deliveryStateChanged("))
        let commit = try #require(body.range(of: "props.deliveryState = deliveryState"))
        #expect(handoff.lowerBound < commit.lowerBound)
        #expect(body.contains("durable handoff"))
    }

    @Test("process does not treat coalesced jobNotFound as an unhandled delete")
    func processDoesNotDeleteOnCoalescedJobNotFound() throws {
        let source = try DeliveryStateHandoffSource.read(
            "Sources/PQSSession/Task/TaskProcessor+Sequence.swift"
        )
        let processBody = try DeliveryStateHandoffSource.functionBody(
            named: "private func process(",
            in: source
        )
        #expect(processBody.contains("Job already removed before process"))
        #expect(processBody.contains("catch SessionCache.CacheErrors.jobNotFound"))
        #expect(processBody.contains("Job vanished during process"))
        guard let vanishedRange = processBody.range(of: "Job vanished during process") else {
            Issue.record("missing jobNotFound skip path")
            return
        }
        let vanishedTail = String(processBody[vanishedRange.lowerBound...])
        let vanishedCatch = String(vanishedTail.prefix(400))
        #expect(vanishedCatch.contains("return .deleted"))
        #expect(!vanishedCatch.contains("deleteJob"))
        #expect(!vanishedCatch.contains("Unhandled error during job processing"))

        let supersedeBody = try DeliveryStateHandoffSource.functionBody(
            named: "private func supersedePendingCoalescedJobs(",
            in: source
        )
        #expect(supersedeBody.contains("if isRunning && !enqueuedIds.contains(job.id)"))
    }
}
#endif

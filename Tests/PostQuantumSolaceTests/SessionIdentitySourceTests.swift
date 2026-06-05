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
}

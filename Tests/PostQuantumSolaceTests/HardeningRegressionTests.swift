//
//  HardeningRegressionTests.swift
//  post-quantum-solace
//
//  Smaller audit items: friendship merge authority, public crash paths, and
//  decoder allocation bounds.
//

import BinaryCodable
import Crypto
import Foundation
import NeedleTailCrypto
@testable import PQSSession
@testable import SessionEvents
import SessionModels
import Testing

@Suite("Hardening regressions")
struct HardeningRegressionTests {
    @Test("a peer cannot flip our rejection into acceptance")
    func peerCannotFlipRejectionToAccepted() {
        var stored = FriendshipMetadata()
        stored.setRequestedState()
        stored.swapUserPerspectives() // they requested us
        stored.rejectRequest()        // we rejected

        var passed = FriendshipMetadata()
        passed.setAcceptedState()     // peer claims everything is accepted
        passed.swapUserPerspectives()

        let merged = preferInboundFriendshipMetadata(passed: passed, stored: stored)
        #expect(merged.ourState != .accepted)
        #expect(merged.myState == stored.myState)
    }

    @Test("a peer accepting the request we made completes the friendship")
    func peerAcceptCompletesOurRequest() {
        var stored = FriendshipMetadata()
        stored.setRequestedState()    // we requested

        var passed = FriendshipMetadata()
        passed.setAcceptedState()
        passed.swapUserPerspectives()

        let merged = preferInboundFriendshipMetadata(passed: passed, stored: stored)
        #expect(merged.ourState == .accepted)
    }

    @Test("recipientDescription never traps")
    func recipientDescriptionIsTotal() {
        #expect(MessageRecipient.personalMessage.recipientDescription == "personal")
        #expect(MessageRecipient.broadcast.recipientDescription == "broadcast")
        #expect(MessageRecipient.nickname("bob").recipientDescription == "bob")
    }

    @Test("updateProps refuses a foreign type without touching the row")
    func updatePropsRefusesForeignType() async throws {
        let key = SymmetricKey(size: .bits256)
        let model = try BaseCommunication(
            id: UUID(),
            props: .init(
                messageCount: 0,
                members: ["a", "b"],
                metadata: Data(),
                blockedMembers: [],
                communicationType: .nickname("b")),
            symmetricKey: key)
        let before = model.data
        await #expect(throws: PQSError.propsError) {
            _ = try await model.updateProps(symmetricKey: key, props: "not props")
        }
        #expect(model.data == before)
    }

    @Test("decoder rejects a collection count larger than the remaining input before allocating")
    func decoderRejectsOversizedCount() {
        // Keyed container header claiming 0xFFFFFFFF entries, then nothing.
        var bytes = Data()
        var count = UInt32.max.bigEndian
        withUnsafeBytes(of: &count) { bytes.append(contentsOf: $0) }
        struct Probe: Codable { let a: Int }
        let started = Date()
        #expect(throws: (any Error).self) {
            _ = try BinaryDecoder().decode(Probe.self, from: bytes)
        }
        #expect(Date().timeIntervalSince(started) < 1, "must fail fast, not attempt a huge allocation")
    }
}

@Suite("Audit redaction")
struct AuditRedactionTests {
    @Test("secret names are replaced by stable tokens")
    func secretNamesAreRedacted() {
        let line = "pqs.send.attempt sharedId=abc recipient=nickname:bob deviceCount=1 persist=true members=alice,bob"
        let redacted = PQSAuditRedaction.redact(line)
        #expect(!redacted.contains("alice"))
        #expect(!redacted.contains("=nickname:bob"))
        #expect(redacted.contains("sharedId=abc"))
        #expect(redacted.contains("recipient=nickname:h:"))
        #expect(PQSAuditRedaction.token(for: "bob") == PQSAuditRedaction.token(for: "bob"))
    }
}

//
//  RatchetHeaderAuditTests.swift
//  post-quantum-solace
//
//  Failing, sent and replayed frames must say which keys their header names and
//  whether this device holds them: the 2026-10-28 logs never showed what 9CC8CF14,
//  210AC674 or BDF162B3 cited, so the missing one-time keys could not be traced.
//

import BinaryCodable
import DoubleRatchetKit
import Foundation
import SessionModels
import Testing

@testable import PQSSession

@Suite
struct RatchetHeaderAuditTests {
    private let citedOTK = UUID()
    private let citedMLKEM = UUID()
    private let embeddedOTK = UUID()
    private let embeddedMLKEM = UUID()

    private func header(citesOTK: UUID?, citesMLKEM: UUID?, embedsOTK: UUID?) throws -> EncryptedHeader {
        EncryptedHeader(
            remoteLongTermPublicKey: Data(repeating: 1, count: 32),
            remoteOneTimePublicKey: try embedsOTK.map { try X25519PublicKey(id: $0, Data(repeating: 2, count: 32)) },
            remoteMLKEMPublicKey: try MLKEMPublicKey(id: embeddedMLKEM, Data(repeating: 3, count: 1568)),
            headerCiphertext: Data(repeating: 4, count: 8),
            messageCiphertext: Data(repeating: 5, count: 8),
            oneTimeKeyId: citesOTK,
            mlKEMOneTimeKeyId: citesMLKEM ?? UUID(),
            encrypted: Data(repeating: 6, count: 8))
    }

    @Test("send fields separate the recipient's cited keys from the sender's embedded keys")
    func sendFieldsNameEachRole() throws {
        let audit = RatchetHeaderAudit(try header(citesOTK: citedOTK, citesMLKEM: citedMLKEM, embedsOTK: embeddedOTK))
        #expect(audit.sendFields == "citesOtk=\(citedOTK.uuidString) citesMlkem=\(citedMLKEM.uuidString) embedsOtk=\(embeddedOTK.uuidString) embedsMlkem=\(embeddedMLKEM.uuidString)")
    }

    @Test("inbound fields carry the hdr prefix, and an absent key reads nil")
    func inboundFieldsNameEachRole() throws {
        let audit = RatchetHeaderAudit(try header(citesOTK: nil, citesMLKEM: citedMLKEM, embedsOTK: nil))
        #expect(audit.inboundFields == "hdrCitesOtk=nil hdrCitesMlkem=\(citedMLKEM.uuidString) hdrEmbedsOtk=nil hdrEmbedsMlkem=\(embeddedMLKEM.uuidString)")
    }

    @Test("failure fields say the header was not verified")
    func unverifiedFieldsAreLabelled() throws {
        let audit = RatchetHeaderAudit(try header(citesOTK: citedOTK, citesMLKEM: citedMLKEM, embedsOTK: embeddedOTK))
        #expect(audit.unverifiedCitedFields == "hdrCitesOtk=\(citedOTK.uuidString) hdrCitesMlkem=\(citedMLKEM.uuidString) hdrUnverified=true")
    }

    @Test("a signed frame decodes to its header ids, and a frame without one decodes to nil")
    func signedFrameDecode() throws {
        let frameHeader = try header(citesOTK: citedOTK, citesMLKEM: citedMLKEM, embedsOTK: embeddedOTK)
        let signed = try SignedRatchetMessage(
            message: RatchetMessage(header: frameHeader, ciphertext: Data("ciphertext".utf8)),
            signingPrivateKey: Curve25519.Signing.PrivateKey().rawRepresentation)

        #expect(RatchetHeaderAudit(signedMessage: signed) == RatchetHeaderAudit(frameHeader))
        #expect(RatchetHeaderAudit(signedMessage: SignedRatchetMessage()) == nil)
    }

    @Test("otkHeld follows initializeRecipient's order: pool, then row")
    func otkHeldLookupOrder() {
        let id = UUID()
        let other = UUID()
        #expect(RatchetHeaderAudit.otkHeld(citedId: id, poolIds: [other, id], rowIds: [id]) == "pool")
        #expect(RatchetHeaderAudit.otkHeld(citedId: id, poolIds: [other], rowIds: [other, id]) == "row")
        #expect(RatchetHeaderAudit.otkHeld(citedId: id, poolIds: [other], rowIds: [other]) == "none")
        #expect(RatchetHeaderAudit.otkHeld(citedId: nil, poolIds: [other], rowIds: [other]) == "none")
    }

    @Test("mlkemHeld follows initializeRecipient's order: pool, final, row, with a keyless header on final")
    func mlkemHeldLookupOrder() {
        let id = UUID()
        let other = UUID()
        #expect(RatchetHeaderAudit.mlkemHeld(citedId: id, poolIds: [id], finalHolds: true, rowIds: [id]) == "pool")
        #expect(RatchetHeaderAudit.mlkemHeld(citedId: id, poolIds: [other], finalHolds: true, rowIds: [id]) == "final")
        #expect(RatchetHeaderAudit.mlkemHeld(citedId: id, poolIds: [other], finalHolds: false, rowIds: [id]) == "row")
        #expect(RatchetHeaderAudit.mlkemHeld(citedId: id, poolIds: [other], finalHolds: false, rowIds: [other]) == "none")
        #expect(RatchetHeaderAudit.mlkemHeld(citedId: nil, poolIds: [other], finalHolds: false, rowIds: [other]) == "final")
    }
}

extension EndToEndTests {
    /// Alice re-keys toward bob and encrypts one frame that is held in transit.
    private func heldInitiatingFrame(
        _ pair: ConnectedPair,
        sharedId: String
    ) async throws -> (frame: ReceivedMessage, header: EncryptedHeader) {
        try await settleLanes(pair)
        _ = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sendOneTimeIdentities: true,
            reason: "test")
        let held = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob", received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        try await pair.alice.send(recipient: .nickname("bob"), text: "held", sharedIdOverride: sharedId)
        #expect(await pollUntil(timeout: 20) { await held.count == 1 })
        pair.aliceTransport.shouldDeliver = nil
        let frame = try #require(await held.take().first)
        let signed = try #require(frame.message.signed)
        return (frame, try BinaryDecoder().decode(RatchetMessage.self, from: signed.data).header)
    }

    private func expectSendFields(_ line: String, _ header: EncryptedHeader) throws {
        #expect(line.contains("citesOtk=\(try #require(header.oneTimeKeyId).uuidString)"))
        #expect(line.contains("citesMlkem=\(try #require(header.mlKEMOneTimeKeyId).uuidString)"))
        #expect(line.contains("embedsOtk=\(try #require(header.remoteOneTimePublicKey?.id).uuidString)"))
        #expect(line.contains("embedsMlkem=\(header.remoteMLKEMPublicKey.id.uuidString)"))
    }

    @Test("a transported frame's audit line names the keys its header cites and embeds")
    func deviceTransportOkNamesHeaderKeys() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(aliceAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        let sharedId = "audit-send-\(UUID().uuidString)"

        let (_, header) = try await heldInitiatingFrame(pair, sharedId: sharedId)

        let lines = sink.lines(containing: "pqs.send.deviceTransportOk sharedId=\(sharedId)")
        #expect(lines.count == 1)
        try expectSendFields(try #require(lines.first), header)
        await pair.finish()
    }

    @Test("a transport line naming every key fits one line of the audit file")
    func deviceTransportOkFitsOneAuditFileLine() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(aliceAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        let sharedId = UUID().uuidString

        _ = try await heldInitiatingFrame(pair, sharedId: sharedId)

        let line = try #require(sink.lines(containing: "pqs.send.deviceTransportOk sharedId=\(sharedId)").first)
        #expect(PQSAuditRedaction.redact(line).count <= FilePQSAuditSink.maxLineLength)
        await pair.finish()
    }

    @Test("a replayed pending frame logs the same transport line, decoded from the frame")
    func pendingTransportNamesHeaderKeys() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(aliceAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        let (frame, header) = try await heldInitiatingFrame(pair, sharedId: "audit-held-\(UUID().uuidString)")

        let sharedId = "audit-pending-\(UUID().uuidString)"
        let identityId = UUID()
        let pending = MessagePipeline.PendingOutboundTransport(
            message: frame.message,
            metadata: SignedRatchetMessageMetadata(
                secretName: "bob",
                deviceId: pair.bobDeviceId,
                recipient: .nickname("bob"),
                transportMetadata: Data(),
                sharedMessageId: sharedId,
                envelopeMessageId: "audit-envelope",
                transportEvent: nil,
                requiresServerAck: false),
            sessionIdentityId: identityId,
            x25519OneTimeKeyId: nil,
            mlKEMOneTimeKeyId: UUID().uuidString,
            createdAt: Date())
        let outbound = OutboundTaskMessage(
            message: CryptoMessage(
                text: "replayed",
                metadata: Data(),
                recipient: .nickname("bob"),
                sentDate: Date(),
                destructionTime: nil),
            recipientIdentity: SessionIdentity(id: identityId, data: Data()),
            localId: UUID(),
            sharedId: sharedId,
            isPersistedOutbound: false)

        pair.aliceTransport.shouldDeliver = { _ in false }
        try await pair.alice.messagePipeline.sendPendingOutboundTransport(
            pending,
            outboundTask: outbound,
            session: pair.alice)

        let line = try #require(sink.lines(containing: "pqs.send.deviceTransportOk sharedId=\(sharedId)").first)
        #expect(line.contains("envelopeMessageId=audit-envelope"))
        #expect(line.contains("sessionIdentityId=\(identityId.uuidString)"))
        #expect(line.contains("pending=true"))
        try expectSendFields(line, header)
        pair.aliceTransport.shouldDeliver = nil
        await pair.finish()
    }

    @Test("a frame citing keys this device lost names them on the rollback and failure lines")
    func failedDecryptNamesTheCitedKeysAndWhichLookupMissed() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(bobAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        let sharedId = "audit-lost-\(UUID().uuidString)"
        let (frame, header) = try await heldInitiatingFrame(pair, sharedId: sharedId)
        let citedOTK = try #require(header.oneTimeKeyId)
        let citedMLKEM = try #require(header.mlKEMOneTimeKeyId)

        var context = try #require(await pair.bob.sessionContext)
        #expect(context.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.contains { $0.id == citedMLKEM },
                "this test needs a frame citing a pool key, so the lookup can miss")
        context.sessionUser.deviceKeys.oneTimePrivateKeys.removeAll { $0.id == citedOTK }
        context.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.removeAll { $0.id == citedMLKEM }
        await pair.bob.setSessionContext(context)

        pair.aliceTransport.continuation?.yield(frame)

        #expect(await pollUntil(timeout: 20) {
            sink.contains("pqs.recovery.laneRolledBack") && sink.contains("pqs.decryptFailure")
        })
        let rollback = try #require(sink.lines(containing: "pqs.recovery.laneRolledBack").first)
        #expect(rollback.contains("hdrCitesOtk=\(citedOTK.uuidString)"))
        #expect(rollback.contains("hdrCitesMlkem=\(citedMLKEM.uuidString)"))
        #expect(rollback.contains("hdrEmbedsMlkem=\(header.remoteMLKEMPublicKey.id.uuidString)"))
        #expect(rollback.contains("otkHeld=none mlkemHeld=none"))
        // A long attempt list may wrap; everything ahead of it must not.
        let attempts = try #require(rollback.range(of: " attempts="))
        #expect(PQSAuditRedaction.redact(String(rollback[..<attempts.lowerBound])).count <= FilePQSAuditSink.maxLineLength)
        let failure = try #require(sink.lines(containing: "pqs.decryptFailure").first)
        #expect(failure.contains("hdrCitesOtk=\(citedOTK.uuidString)"))
        #expect(failure.contains("hdrCitesMlkem=\(citedMLKEM.uuidString)"))
        #expect(failure.contains("hdrUnverified=true"))
        await pair.finish()
    }
}

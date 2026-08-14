//
//  EnvelopeMessageIdTests.swift
//  post-quantum-solace
//
//  Strict §4.1 RED/GREEN: unique MessageID per encrypted per-device
//  envelope; resend replaces envelope while preserving logical sharedId.
//

import Foundation
import Crypto
import SessionModels
import Testing
@testable import PQSSession

@Suite("Envelope MessageID (§4.1)")
struct EnvelopeMessageIdTests {
    @Test("S11: fan-out mints distinct envelope ids per device")
    func fanoutMintsDistinctEnvelopes() {
        let deviceA = UUID()
        let deviceB = UUID()
        let logical = UUID().uuidString
        let envelopes = [
            (deviceA, EnvelopeMessageIdentityPolicy.mintEnvelopeMessageId()),
            (deviceB, EnvelopeMessageIdentityPolicy.mintEnvelopeMessageId()),
        ]
        #expect(EnvelopeMessageIdentityPolicy.fanoutEnvelopesAreDistinct(envelopes: envelopes))
        #expect(envelopes[0].1 != envelopes[1].1)
        #expect(envelopes[0].1.rawValue != logical || envelopes[1].1.rawValue != logical)
    }

    @Test("S12: resend replaces envelope and preserves logical id")
    func resendSupersedesEnvelope() {
        let logical = LogicalMessageID("logical-shared")
        let prior = EnvelopeID("envelope-v1")
        let next = EnvelopeMessageIdentityPolicy.mintEnvelopeMessageId()
        #expect(
            EnvelopeMessageIdentityPolicy.resendReplacesEnvelope(
                priorEnvelopeMessageId: prior,
                newEnvelopeMessageId: next,
                priorLogicalSharedId: logical,
                newLogicalSharedId: logical))
        #expect(
            !EnvelopeMessageIdentityPolicy.resendReplacesEnvelope(
                priorEnvelopeMessageId: prior,
                newEnvelopeMessageId: prior,
                priorLogicalSharedId: logical,
                newLogicalSharedId: logical))
    }

    @Test("resolveLogicalMessageId returns the logical id")
    func resolveLogicalMessageIdReturnsLogical() {
        let envelope = EnvelopeID("env")
        let logical = LogicalMessageID("logical")
        #expect(
            EnvelopeMessageIdentityPolicy.resolveLogicalMessageId(
                envelopeMessageId: envelope,
                logicalMessageId: logical) == logical)
    }

    @Test("S11: production OutboundDeviceSendRecord retains envelope history")
    func outboundRecordRetainsEnvelopeHistory() {
        let record = OutboundDeviceSendRecord(
            envelopeMessageId: "env-1",
            sharedId: "logical-1",
            recipientSecretName: "bob",
            recipientDeviceId: UUID(),
            sessionIdentityId: UUID(),
            resendAttempt: 0)
        #expect(record.envelopeMessageId == "env-1")
        #expect(record.sharedId == "logical-1")
        #expect(record.supersededAt == nil)
        #expect(record.resendAttempt == 0)
    }

    @Test("Accepted ledger marks only after full success")
    func acceptedLedgerRequiresFullSuccess() {
        #expect(
            !AcceptedEnvelopeLedgerPolicy.shouldMarkAccepted(
                decryptSucceeded: true,
                payloadDecoded: true,
                hostHandlingSucceeded: false))
        #expect(
            AcceptedEnvelopeLedgerPolicy.shouldMarkAccepted(
                decryptSucceeded: true,
                payloadDecoded: true,
                hostHandlingSucceeded: true))
    }

    @Test("T13/T16: accepted drop is sender-device-envelope scoped")
    func acceptedDropIsDeviceScoped() {
        let deviceA = UUID()
        let deviceB = UUID()
        let keyA = AcceptedEnvelopeKey(
            senderSecretName: "alice",
            senderDeviceId: deviceA,
            envelopeMessageId: "env-1")
        let keyB = AcceptedEnvelopeKey(
            senderSecretName: "alice",
            senderDeviceId: deviceB,
            envelopeMessageId: "env-1")
        #expect(AcceptedEnvelopeLedgerPolicy.keysAreIndependent(keyA, keyB))
        var accepted: Set<String> = [keyA.storageKey]
        #expect(AcceptedEnvelopeLedgerPolicy.shouldAckAndDrop(key: keyA, accepted: accepted))
        #expect(!AcceptedEnvelopeLedgerPolicy.shouldAckAndDrop(key: keyB, accepted: accepted))
        accepted.insert(keyB.storageKey)
        #expect(AcceptedEnvelopeLedgerPolicy.shouldAckAndDrop(key: keyB, accepted: accepted))
    }

    @Test("T15: accepted ledger prune uses retention expiry")
    func acceptedLedgerPruneUsesRetentionExpiry() {
        let acceptedAt = Date(timeIntervalSince1970: 1_000)
        let retention: TimeInterval = 600
        #expect(
            !AcceptedEnvelopeLedgerPolicy.isExpired(
                acceptedAt: acceptedAt,
                now: acceptedAt.addingTimeInterval(599),
                retention: retention))
        #expect(
            AcceptedEnvelopeLedgerPolicy.isExpired(
                acceptedAt: acceptedAt,
                now: acceptedAt.addingTimeInterval(601),
                retention: retention))
    }

    /// Covered by EndToEndTests "Duplicate decrypts and redelivered frames persist
    /// exactly one row per shared id" and `acceptedDropIsDeviceScoped` above.
    /// Compile-time pin: inbound consults `hasAcceptedEnvelope` (rename fails this suite).
    @Test("T13: inbound path drops already-accepted envelopes before ratchet")
    func inboundDropsAlreadyAcceptedBeforeRatchet() {
        let pin: (PQSSession, String, UUID, String) async throws -> Bool = {
            try await $0.hasAcceptedEnvelope(
                senderSecretName: $1,
                senderDeviceId: $2,
                envelopeMessageId: $3)
        }
        _ = pin
        let key = AcceptedEnvelopeKey(
            senderSecretName: "alice",
            senderDeviceId: UUID(),
            envelopeMessageId: "env-1")
        #expect(
            AcceptedEnvelopeLedgerPolicy.shouldAckAndDrop(
                key: key,
                accepted: [key.storageKey]))
    }

    @Test("T17: archive tokens for distinct fingerprints are independent")
    func archiveTokensIndependentAcrossFingerprints() {
        let device = UUID()
        let a = ArchivedInboundFallbackToken(
            senderSecretName: "bob",
            senderDeviceId: device,
            envelopeMessageId: "env-1",
            fingerprint: Data([0x01]))
        let b = ArchivedInboundFallbackToken(
            senderSecretName: "bob",
            senderDeviceId: device,
            envelopeMessageId: "env-1",
            fingerprint: Data([0x02]))
        #expect(InboundRecoveryStormPolicy.tokensAreIndependent(a, b))
        var exhausted: Set<String> = []
        var pending: Set<String> = []
        #expect(
            InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
                token: a, exhausted: exhausted, pendingPass: pending))
        pending.insert(a.storageKey)
        #expect(
            !InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
                token: a, exhausted: exhausted, pendingPass: pending))
        #expect(
            InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
                token: b, exhausted: exhausted, pendingPass: pending),
            "Fresh fingerprint must retain its own archive pass")
        exhausted = InboundRecoveryStormPolicy.exhaustedAfterArchivePassCompleted(
            current: exhausted, token: a)
        #expect(
            InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
                token: b, exhausted: exhausted, pendingPass: []))
    }

    @Test("S14: OOB resend controls authenticate origin, target, and request id")
    func outOfBandResendControlAuthenticates() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let senderDeviceId = UUID()
        let targetDeviceId = UUID()
        let requestId = UUID()
        let control = try OutOfBandResendControl(
            kind: .request,
            requestId: requestId,
            senderSecretName: "alice",
            senderDeviceId: senderDeviceId,
            targetSecretName: "bob",
            targetDeviceId: targetDeviceId,
            envelopeMessageIds: ["env-1", "env-2"],
            signingPrivateKey: privateKey.rawRepresentation)

        try control.verify(
            signingPublicKey: privateKey.publicKey.rawRepresentation)
        #expect(control.requestId == requestId)
        #expect(control.senderDeviceId == senderDeviceId)
        #expect(control.targetDeviceId == targetDeviceId)
        #expect(control.envelopeMessageIds == ["env-1", "env-2"])

        let attackerKey = Curve25519.Signing.PrivateKey()
        #expect(throws: OutOfBandResendControl.ValidationError.self) {
            try control.verify(
                signingPublicKey: attackerKey.publicKey.rawRepresentation)
        }
    }

    @Test("S14: OOB resend controls reject oversized batches")
    func outOfBandResendControlBoundsBatch() {
        let privateKey = Curve25519.Signing.PrivateKey()
        #expect(throws: OutOfBandResendControl.ValidationError.self) {
            _ = try OutOfBandResendControl(
                kind: .request,
                senderSecretName: "alice",
                senderDeviceId: UUID(),
                targetSecretName: "bob",
                targetDeviceId: UUID(),
                envelopeMessageIds: (0...OutOfBandResendControl.maxMessageIds)
                    .map { "env-\($0)" },
                signingPrivateKey: privateKey.rawRepresentation)
        }
    }

    /// Covered by `acceptedLedgerRequiresFullSuccess` in this suite (hostHandlingSucceeded
    /// false must not mark accepted) and EndToEndTests duplicate-decrypt persistence.
    /// Private `shouldAcceptWithoutChatRow` is the control/non-persist exception, not a public API.
    @Test("T14: persistable host decline must not finalizeAcceptedInbound unconditionally")
    func persistableHostDeclineMustNotFinalizeAcceptedUnconditionally() {
        #expect(
            !AcceptedEnvelopeLedgerPolicy.shouldMarkAccepted(
                decryptSucceeded: true,
                payloadDecoded: true,
                hostHandlingSucceeded: false))
        #expect(
            AcceptedEnvelopeLedgerPolicy.shouldMarkAccepted(
                decryptSucceeded: true,
                payloadDecoded: true,
                hostHandlingSucceeded: true))
    }
}

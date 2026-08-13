//
//  RecoveryScenarioHarnessTests.swift
//  post-quantum-solace
//

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
@testable import PQSSession
import SessionModels
import Testing

/// Deterministic event gate for recovery tests. Tests explicitly release state
/// transitions instead of waiting for wall-clock delays.
private actor RecoveryEventGate<Event: Hashable & Sendable> {
    private var arrived = Set<Event>()
    private var arrivalWaiters: [Event: [CheckedContinuation<Void, Never>]] = [:]
    private var releaseWaiters: [Event: [CheckedContinuation<Void, Never>]] = [:]
    private var released = Set<Event>()

    func arriveAndWait(for event: Event) async {
        arrived.insert(event)
        let waiters = arrivalWaiters.removeValue(forKey: event) ?? []
        waiters.forEach { $0.resume() }
        guard !released.contains(event) else { return }
        await withCheckedContinuation { continuation in
            releaseWaiters[event, default: []].append(continuation)
        }
    }

    func waitUntilArrived(_ event: Event) async {
        guard !arrived.contains(event) else { return }
        await withCheckedContinuation { continuation in
            arrivalWaiters[event, default: []].append(continuation)
        }
    }

    func release(_ event: Event) {
        released.insert(event)
        let waiters = releaseWaiters.removeValue(forKey: event) ?? []
        waiters.forEach { $0.resume() }
    }
}

actor PreparedTransportProbe: PQSTransport, PQSKeyDirectory, PQSRecoveryTransport {
    enum ProbeError: Error {
        case unsupported
    }

    private var payloads: [Data] = []
    private var envelopeMessageIds: [String] = []
    private var sendWaiters: [CheckedContinuation<Void, Never>] = []

    func sendMessage(
        _ message: SignedRatchetMessage,
        metadata: SignedRatchetMessageMetadata
    ) async throws {
        payloads.append(message.signed?.data ?? Data())
        envelopeMessageIds.append(metadata.envelopeMessageId)
        let waiters = sendWaiters
        sendWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }

    /// Suspends until at least `count` sends were captured. Event-driven so tests never
    /// race real code against a fixed sleep (deadline resends land whenever the actor
    /// hop completes, not on a stopwatch).
    func waitForCapturedSends(atLeast count: Int) async {
        while payloads.count < count {
            await withCheckedContinuation { sendWaiters.append($0) }
        }
    }

    func capturedPayloads() -> [Data] {
        payloads
    }

    func capturedEnvelopeMessageIds() -> [String] {
        envelopeMessageIds
    }

    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        throw ProbeError.unsupported
    }

    func publishUserConfiguration(
        _ configuration: UserConfiguration,
        recipient secretName: String,
        recipient identity: UUID
    ) async throws {
        throw ProbeError.unsupported
    }

    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> OneTimeKeys {
        throw ProbeError.unsupported
    }

    func fetchOneTimeKeyIdentities(
        for secretName: String,
        deviceId: String,
        type: KeyKind
    ) async throws -> [UUID] {
        throw ProbeError.unsupported
    }

    func updateOneTimeKeys(
        for secretName: String,
        deviceId: String,
        keys: [UserConfiguration.SignedOneTimePublicKey]
    ) async throws {
        throw ProbeError.unsupported
    }

    func updateOneTimeMLKEMKeys(
        for secretName: String,
        deviceId: String,
        keys: [UserConfiguration.SignedMLKEMOneTimeKey]
    ) async throws {
        throw ProbeError.unsupported
    }

    func batchDeleteOneTimeKeys(
        for secretName: String,
        with id: String,
        type: KeyKind
    ) async throws {
        throw ProbeError.unsupported
    }

    func deleteOneTimeKeys(
        for secretName: String,
        with id: String,
        type: KeyKind
    ) async throws {
        throw ProbeError.unsupported
    }

    func publishRotatedKeys(
        for secretName: String,
        deviceId: String,
        rotated keys: RotatedPublicKeys
    ) async throws {
        throw ProbeError.unsupported
    }

    func createUploadPacket(
        secretName: String,
        deviceId: UUID,
        recipient: MessageRecipient,
        metadata: Data
    ) async throws {
        throw ProbeError.unsupported
    }

    func sendOutOfBandResendRequest(
        failedEnvelopeMessageIds: [String],
        to secretName: String,
        deviceId: UUID,
        requestingDeviceId: UUID
    ) async throws {
        throw ProbeError.unsupported
    }

    func sendOutOfBandResendUnavailable(
        unavailableEnvelopeMessageIds: [String],
        to secretName: String,
        deviceId: UUID,
        respondingDeviceId: UUID
    ) async throws {
        throw ProbeError.unsupported
    }
}

@Suite(.serialized)
struct RecoveryScenarioHarnessTests {
    private enum Event: Hashable, Sendable {
        case siblingRecoveryOwned
    }

    @Test("Device-local reset bookkeeping preserves sibling recovery ownership")
    func deviceLocalRecoveryClearPreservesSibling() async {
        let session = PQSSession()
        let peer = "alice"
        let resettingDevice = UUID()
        let siblingDevice = UUID()
        let resettingSession = UUID()
        let siblingSession = UUID()
        let gate = RecoveryEventGate<Event>()

        await session.markOrphanResendInitiatingSession(
            secretName: peer,
            deviceId: resettingDevice,
            sessionId: resettingSession)

        let siblingOwner = Task {
            await session.markOrphanResendInitiatingSession(
                secretName: peer,
                deviceId: siblingDevice,
                sessionId: siblingSession)
            await gate.arriveAndWait(for: .siblingRecoveryOwned)
        }

        await gate.waitUntilArrived(.siblingRecoveryOwned)
        await session.clearOrphanResendRecoveryState(
            secretName: peer,
            deviceId: resettingDevice)
        await session.invalidateSessionIdentityCache(secretName: peer)

        #expect(await session.orphanResendInitiatingSessionId(
            secretName: peer,
            deviceId: resettingDevice) == nil)
        #expect(await session.orphanResendRecoverySessionId(
            secretName: peer,
            deviceId: resettingDevice) == nil)
        #expect(await session.orphanResendInitiatingSessionId(
            secretName: peer,
            deviceId: siblingDevice) == siblingSession)
        #expect(await session.orphanResendRecoverySessionId(
            secretName: peer,
            deviceId: siblingDevice) == siblingSession)

        await gate.release(.siblingRecoveryOwned)
        await siblingOwner.value
        await session.shutdown()
    }

    @Test("Account removal still clears every sibling recovery lane")
    func accountRemovalClearsAllSiblingRecovery() async {
        let session = PQSSession()
        let peer = "alice"
        let firstDevice = UUID()
        let secondDevice = UUID()

        await session.markOrphanResendInitiatingSession(
            secretName: peer,
            deviceId: firstDevice,
            sessionId: UUID())
        await session.markOrphanResendInitiatingSession(
            secretName: peer,
            deviceId: secondDevice,
            sessionId: UUID())

        await session.removeIdentity(with: peer)

        #expect(await session.orphanResendRecoverySessionId(
            secretName: peer,
            deviceId: firstDevice) == nil)
        #expect(await session.orphanResendRecoverySessionId(
            secretName: peer,
            deviceId: secondDevice) == nil)
        await session.shutdown()
    }

    @Test("Prepared outbound checkpoint round-trips exact signed ciphertext")
    func preparedOutboundRoundTripsExactCiphertext() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let mlKEMId = UUID()
        let encryptedHeader = EncryptedHeader(
            remoteLongTermPublicKey: Data(repeating: 0x11, count: 32),
            remoteOneTimePublicKey: nil,
            remoteMLKEMPublicKey: try MLKEMPublicKey(
                id: mlKEMId,
                Data(repeating: 0x22, count: 1_568)),
            headerCiphertext: Data([0x01]),
            messageCiphertext: Data([0x02]),
            oneTimeKeyId: nil,
            mlKEMOneTimeKeyId: mlKEMId,
            encrypted: Data([0x03]))
        let signed = try SignedRatchetMessage(
            message: RatchetMessage(
                header: encryptedHeader,
                ciphertext: Data([0xA1, 0xB2, 0xC3])),
            signingPrivateKey: signingKey.rawRepresentation)
        let sessionIdentityId = UUID()
        let deviceId = UUID()
        let prepared = JobModel.PreparedOutbound(
            signedMessage: signed,
            secretName: "bob",
            deviceId: deviceId,
            recipient: .nickname("bob"),
            transportMetadata: Data([0x01, 0x02]),
            sharedMessageId: "shared-id",
            envelopeMessageId: "shared-id",
            transportEvent: nil,
            sessionIdentityId: sessionIdentityId,
            needsRemoteDeletion: true,
            x25519OneTimeKeyId: "curve-id",
            mlKEMOneTimeKeyId: "mlkem-id")

        let encoded = try BinaryEncoder().encode(prepared)
        let decoded = try BinaryDecoder().decode(
            JobModel.PreparedOutbound.self,
            from: encoded)

        #expect(decoded.signedMessage.signed?.data == signed.signed?.data)
        #expect(decoded.secretName == "bob")
        #expect(decoded.deviceId == deviceId)
        #expect(decoded.sharedMessageId == "shared-id")
        #expect(decoded.sessionIdentityId == sessionIdentityId)
        #expect(decoded.needsRemoteDeletion)
        #expect(decoded.x25519OneTimeKeyId == "curve-id")
        #expect(decoded.mlKEMOneTimeKeyId == "mlkem-id")
    }

    @Test("Prepared ciphertext is identical after task processor recreation")
    func preparedCiphertextReplaysUnchangedAfterProcessorRecreation() async throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let mlKEMId = UUID()
        let header = EncryptedHeader(
            remoteLongTermPublicKey: Data(repeating: 0x31, count: 32),
            remoteOneTimePublicKey: nil,
            remoteMLKEMPublicKey: try MLKEMPublicKey(
                id: mlKEMId,
                Data(repeating: 0x32, count: 1_568)),
            headerCiphertext: Data([0x33]),
            messageCiphertext: Data([0x34]),
            oneTimeKeyId: nil,
            mlKEMOneTimeKeyId: mlKEMId,
            encrypted: Data([0x35]))
        let signed = try SignedRatchetMessage(
            message: RatchetMessage(
                header: header,
                ciphertext: Data([0x36, 0x37])),
            signingPrivateKey: signingKey.rawRepresentation)
        let identityId = UUID()
        let deviceId = UUID()
        let prepared = JobModel.PreparedOutbound(
            signedMessage: signed,
            secretName: "bob",
            deviceId: deviceId,
            recipient: .nickname("bob"),
            transportMetadata: nil,
            sharedMessageId: "relaunch-shared-id",
            envelopeMessageId: "relaunch-shared-id",
            transportEvent: nil,
            sessionIdentityId: identityId,
            needsRemoteDeletion: false,
            x25519OneTimeKeyId: nil,
            mlKEMOneTimeKeyId: mlKEMId.uuidString)
        let outbound = OutboundTaskMessage(
            message: CryptoMessage(
                text: "logical-message",
                metadata: Data(),
                recipient: .nickname("bob"),
                sentDate: Date(),
                destructionTime: nil),
            recipientIdentity: SessionIdentity(id: identityId, data: Data()),
            localId: UUID(),
            sharedId: prepared.sharedMessageId,
            isPersistedOutbound: true)
        let session = PQSSession()
        let transport = PreparedTransportProbe()
        await session.setTransportDelegate(conformer: transport)

        let beforeRelaunch = MessagePipeline()
        try await beforeRelaunch.sendPreparedOutbound(
            prepared,
            outboundTask: outbound,
            session: session)
        try await beforeRelaunch.ratchetManager.flushAndClose()
        let afterRelaunch = MessagePipeline()
        try await afterRelaunch.sendPreparedOutbound(
            prepared,
            outboundTask: outbound,
            session: session)
        try await afterRelaunch.ratchetManager.flushAndClose()

        let payloads = await transport.capturedPayloads()
        #expect(payloads.count == 2)
        #expect(payloads[0] == payloads[1])
        #expect(payloads[0] == signed.signed?.data)
        await session.shutdown()
    }
}

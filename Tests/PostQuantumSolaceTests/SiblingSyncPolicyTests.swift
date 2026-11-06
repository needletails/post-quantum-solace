//
//  SiblingSyncPolicyTests.swift
//  post-quantum-solace
//
//  Bug: a `.nickname` send reached the sender's other linked devices only when
//  the host persisted it as a chat row. Edits and reactions are non-persisted
//  controls, so a reaction made on one device never reached its siblings.
//  `shouldSyncToSiblings` is now its own host decision, defaulting to
//  `shouldPersist` so existing hosts keep their behavior.
//

import DoubleRatchetKit
import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

/// Forwards every host callback to the shared test `SessionDelegate`, so a test
/// policy only states the persist and sibling-sync decisions it is about.
fileprivate protocol ForwardingHostPolicy: MessagingPolicy, RecoveryObserver {
    var base: SessionDelegate { get }
}

fileprivate extension ForwardingHostPolicy {
    func synchronizeCommunication(recipient: MessageRecipient, sharedIdentifier: String, metadata: Data) async throws {
        try await base.synchronizeCommunication(recipient: recipient, sharedIdentifier: sharedIdentifier, metadata: metadata)
    }
    func requestFriendshipStateChange(
        recipient: MessageRecipient,
        blockData: Data?,
        metadata: Data,
        currentState: FriendshipMetadata.State
    ) async throws {
        try await base.requestFriendshipStateChange(
            recipient: recipient,
            blockData: blockData,
            metadata: metadata,
            currentState: currentState)
    }
    func deliveryStateChanged(recipient: MessageRecipient, metadata: Data) async throws {
        try await base.deliveryStateChanged(recipient: recipient, metadata: metadata)
    }
    func createdContact(recipient: MessageRecipient) async throws {
        try await base.createdContact(recipient: recipient)
    }
    func requestMetadata(recipient: MessageRecipient) async throws {
        try await base.requestMetadata(recipient: recipient)
    }
    func editMessage(recipient: MessageRecipient, metadata: Data) async throws {
        try await base.editMessage(recipient: recipient, metadata: metadata)
    }
    func shouldPersist(transportInfo: Data?) -> Bool {
        base.shouldPersist(transportInfo: transportInfo)
    }
    func shouldReplayNonPersistentOutbound(transportInfo: Data?) -> Bool {
        base.shouldReplayNonPersistentOutbound(transportInfo: transportInfo)
    }
    func isInboundRecoveryPlaceholder(transportInfo: Data?) -> Bool {
        base.isInboundRecoveryPlaceholder(transportInfo: transportInfo)
    }
    func retrieveUserInfo(_ transportInfo: Data?) async -> (secretName: String, deviceId: String)? {
        await base.retrieveUserInfo(transportInfo)
    }
    func updateCryptoMessageMetadata(_ message: CryptoMessage, sharedMessageId: String) -> CryptoMessage {
        base.updateCryptoMessageMetadata(message, sharedMessageId: sharedMessageId)
    }
    func updateEncryptableMessageMetadata(
        _ message: EncryptedMessage,
        transportInfo: Data?,
        identity: SessionIdentity,
        recipient: MessageRecipient
    ) async -> EncryptedMessage {
        await base.updateEncryptableMessageMetadata(
            message,
            transportInfo: transportInfo,
            identity: identity,
            recipient: recipient)
    }
    func shouldFinishCommunicationSynchronization(_ transportInfo: Data?) -> Bool {
        base.shouldFinishCommunicationSynchronization(transportInfo)
    }
    func processMessage(_ message: CryptoMessage, senderSecretName: String, senderDeviceId: UUID) async -> Bool {
        await base.processMessage(message, senderSecretName: senderSecretName, senderDeviceId: senderDeviceId)
    }
    func shouldSendAutomaticDeliveryReceipts() async -> Bool {
        await base.shouldSendAutomaticDeliveryReceipts()
    }
    func inboundRecoveryDeferred(
        senderSecretName: String,
        senderDeviceId: UUID,
        failedSharedMessageId: String,
        failureClass: String
    ) async {
        await base.inboundRecoveryDeferred(
            senderSecretName: senderSecretName,
            senderDeviceId: senderDeviceId,
            failedSharedMessageId: failedSharedMessageId,
            failureClass: failureClass)
    }
    func inboundMessagePendingRecovery(senderSecretName: String, senderDeviceId: UUID, sharedMessageId: String) async {
        await base.inboundMessagePendingRecovery(
            senderSecretName: senderSecretName,
            senderDeviceId: senderDeviceId,
            sharedMessageId: sharedMessageId)
    }
    func inboundCiphertextAccepted(sharedMessageId: String) async {
        await base.inboundCiphertextAccepted(sharedMessageId: sharedMessageId)
    }
    func inboundContentUnrecoverable(senderSecretName: String, senderDeviceId: UUID, sharedMessageId: String) async {
        await base.inboundContentUnrecoverable(
            senderSecretName: senderSecretName,
            senderDeviceId: senderDeviceId,
            sharedMessageId: sharedMessageId)
    }
    func outboundMessageUnrecoverable(sharedMessageId: String, reason: String) async {
        await base.outboundMessageUnrecoverable(sharedMessageId: sharedMessageId, reason: reason)
    }
    func reestablishmentEpisodeDidEnd(senderSecretName: String, senderDeviceId: UUID) async {
        await base.reestablishmentEpisodeDidEnd(senderSecretName: senderSecretName, senderDeviceId: senderDeviceId)
    }
    func linkedDeviceReportedPotentialCompromise(deviceId: UUID, intentId: UUID?) async {
        await base.linkedDeviceReportedPotentialCompromise(deviceId: deviceId, intentId: intentId)
    }
    func peerAccountIdentityChanged(secretName: String, deviceId: UUID, failedSharedMessageId: String?) async {
        await base.peerAccountIdentityChanged(
            secretName: secretName,
            deviceId: deviceId,
            failedSharedMessageId: failedSharedMessageId)
    }
    func shouldSuppressInboundRecoveryFromSender(_ senderSecretName: String) async -> Bool {
        await base.shouldSuppressInboundRecoveryFromSender(senderSecretName)
    }
    func preferredOnlinePeerDeviceId(for secretName: String) async -> UUID? {
        await base.preferredOnlinePeerDeviceId(for: secretName)
    }
}

/// A host that persists nothing and leaves sibling sync at the SDK default.
fileprivate struct NonPersistingPolicy: ForwardingHostPolicy {
    let base: SessionDelegate
    func shouldPersist(transportInfo _: Data?) -> Bool { false }
}

/// A host that persists nothing but syncs every send to linked devices,
/// the way nudge-kit treats edits, reactions and revokes.
fileprivate struct SiblingSyncingPolicy: ForwardingHostPolicy {
    let base: SessionDelegate
    func shouldPersist(transportInfo _: Data?) -> Bool { false }
    func shouldSyncToSiblings(transportInfo _: Data?) -> Bool { true }
}

extension EndToEndTests {
    /// Alice has a linked child device; Alice and Bob are friends.
    private func setUpAliceWithLinkedChild() async throws -> (
        aliceTransport: _MockTransportDelegate,
        aliceDelegate: SessionDelegate,
        alice: String,
        bob: String,
        aliceChildDeviceId: UUID,
        bobMasterDeviceId: UUID
    ) {
        let aliceStore = createSenderStore()
        let aliceChildStore = createSenderChildStore1()
        let bobStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let aliceChildTransport = _MockTransportDelegate(session: _senderChildSession1, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceDelegate = SessionDelegate(session: _senderSession)
        let bobDelegate = SessionDelegate(session: _recipientSession)

        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: aliceDelegate)
        try await createRecipientSession(
            store: bobStore,
            transport: bobTransport,
            sessionDelegate: bobDelegate)
        try await linkSenderChildSession1(
            store: aliceChildStore,
            transport: aliceChildTransport,
            useProvidedTransport: true)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: aliceDelegate,
            bobSession: _recipientSession,
            rsd: bobDelegate)

        // Alice's master learns about her child, as nudge-kit does before sibling fan-out.
        _ = try await _senderSession.refreshIdentities(secretName: sMockUserData.ssn, forceRefresh: true)

        let aliceChildDeviceId = try #require(await _senderChildSession1.sessionContext?.sessionUser.deviceId)
        let bobMasterDeviceId = try #require(await _recipientSession.sessionContext?.sessionUser.deviceId)
        return (aliceTransport, aliceDelegate, sMockUserData.ssn, rMockUserData.rsn, aliceChildDeviceId, bobMasterDeviceId)
    }

    /// Sends one packet to Bob from Alice's master and returns every envelope it produced.
    private func sendToBobAndCollectEnvelopes(
        aliceTransport: _MockTransportDelegate,
        bob: String
    ) async throws -> [ReceivedMessage] {
        let log = SentEnvelopeLog()
        aliceTransport.duringSendMessage = { received in await log.record(received) }
        let sharedId = "sibling-sync-\(UUID().uuidString)"
        try await _senderSession.send(
            recipient: .nickname(bob),
            text: "reaction",
            transportInfo: Data("reaction-control".utf8),
            sharedIdOverride: sharedId)
        await _senderSession.waitForOutboundJobDrain()
        aliceTransport.duringSendMessage = nil
        return await log.sent.filter { $0.logicalMessageId == sharedId }
    }

    @Test("a persisted message reaches the sender's linked device")
    func persistedMessageReachesSenderLinkedDevice() async throws {
        defer { Task { await shutdownSessions() } }
        let setUp = try await setUpAliceWithLinkedChild()

        let sent = try await sendToBobAndCollectEnvelopes(aliceTransport: setUp.aliceTransport, bob: setUp.bob)
        #expect(sent.contains { $0.recipient == setUp.bob && $0.recipientDeviceId == setUp.bobMasterDeviceId })
        #expect(sent.contains { $0.recipient == setUp.alice && $0.recipientDeviceId == setUp.aliceChildDeviceId })
    }

    @Test("a non-persisted control stays off linked devices by default")
    func nonPersistedControlSkipsLinkedDeviceByDefault() async throws {
        defer { Task { await shutdownSessions() } }
        let setUp = try await setUpAliceWithLinkedChild()
        await _senderSession.setPQSSessionDelegate(conformer: NonPersistingPolicy(base: setUp.aliceDelegate))

        let sent = try await sendToBobAndCollectEnvelopes(aliceTransport: setUp.aliceTransport, bob: setUp.bob)
        #expect(sent.contains { $0.recipient == setUp.bob && $0.recipientDeviceId == setUp.bobMasterDeviceId })
        #expect(!sent.contains { $0.recipient == setUp.alice })
    }

    @Test("a non-persisted control the host syncs reaches linked devices")
    func nonPersistedControlHostSyncsReachesLinkedDevice() async throws {
        defer { Task { await shutdownSessions() } }
        let setUp = try await setUpAliceWithLinkedChild()
        await _senderSession.setPQSSessionDelegate(conformer: SiblingSyncingPolicy(base: setUp.aliceDelegate))

        let sent = try await sendToBobAndCollectEnvelopes(aliceTransport: setUp.aliceTransport, bob: setUp.bob)
        #expect(sent.contains { $0.recipient == setUp.bob && $0.recipientDeviceId == setUp.bobMasterDeviceId })
        #expect(
            sent.contains { $0.recipient == setUp.alice && $0.recipientDeviceId == setUp.aliceChildDeviceId },
            "edits and reactions must reach the sender's other devices")
    }
}

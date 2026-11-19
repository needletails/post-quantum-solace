//
//  ReceiptDuringRowWriteTests.swift
//  post-quantum-solace
//
//  A peer's read receipt must survive a server accept, a failure or a retry for the same
//  message that is handled while the host is still applying the receipt. Each of them reads
//  the message's stored row, changes the delivery state and writes the row back. When two of
//  them overlap, both read the old state and the later write replaces the earlier one: the
//  accept writes "waiting for delivery" over "read".
//
//  Real pieces as in OutboundFailureOverReceiptTests, and the receipt travels the real way:
//  Bob's session sends it, Alice's inbound job decrypts it and hands it to her host's
//  `processMessage`. The accept, the failure and the retry go through the calls nudge-kit
//  makes. Doubles: the server (holds every copy of the test message), the host (does with a
//  receipt what nudge-kit's `applyDeliveryStateChange` does: fetch the row from its store,
//  set the state, save, tell the receiver), and the store, which waits a simulated latency
//  on every message fetch and update, as a database call takes time. Nothing orders the two
//  writes: the second one is started a few milliseconds after the host began the first.
//

import BinaryCodable
import DoubleRatchetKit
import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

/// What the host saw of the receipt.
actor ReceiptProgress {
    private(set) var applied = false
    func markApplied() { applied = true }
}

/// A host that applies a peer's delivery receipt inside `processMessage`, as nudge-kit does,
/// and leaves everything else to the rig's delegate.
struct ReceiptApplyingHost: MessagingPolicy, RecoveryObserver {
    static let receiptTransportInfo = Data("delivery-receipt".utf8)

    let session: PQSSession
    let store: MockIdentityStore
    let base: SessionDelegate
    let progress: ReceiptProgress
    let began: AsyncStream<Void>.Continuation

    func processMessage(_ message: CryptoMessage, senderSecretName: String, senderDeviceId: UUID) async -> Bool {
        guard message.transportInfo == Self.receiptTransportInfo,
              let receipt = try? BinaryDecoder().decode(DeliveryStateMetadata.self, from: message.metadata)
        else {
            return await base.processMessage(message, senderSecretName: senderSecretName, senderDeviceId: senderDeviceId)
        }
        began.yield()
        do {
            let key = try await session.getDatabaseSymmetricKey()
            guard let row = try await store.fetchMessageIfExists(sharedId: receipt.sharedId),
                  var props = await row.props(symmetricKey: key) else { return false }
            props.deliveryState = receipt.state
            let updated = try await row.updateMessage(with: props, symmetricKey: key)
            try await store.updateMessage(updated, symmetricKey: key)
            await session.receiverDelegate?.updatedMessage(updated)
            await progress.markApplied()
        } catch {}
        return false
    }

    func shouldPersist(transportInfo: Data?) -> Bool { transportInfo != Self.receiptTransportInfo }

    func synchronizeCommunication(recipient: MessageRecipient, sharedIdentifier: String, metadata: Data) async throws {
        try await base.synchronizeCommunication(recipient: recipient, sharedIdentifier: sharedIdentifier, metadata: metadata)
    }
    func requestFriendshipStateChange(recipient: MessageRecipient, blockData: Data?, metadata: Data, currentState: FriendshipMetadata.State) async throws {
        try await base.requestFriendshipStateChange(recipient: recipient, blockData: blockData, metadata: metadata, currentState: currentState)
    }
    func deliveryStateChanged(recipient _: MessageRecipient, metadata _: Data) async throws {}
    func createdContact(recipient _: MessageRecipient) async throws {}
    func requestMetadata(recipient _: MessageRecipient) async throws {}
    func editMessage(recipient _: MessageRecipient, metadata _: Data) async throws {}
    func shouldReplayNonPersistentOutbound(transportInfo _: Data?) -> Bool { false }
    func isInboundRecoveryPlaceholder(transportInfo: Data?) -> Bool { base.isInboundRecoveryPlaceholder(transportInfo: transportInfo) }
    func retrieveUserInfo(_: Data?) async -> (secretName: String, deviceId: String)? { nil }
    func updateCryptoMessageMetadata(_ message: CryptoMessage, sharedMessageId _: String) -> CryptoMessage { message }
    func updateEncryptableMessageMetadata(_ message: EncryptedMessage, transportInfo _: Data?, identity _: SessionIdentity, recipient _: MessageRecipient) async -> EncryptedMessage { message }
    func shouldFinishCommunicationSynchronization(_: Data?) -> Bool { false }
    func shouldSendAutomaticDeliveryReceipts() async -> Bool { true }

    func inboundRecoveryDeferred(senderSecretName _: String, senderDeviceId _: UUID, failedSharedMessageId _: String, failureClass _: String) async {}
    func inboundMessagePendingRecovery(senderSecretName _: String, senderDeviceId _: UUID, sharedMessageId _: String) async {}
    func inboundCiphertextAccepted(sharedMessageId _: String) async {}
    func inboundContentUnrecoverable(senderSecretName _: String, senderDeviceId _: UUID, sharedMessageId _: String) async {}
    func outboundMessageUnrecoverable(sharedMessageId _: String, reason _: String) async {}
    func reestablishmentEpisodeDidEnd(senderSecretName _: String, senderDeviceId _: UUID) async {}
    func linkedDeviceReportedPotentialCompromise(deviceId _: UUID, intentId _: UUID?) async {}
    func peerAccountIdentityChanged(secretName _: String, deviceId _: UUID, failedSharedMessageId _: String?) async {}
    func shouldSuppressInboundRecoveryFromSender(_: String) async -> Bool { false }
    func preferredOnlinePeerDeviceId(for _: String) async -> UUID? { nil }
}

extension EndToEndTests {
    /// Simulated latency of each message fetch and update in Alice's store.
    static let receiptRaceStoreLatency: Duration = .milliseconds(20)
    /// How long after the host began applying the receipt the second write is started.
    static let receiptRaceSecondWriteDelay: Duration = .milliseconds(5)

    /// Bob sends a read receipt for the rig's message. Returns when Alice's inbound job has
    /// decrypted it and her host has begun to apply it; her store is slow from here on.
    func bobSendsReadReceipt(_ rig: AcceptRig) async throws -> ReceiptProgress {
        let alice = rig.pair.alice
        let progress = ReceiptProgress()
        let (began, beganContinuation) = AsyncStream<Void>.makeStream()
        await alice.setPQSSessionDelegate(conformer: ReceiptApplyingHost(
            session: alice, store: rig.pair.aliceStore, base: SessionDelegate(session: alice),
            progress: progress, began: beganContinuation))
        await rig.pair.aliceStore.setSimulatedMessageLatency(Self.receiptRaceStoreLatency)

        let receipt = try BinaryEncoder().encode(DeliveryStateMetadata(state: .read, sharedId: rig.sharedId))
        try await rig.pair.bob.send(
            recipient: .nickname("alice"),
            transportInfo: ReceiptApplyingHost.receiptTransportInfo,
            metadata: receipt,
            shouldPersistOverride: false)

        let giveUp = Task {
            try? await Task.sleep(for: .seconds(30))
            beganContinuation.finish()
        }
        var didBegin = false
        for await _ in began {
            didBegin = true
            break
        }
        giveUp.cancel()
        try #require(didBegin, "setup: Alice's job handed Bob's receipt to her host")
        return progress
    }

    /// Waits for the receipt's job to finish and reads the row the host shows.
    func stateAfterReceiptJob(_ rig: AcceptRig, _ progress: ReceiptProgress) async throws -> DeliveryState? {
        let applied = await pollUntil(timeout: 30) { await progress.applied }
        try #require(applied, "setup: Alice's host applied the receipt")
        await jobLoopIdle(rig.pair.alice)
        await rig.pair.aliceStore.setSimulatedMessageLatency(nil)
        return try await rowState(rig)
    }

    @Test("A read receipt survives a server accept handled while the host applies the receipt")
    func readReceiptSurvivesAnAcceptDuringItsWrite() async throws {
        let rig = try await startAcceptRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await deliverToBobMaster(rig)
        let progress = try await bobSendsReadReceipt(rig)

        try await Task.sleep(for: Self.receiptRaceSecondWriteDelay)
        try #require(await progress.applied == false, "setup: the accept starts while the receipt is being applied")
        await alice.confirmServerAcceptedEnvelope(pending)
        try #require(await alice.isAwaitingServerAccept(pending) == false, "setup: the accept was consumed")

        let observed = try await stateAfterReceiptJob(rig, progress)
        #expect(observed == .read, "a read message must not be written back to waiting for delivery: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    @Test("Control: a read receipt survives a server accept handled after the receipt's job")
    func readReceiptSurvivesAnAcceptAfterItsJob() async throws {
        let rig = try await startAcceptRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await deliverToBobMaster(rig)
        let progress = try await bobSendsReadReceipt(rig)

        let applied = try await stateAfterReceiptJob(rig, progress)
        try #require(applied == .read, "setup: the receipt was applied")
        await rig.pair.aliceStore.setSimulatedMessageLatency(Self.receiptRaceStoreLatency)
        await alice.confirmServerAcceptedEnvelope(pending)
        try #require(await alice.isAwaitingServerAccept(pending) == false, "setup: the accept was consumed")
        await rig.pair.aliceStore.setSimulatedMessageLatency(nil)

        let observed = try await rowState(rig)
        #expect(observed == .read, "observed \(String(describing: observed))")
        await finishRig(rig)
    }

    /// The call nudge-kit makes when the server rejects one sealed copy of the message.
    @Test("A read receipt survives a failure handled while the host applies the receipt")
    func readReceiptSurvivesAFailureDuringItsWrite() async throws {
        let rig = try await startAcceptRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await deliverToBobMaster(rig)
        let progress = try await bobSendsReadReceipt(rig)

        try await Task.sleep(for: Self.receiptRaceSecondWriteDelay)
        try #require(await progress.applied == false, "setup: the failure starts while the receipt is being applied")
        await alice.failUnackedServerAcceptEnvelope(pending, reason: "sealedRejected")

        let observed = try await stateAfterReceiptJob(rig, progress)
        #expect(observed == .read, "a read message must not be written back to failed: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    /// The message failed, and Retry is tapped while a peer's read receipt is being applied.
    @Test("A read receipt survives a retry handled while the host applies the receipt")
    func readReceiptSurvivesARetryDuringItsWrite() async throws {
        let rig = try await startAcceptRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await deliverToBobMaster(rig)
        try await exhaustAcceptBudget(rig, for: [pending])
        let failed = try await rowState(rig)
        try #require(failed == .failed("serverAcceptExhausted"), "setup: the message failed first")
        let progress = try await bobSendsReadReceipt(rig)

        try await Task.sleep(for: Self.receiptRaceSecondWriteDelay)
        try #require(await progress.applied == false, "setup: the retry starts while the receipt is being applied")
        await alice.retryFailedServerAcceptOutbound(localMessageId: rig.localId)

        let observed = try await stateAfterReceiptJob(rig, progress)
        #expect(observed == .read, "a read message must not be written back to sending: observed \(String(describing: observed))")
        await finishRig(rig)
    }
}

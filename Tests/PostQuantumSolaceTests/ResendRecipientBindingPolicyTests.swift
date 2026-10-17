import Foundation
import Testing
@testable import PQSSession
import SessionModels

@Suite("Resend recipient binding policy")
struct ResendRecipientBindingPolicyTests {
    private func record(recipient: String, device: UUID) -> OutboundDeviceSendRecord {
        OutboundDeviceSendRecord(
            envelopeMessageId: UUID().uuidString,
            sharedId: "shared",
            recipientSecretName: recipient,
            recipientDeviceId: device,
            sessionIdentityId: UUID())
    }

    @Test("the addressed device may replay")
    func addressedDeviceMayReplay() {
        let device = UUID()
        #expect(OrphanResendOwnershipPolicy.requesterMayReplay(
            record: record(recipient: "bob", device: device),
            requesterSecretName: "bob",
            requestingDeviceId: device))
    }

    @Test("a different device of the same account may not replay")
    func siblingDeviceMayNotReplay() {
        #expect(!OrphanResendOwnershipPolicy.requesterMayReplay(
            record: record(recipient: "bob", device: UUID()),
            requesterSecretName: "bob",
            requestingDeviceId: UUID()))
    }

    @Test("another account may not replay even with the right device id")
    func otherAccountMayNotReplay() {
        let device = UUID()
        #expect(!OrphanResendOwnershipPolicy.requesterMayReplay(
            record: record(recipient: "alice", device: device),
            requesterSecretName: "bob",
            requestingDeviceId: device))
    }

    @Test("no record means no replay")
    func missingRecordMayNotReplay() {
        #expect(!OrphanResendOwnershipPolicy.requesterMayReplay(
            record: nil,
            requesterSecretName: "bob",
            requestingDeviceId: UUID()))
    }

    @Test("secret names compare canonically")
    func secretNamesCompareCanonically() {
        let device = UUID()
        #expect(OrphanResendOwnershipPolicy.requesterMayReplay(
            record: record(recipient: "Bob", device: device),
            requesterSecretName: "bob",
            requestingDeviceId: device))
    }
}

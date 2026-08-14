import Foundation
import SessionModels

/// Shared in-memory outbound/accepted-envelope ledgers for test stores.
final class InMemoryRecoveryLedger: @unchecked Sendable {
    private var outboundRecords: [OutboundDeviceSendRecord] = []
    private var acceptedEnvelopes: [AcceptedEnvelopeRecord] = []
    private let lock = NSLock()

    func upsertOutboundDeviceSendRecord(_ record: OutboundDeviceSendRecord) {
        lock.lock()
        defer { lock.unlock() }
        outboundRecords.removeAll {
            $0.sharedId == record.sharedId && $0.recipientDeviceId == record.recipientDeviceId
        }
        outboundRecords.append(record)
    }

    func fetchOutboundDeviceSendRecord(
        sharedId: String,
        recipientDeviceId: UUID
    ) -> OutboundDeviceSendRecord? {
        lock.lock()
        defer { lock.unlock() }
        return outboundRecords.first {
            $0.sharedId == sharedId && $0.recipientDeviceId == recipientDeviceId
        }
    }

    func fetchOutboundDeviceSendRecord(envelopeMessageId: String) -> OutboundDeviceSendRecord? {
        lock.lock()
        defer { lock.unlock() }
        return outboundRecords.first { $0.envelopeMessageId == envelopeMessageId }
    }

    func deleteOutboundDeviceSendRecords(sharedId: String) {
        lock.lock()
        defer { lock.unlock() }
        outboundRecords.removeAll { $0.sharedId == sharedId }
    }

    func upsertAcceptedEnvelope(_ record: AcceptedEnvelopeRecord) {
        lock.lock()
        defer { lock.unlock() }
        acceptedEnvelopes.removeAll { $0.storageKey == record.storageKey }
        acceptedEnvelopes.append(record)
    }

    func fetchAcceptedEnvelope(
        senderSecretName: String,
        senderDeviceId: UUID,
        envelopeMessageId: String
    ) -> AcceptedEnvelopeRecord? {
        lock.lock()
        defer { lock.unlock() }
        return acceptedEnvelopes.first {
            $0.senderSecretName == senderSecretName
                && $0.senderDeviceId == senderDeviceId
                && $0.envelopeMessageId == envelopeMessageId
        }
    }

    func pruneAcceptedEnvelopes(olderThan date: Date) -> Int {
        lock.lock()
        defer { lock.unlock() }
        let before = acceptedEnvelopes.count
        acceptedEnvelopes.removeAll { $0.acceptedAt < date }
        return before - acceptedEnvelopes.count
    }
}

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
import Testing
@testable import SessionModels

@Suite("Deferred OTK consumption")
struct DeferredOTKConsumptionTests {
    private let crypto = NeedleTailCrypto()

    @Test("pending record is idempotent and clears to nil")
    func pendingRecordIsIdempotentAndClearsToNil() throws {
        var keys = try makeDeviceKeys()
        let lane = UUID()
        let otkId = UUID()
        let entry = PendingOneTimeKeyConsumption(
            sessionIdentityId: lane,
            oneTimeKeyId: otkId,
            mlKEMOneTimeKeyId: nil)

        keys.recordPendingOneTimeKeyConsumption(entry)
        keys.recordPendingOneTimeKeyConsumption(entry)
        #expect(keys.pendingOneTimeKeyConsumptions?.count == 1)

        let removed = keys.removePendingOneTimeKeyConsumptions(for: lane)
        #expect(removed == [entry])
        #expect(keys.pendingOneTimeKeyConsumptions == nil)
    }

    @Test("sibling lane keeps a shared OTK pending after one lane confirms")
    func siblingLaneKeepsSharedOTKPending() throws {
        var keys = try makeDeviceKeys()
        let otkId = UUID()
        let firstLane = UUID()
        let secondLane = UUID()
        keys.recordPendingOneTimeKeyConsumption(
            PendingOneTimeKeyConsumption(
                sessionIdentityId: firstLane,
                oneTimeKeyId: otkId,
                mlKEMOneTimeKeyId: nil))
        keys.recordPendingOneTimeKeyConsumption(
            PendingOneTimeKeyConsumption(
                sessionIdentityId: secondLane,
                oneTimeKeyId: otkId,
                mlKEMOneTimeKeyId: nil))

        _ = keys.removePendingOneTimeKeyConsumptions(for: firstLane)
        #expect(keys.isOneTimeKeyStillPending(otkId))
        #expect(keys.pendingOneTimeKeyConsumptions?.count == 1)

        _ = keys.removePendingOneTimeKeyConsumptions(for: secondLane)
        #expect(!keys.isOneTimeKeyStillPending(otkId))
        #expect(keys.pendingOneTimeKeyConsumptions == nil)
    }

    @Test("legacy DeviceKeys blobs decode without pending consumptions")
    func legacyDeviceKeysDecodeWithoutPendingField() throws {
        var keys = try makeDeviceKeys()
        #expect(keys.pendingOneTimeKeyConsumptions == nil)
        let encoded = try BinaryEncoder().encode(keys)
        let decoded = try BinaryDecoder().decode(DeviceKeys.self, from: encoded)
        #expect(decoded.pendingOneTimeKeyConsumptions == nil)
        #expect(decoded.deviceId == keys.deviceId)
    }

    private func makeDeviceKeys() throws -> DeviceKeys {
        let signing = crypto.generateCurve25519SigningPrivateKey()
        let longTerm = crypto.generateCurve25519PrivateKey()
        let otk = crypto.generateCurve25519PrivateKey()
        let mlkem = try crypto.generateMLKem1024PrivateKey()
        return DeviceKeys(
            deviceId: UUID(),
            signingPrivateKey: signing.rawRepresentation,
            longTermPrivateKey: longTerm.rawRepresentation,
            oneTimePrivateKeys: [try X25519PrivateKey(id: UUID(), otk.rawRepresentation)],
            mlKEMOneTimePrivateKeys: [try MLKEMPrivateKey(id: UUID(), mlkem.encode())],
            finalMLKEMPrivateKey: try MLKEMPrivateKey(id: UUID(), mlkem.encode()))
    }
}

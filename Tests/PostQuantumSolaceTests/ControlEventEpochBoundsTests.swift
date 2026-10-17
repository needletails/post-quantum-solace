//
//  ControlEventEpochBoundsTests.swift
//  post-quantum-solace
//
//  Control-event epochs arrive from the wire. Arithmetic on them must never
//  trap, and a peer-chosen value must not be able to poison the local counter
//  so that the next local emission traps instead.
//

import BinaryCodable
import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

@Suite("Control event epoch bounds")
struct ControlEventEpochBoundsTests {
    @Test("decoded epoch is clamped to the wire maximum")
    func decodedEpochIsClamped() throws {
        let envelope = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: .max)
        let encoded = try BinaryEncoder().encode(envelope)
        let decoded = try BinaryDecoder().decode(SessionReestablishmentEnvelope.self, from: encoded)
        #expect(decoded.epoch <= SessionReestablishmentEnvelope.maximumWireEpoch)
        #expect(decoded.epoch == SessionReestablishmentEnvelope.maximumWireEpoch)
    }

    @Test("sane epochs decode unchanged")
    func saneEpochDecodesUnchanged() throws {
        let envelope = SessionReestablishmentEnvelope(kind: .linkedDeviceRepair, epoch: 42)
        let encoded = try BinaryEncoder().encode(envelope)
        let decoded = try BinaryDecoder().decode(SessionReestablishmentEnvelope.self, from: encoded)
        #expect(decoded.epoch == 42)
    }

    @Test("response epoch for a max request epoch saturates instead of trapping")
    func responseEpochSaturates() {
        #expect(PQSSession.nextResponseEpoch(currentCounter: 0, requestEpoch: .max) == .max)
        #expect(PQSSession.nextResponseEpoch(currentCounter: .max, requestEpoch: 1) == .max)
        #expect(PQSSession.nextResponseEpoch(currentCounter: nil, requestEpoch: .max - 1) == .max)
    }

    @Test("response epoch stays monotonic for sane values")
    func responseEpochMonotonic() {
        #expect(PQSSession.nextResponseEpoch(currentCounter: 5, requestEpoch: 3) == 6)
        #expect(PQSSession.nextResponseEpoch(currentCounter: 2, requestEpoch: 9) == 10)
        #expect(PQSSession.nextResponseEpoch(currentCounter: nil, requestEpoch: 0) == 1)
        #expect(PQSSession.nextEmissionEpoch(currentCounter: nil) == 1)
        #expect(PQSSession.nextEmissionEpoch(currentCounter: 7) == 8)
        #expect(PQSSession.nextEmissionEpoch(currentCounter: .max) == .max)
    }

    @Test("a poisoned sender counter does not trap the next local emission")
    func poisonedSenderCounterDoesNotTrap() async {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        await session.seedSenderControlEpochCounter(.max, for: .peerRefresh)

        let first = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .personal)
        #expect(first?.epoch == .max)

        // Same episode, forced re-emit: the in-episode increment path.
        let second = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .personal,
            forceReemit: true)
        #expect(second?.epoch == .max)
    }
}

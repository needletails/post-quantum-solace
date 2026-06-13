//
//  TransportEventCodingTests.swift
//  post-quantum-solace
//
//  Created by Cursor on 2026-05-22.
//

import BinaryCodable
import Foundation
import SessionModels
import Testing

@Suite("Transport event coding")
struct TransportEventCodingTests {

    @Test("requestMessageResend preserves batched failed ids")
    func requestMessageResendPreservesBatchedFailedIds() throws {
        let deviceId = UUID()
        let request = FailedMessageResendRequest(
            failedSharedMessageIds: ["first", "second", "first", ""],
            requestingDeviceId: deviceId)
        let encoded = try BinaryEncoder().encode(TransportEvent.requestMessageResend(request))
        let decoded = try BinaryDecoder().decode(TransportEvent.self, from: encoded)

        guard case .requestMessageResend(let decodedRequest) = decoded else {
            Issue.record("Expected requestMessageResend transport event")
            return
        }

        #expect(decodedRequest.failedSharedMessageId == "first")
        #expect(decodedRequest.failedSharedMessageIds == ["first", "second"])
        #expect(decodedRequest.requestingDeviceId == deviceId)
    }

    @Test("requestMessageResend caps oversized batches")
    func requestMessageResendCapsOversizedBatches() throws {
        let deviceId = UUID()
        let oversized = (0..<500).map { "id\($0)" }
        let request = FailedMessageResendRequest(
            failedSharedMessageIds: oversized,
            requestingDeviceId: deviceId)

        #expect(
            request.failedSharedMessageIds.count == FailedMessageResendRequest.maxBatchedIds,
            "Oversized resend batches must be capped to bound inbound replay work")
        #expect(request.failedSharedMessageId == "id0")

        // The cap must survive the wire round-trip so a hostile peer cannot
        // amplify replay work on the receiver.
        let encoded = try BinaryEncoder().encode(TransportEvent.requestMessageResend(request))
        let decoded = try BinaryDecoder().decode(TransportEvent.self, from: encoded)
        guard case .requestMessageResend(let decodedRequest) = decoded else {
            Issue.record("Expected requestMessageResend transport event")
            return
        }
        #expect(decodedRequest.failedSharedMessageIds.count <= FailedMessageResendRequest.maxBatchedIds)
    }

    @Test("requestMessageResend keeps legacy single-id payload shape")
    func requestMessageResendKeepsLegacySingleIdPayloadShape() throws {
        let deviceId = UUID()
        let request = FailedMessageResendRequest(
            failedSharedMessageId: "single",
            requestingDeviceId: deviceId)
        let encoded = try BinaryEncoder().encode(TransportEvent.requestMessageResend(request))
        let decoded = try BinaryDecoder().decode(TransportEvent.self, from: encoded)

        guard case .requestMessageResend(let decodedRequest) = decoded else {
            Issue.record("Expected requestMessageResend transport event")
            return
        }

        #expect(decodedRequest.failedSharedMessageId == "single")
        #expect(decodedRequest.failedSharedMessageIds == ["single"])
        #expect(decodedRequest.requestingDeviceId == deviceId)
    }
}

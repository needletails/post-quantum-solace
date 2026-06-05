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

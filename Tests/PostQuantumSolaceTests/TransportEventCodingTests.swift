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

    /// Pinned v1 `TransportEvent.requestMessageResend` bytes from
    /// `GoldenPersistedDataTests.transportRequestMessageResendGolden`.
    private static let retiredRequestMessageResendGolden =
        "Ak5CVE4cAAAAU2Vzc2lvbk1vZGVscy5UcmFuc3BvcnRFdmVudAEAAAABAAAAZWIAAAABAAAAAgAAAF8wVAAAAAEDAAAAAQAAAGEKAAAAAQUAAABlbnYtMQEAAABiEQAAAAEAAAAAAABAAIAAAAAAAAABAQAAAGMZAAAAAQIAAAABBQAAAGVudi0xAQUAAABlbnYtMg=="

    @Test("ResendRequest preserves batched failed ids")
    func resendRequestPreservesBatchedFailedIds() throws {
        let deviceId = UUID()
        let request = ResendRequest(
            failedSharedMessageIds: ["first", "second", "first", ""],
            requestingDeviceId: deviceId)
        let encoded = try BinaryEncoder().encode(request)
        let decoded = try BinaryDecoder().decode(ResendRequest.self, from: encoded)

        #expect(decoded.failedSharedMessageId == "first")
        #expect(decoded.failedSharedMessageIds == ["first", "second"])
        #expect(decoded.requestingDeviceId == deviceId)
    }

    @Test("ResendRequest caps oversized batches")
    func resendRequestCapsOversizedBatches() throws {
        let deviceId = UUID()
        let oversized = (0..<500).map { "id\($0)" }
        let request = ResendRequest(
            failedSharedMessageIds: oversized,
            requestingDeviceId: deviceId)

        #expect(
            request.failedSharedMessageIds.count == ResendRequest.maxBatchedIds,
            "Oversized resend batches must be capped to bound inbound replay work")
        #expect(request.failedSharedMessageId == "id0")

        let encoded = try BinaryEncoder().encode(request)
        let decoded = try BinaryDecoder().decode(ResendRequest.self, from: encoded)
        #expect(decoded.failedSharedMessageIds.count <= ResendRequest.maxBatchedIds)
    }

    @Test("ResendRequest keeps legacy single-id payload shape")
    func resendRequestKeepsLegacySingleIdPayloadShape() throws {
        let deviceId = UUID()
        let request = ResendRequest(
            failedSharedMessageId: "single",
            requestingDeviceId: deviceId)
        let encoded = try BinaryEncoder().encode(request)
        let decoded = try BinaryDecoder().decode(ResendRequest.self, from: encoded)

        #expect(decoded.failedSharedMessageId == "single")
        #expect(decoded.failedSharedMessageIds == ["single"])
        #expect(decoded.requestingDeviceId == deviceId)
    }

    @Test("retired requestMessageResend TransportEvent bytes are rejected")
    func retiredRequestMessageResendTransportEventIsRejected() throws {
        let data = try #require(Data(base64Encoded: Self.retiredRequestMessageResendGolden))
        #expect(TransportEvent.carriesRetiredEncryptedRetry(data))
        do {
            _ = try BinaryDecoder().decode(TransportEvent.self, from: data)
            Issue.record("retired requestMessageResend bytes must not decode as TransportEvent")
        } catch {
            #expect(TransportEvent.isRetiredEncryptedRetry(error))
        }
    }

    @Test("publishedOneTimeKeysReplenished encodes and decodes")
    func publishedOneTimeKeysReplenishedEncodesAndDecodes() throws {
        let encoded = try BinaryEncoder().encode(TransportEvent.publishedOneTimeKeysReplenished)
        let decoded = try BinaryDecoder().decode(TransportEvent.self, from: encoded)
        guard case .publishedOneTimeKeysReplenished = decoded else {
            Issue.record("Expected publishedOneTimeKeysReplenished transport event")
            return
        }
    }
}

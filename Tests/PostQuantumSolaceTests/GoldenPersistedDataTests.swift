//
//  GoldenPersistedDataTests.swift
//  post-quantum-solace
//
//  Phase 0 v1 fixtures. Pin BinaryCodable encodings of persisted / wire types
//  so later rename phases cannot silently change on-disk keys.
//
//  Dump: PQS_GOLDEN_DUMP=1 swift test --filter GoldenPersistedDataTests
//  Phase 2 may retire the two encrypted-retry TransportEvent fixtures
//  (requestMessageResend / messageResendUnavailable) by converting them to
//  reject tests. Everything else must stay byte-identical through Phases 3–6.
//

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
import SessionModels
import Testing

@Suite("Golden persisted-data fixtures (v1)")
struct GoldenPersistedDataTests {
    private static let id1 = UUID(uuidString: "00000000-0000-4000-8000-000000000001")!
    private static let id2 = UUID(uuidString: "00000000-0000-4000-8000-000000000002")!
    private static let epoch = Date(timeIntervalSince1970: 1_700_000_000)
    private static let dump = ProcessInfo.processInfo.environment["PQS_GOLDEN_DUMP"] == "1"

    // MARK: - Helpers

    private func assertGolden<T: Codable>(
        _ name: String,
        _ value: T,
        pinned: String
    ) throws {
        let encoded = try BinaryEncoder().encode(value)
        let b64 = encoded.base64EncodedString()
        if Self.dump || pinned.isEmpty {
            print("GOLDEN \(name)=\(b64)")
        }
        #expect(b64 == pinned, "\(name) encoding changed.\nNew: \(b64)")
        let decoded = try BinaryDecoder().decode(T.self, from: encoded)
        let reencoded = try BinaryEncoder().encode(decoded)
        #expect(
            reencoded == encoded,
            "\(name) decode+re-encode is not byte-identical")
    }

    private func assertGoldenSHA256<T: Codable>(
        _ name: String,
        _ value: T,
        pinnedHex: String
    ) throws {
        let encoded = try BinaryEncoder().encode(value)
        let hex = SHA256.hash(data: encoded).map { String(format: "%02x", $0) }.joined()
        if Self.dump || pinnedHex.isEmpty {
            print("GOLDEN_SHA256 \(name)=\(hex) bytes=\(encoded.count)")
        }
        #expect(hex == pinnedHex, "\(name) encoding digest changed.\nNew: \(hex)")
        let decoded = try BinaryDecoder().decode(T.self, from: encoded)
        let reencoded = try BinaryEncoder().encode(decoded)
        #expect(
            reencoded == encoded,
            "\(name) decode+re-encode is not byte-identical")
    }

    private func userConfiguration() -> UserConfiguration {
        UserConfiguration(
            signingPublicKey: Data(repeating: 0x11, count: 32),
            signedDevices: [],
            signedOneTimePublicKeys: [],
            signedMLKEMOneTimePublicKeys: [],
            signedDeviceKeyBundles: [])
    }

    private func channelInfo() -> ChannelInfo {
        ChannelInfo(
            name: "design",
            administrator: "alice",
            members: ["alice"],
            operators: [])
    }

    private func sessionIdentityProps() throws -> SessionIdentity.UnwrappedProps {
        SessionIdentity.UnwrappedProps(
            secretName: "alice",
            deviceId: Self.id1,
            sessionContextId: 1,
            longTermPublicKey: Data(repeating: 0x22, count: 32),
            signingPublicKey: Data(repeating: 0x33, count: 32),
            mlKEMPublicKey: try MLKEMPublicKey(id: Self.id2, Data(repeating: 0x44, count: 1568)),
            oneTimePublicKey: nil,
            deviceName: "alice-phone",
            serverTrusted: true,
            previousRekey: Self.epoch,
            isMasterDevice: true,
            verifiedIdentity: true,
            verificationCode: "ABCD")
    }

    private func communicationProps() -> BaseCommunication.UnwrappedProps {
        BaseCommunication.UnwrappedProps(
            sharedId: Self.id2,
            messageCount: 3,
            administrator: "alice",
            operators: ["alice"],
            members: ["alice"],
            metadata: Data([0x01, 0x02]),
            blockedMembers: [],
            communicationType: .nickname("bob"))
    }

    private func cryptoMessage() -> CryptoMessage {
        CryptoMessage(
            text: "hello",
            metadata: Data([0xAA]),
            recipient: .nickname("bob"),
            transportInfo: nil,
            sentDate: Self.epoch,
            destructionTime: nil,
            updatedDate: nil)
    }

    // MARK: - UserConfiguration / channel / ledger

    @Test("UserConfiguration v1 encoding is stable")
    func userConfigurationGolden() throws {
        try assertGolden(
            "UserConfiguration",
            userConfiguration(),
            pinned: "Ak5CVE4fAAAAU2Vzc2lvbk1vZGVscy5Vc2VyQ29uZmlndXJhdGlvbgUAAAABAAAAYSUAAAABIAAAABERERERERERERERERERERERERERERERERERERERERERAQAAAGIFAAAAAQAAAAABAAAAYwUAAAABAAAAAAEAAABkBQAAAAEAAAAAAQAAAGUFAAAAAQAAAAA=")
    }

    @Test("ChannelStoredMetadata v1 encoding is stable")
    func channelStoredMetadataGolden() throws {
        try assertGolden(
            "ChannelStoredMetadata",
            ChannelStoredMetadata(core: channelInfo(), overlay: nil),
            pinned: "Ak5CVE4jAAAAU2Vzc2lvbk1vZGVscy5DaGFubmVsU3RvcmVkTWV0YWRhdGECAAAABAAAAGNvcmVvAAAAAQQAAAAEAAAAbmFtZQsAAAABBgAAAGRlc2lnbg0AAABhZG1pbmlzdHJhdG9yCgAAAAEFAAAAYWxpY2UHAAAAbWVtYmVycw8AAAABAQAAAAEFAAAAYWxpY2UJAAAAb3BlcmF0b3JzBQAAAAEAAAAABwAAAG92ZXJsYXkBAAAAAA==")
    }

    @Test("OutboundDeviceSendRecord v1 encoding is stable")
    func outboundDeviceSendRecordGolden() throws {
        try assertGolden(
            "OutboundDeviceSendRecord",
            OutboundDeviceSendRecord(
                envelopeMessageId: "env-1",
                sharedId: "logical-1",
                recipientSecretName: "bob",
                recipientDeviceId: Self.id1,
                sessionIdentityId: Self.id2,
                resendAttempt: 0,
                createdAt: Self.epoch,
                supersededAt: nil),
            pinned: "Ak5CVE4mAAAAU2Vzc2lvbk1vZGVscy5PdXRib3VuZERldmljZVNlbmRSZWNvcmQIAAAAEQAAAGVudmVsb3BlTWVzc2FnZUlkCgAAAAEFAAAAZW52LTEIAAAAc2hhcmVkSWQOAAAAAQkAAABsb2dpY2FsLTETAAAAcmVjaXBpZW50U2VjcmV0TmFtZQgAAAABAwAAAGJvYhEAAAByZWNpcGllbnREZXZpY2VJZBEAAAABAAAAAAAAQACAAAAAAAAAAREAAABzZXNzaW9uSWRlbnRpdHlJZBEAAAABAAAAAAAAQACAAAAAAAAAAg0AAAByZXNlbmRBdHRlbXB0CQAAAAEAAAAAAAAAAAkAAABjcmVhdGVkQXQJAAAAAQAAAEAUgsVBDAAAAHN1cGVyc2VkZWRBdAEAAAAA")
    }

    // MARK: - Inner props (deterministic; encrypted wrappers use random nonces)

    @Test("ContactModel.UnwrappedProps v1 encoding is stable")
    func contactPropsGolden() throws {
        try assertGolden(
            "ContactModel.UnwrappedProps",
            ContactModel.UnwrappedProps(
                secretName: "bob",
                configuration: userConfiguration(),
                metadata: ["k": Data([0x01])]),
            pinned: "Ak5CVE4pAAAAU2Vzc2lvbk1vZGVscy5Db250YWN0TW9kZWwuVW53cmFwcGVkUHJvcHMDAAAAAQAAAGEIAAAAAQMAAABib2IBAAAAYmsAAAABBQAAAAEAAABhJQAAAAEgAAAAEREREREREREREREREREREREREREREREREREREREREREBAAAAYgUAAAABAAAAAAEAAABjBQAAAAEAAAAAAQAAAGQFAAAAAQAAAAABAAAAZQUAAAABAAAAAAEAAABjFAAAAAEBAAAAAQAAAGsGAAAAAQEAAAAB")
    }

    @Test("BaseCommunication.UnwrappedProps v1 encoding is stable")
    func communicationPropsGolden() throws {
        try assertGolden(
            "BaseCommunication.UnwrappedProps",
            communicationProps(),
            pinned: "Ak5CVE4uAAAAU2Vzc2lvbk1vZGVscy5CYXNlQ29tbXVuaWNhdGlvbi5VbndyYXBwZWRQcm9wcwgAAAABAAAAYREAAAABAAAAAAAAQACAAAAAAAAAAgEAAABiCQAAAAEDAAAAAAAAAAEAAABjCgAAAAEFAAAAYWxpY2UBAAAAZA8AAAABAQAAAAEFAAAAYWxpY2UBAAAAZQ8AAAABAQAAAAEFAAAAYWxpY2UBAAAAZgUAAAABAAAAAAEAAABnBwAAAAECAAAAAQIBAAAAaCsAAAABAQAAAAgAAABuaWNrbmFtZRYAAAABAAAAAgAAAF8wCAAAAAEDAAAAYm9i")
    }

    @Test("EncryptedMessage.UnwrappedProps v1 encoding is stable")
    func encryptedMessagePropsGolden() throws {
        let base = BaseCommunication(id: Self.id1, data: Data([0xBE, 0xEF]))
        try assertGolden(
            "EncryptedMessage.UnwrappedProps",
            EncryptedMessage.UnwrappedProps(
                id: Self.id2,
                base: base,
                sentDate: Self.epoch,
                receiveDate: nil,
                deliveryState: .sending,
                message: cryptoMessage(),
                senderSecretName: "alice",
                senderDeviceId: Self.id1),
            pinned: "Ak5CVE4tAAAAU2Vzc2lvbk1vZGVscy5FbmNyeXB0ZWRNZXNzYWdlLlVud3JhcHBlZFByb3BzCAAAAAEAAABhEQAAAAEAAAAAAABAAIAAAAAAAAACAQAAAGIwAAAAAQIAAAACAAAAaWQRAAAAAQAAAAAAAEAAgAAAAAAAAAEBAAAAYQcAAAABAgAAAL7vAQAAAGMJAAAAAQAAAEAUgsVBAQAAAGQBAAAAAAEAAABlGAAAAAEBAAAABwAAAHNlbmRpbmcEAAAAAAAAAAEAAABmgQAAAAEGAAAAAQAAAGEKAAAAAQUAAABoZWxsbwEAAABiBgAAAAEBAAAAqgEAAABjKwAAAAEBAAAACAAAAG5pY2tuYW1lFgAAAAEAAAACAAAAXzAIAAAAAQMAAABib2IBAAAAZAEAAAAAAQAAAGUJAAAAAQAAAEAUgsVBAQAAAGcBAAAAAAEAAABnCgAAAAEFAAAAYWxpY2UBAAAAaBEAAAABAAAAAAAAQACAAAAAAAAAAQ==")
    }

    @Test("JobModel.UnwrappedProps v1 encoding is stable")
    func jobPropsGolden() throws {
        let inbound = InboundTaskMessage(
            message: SignedRatchetMessage(outOfBandPlaceholder: ()),
            senderSecretName: "bob",
            senderDeviceId: Self.id1,
            sharedMessageId: "env-1",
            logicalSharedId: "logical-1")
        try assertGolden(
            "JobModel.UnwrappedProps",
            JobModel.UnwrappedProps(
                sequenceId: 7,
                task: EncryptableTask(
                    task: .streamMessage(inbound),
                    priority: .standard,
                    scheduledAt: Self.epoch),
                isBackgroundTask: false,
                delayedUntil: nil,
                scheduledAt: Self.epoch,
                attempts: 0),
            pinned: "Ak5CVE4lAAAAU2Vzc2lvbk1vZGVscy5Kb2JNb2RlbC5VbndyYXBwZWRQcm9wcwcAAAABAAAAYQkAAAABBwAAAAAAAAABAAAAYh4BAAABAwAAAAQAAAB0YXNr2AAAAAEBAAAADQAAAHN0cmVhbU1lc3NhZ2W+AAAAAQAAAAIAAABfMLAAAAABBQAAAAcAAABtZXNzYWdlDwAAAAEBAAAAAQAAAGEBAAAAABAAAABzZW5kZXJTZWNyZXROYW1lCAAAAAEDAAAAYm9iDgAAAHNlbmRlckRldmljZUlkEQAAAAEAAAAAAABAAIAAAAAAAAABDwAAAHNoYXJlZE1lc3NhZ2VJZAoAAAABBQAAAGVudi0xDwAAAGxvZ2ljYWxTaGFyZWRJZA4AAAABCQAAAGxvZ2ljYWwtMQgAAABwcmlvcml0eQkAAAABAQAAAAAAAAALAAAAc2NoZWR1bGVkQXQJAAAAAQAAAEAUgsVBAQAAAGMCAAAAAQABAAAAZAEAAAAAAQAAAGUJAAAAAQAAAEAUgsVBAQAAAGYJAAAAAQAAAAAAAAAAAQAAAGcBAAAAAA==")
    }

    @Test("SessionIdentity.UnwrappedProps v1 encoding is stable")
    func sessionIdentityPropsGolden() throws {
        try assertGoldenSHA256(
            "SessionIdentity.UnwrappedProps",
            try sessionIdentityProps(),
            pinnedHex: "48612def2ab8c426e0369d437dcdbcbac508b889b22cf3f3c24f8a690cf44acd")
    }

    // MARK: - Outer shells with fixed ciphertext (init(id:data:))

    @Test("ContactModel outer shell v1 encoding is stable")
    func contactModelShellGolden() throws {
        try assertGolden(
            "ContactModel.shell",
            ContactModel(id: Self.id1, data: Data([0xCA, 0xFE])),
            pinned: "Ak5CVE4aAAAAU2Vzc2lvbk1vZGVscy5Db250YWN0TW9kZWwCAAAAAQAAAGERAAAAAQAAAAAAAEAAgAAAAAAAAAEBAAAAYgcAAAABAgAAAMr+")
    }

    @Test("JobModel outer shell v1 encoding is stable")
    func jobModelShellGolden() throws {
        try assertGolden(
            "JobModel.shell",
            JobModel(id: Self.id1, data: Data([0xCA, 0xFE])),
            pinned: "Ak5CVE4WAAAAU2Vzc2lvbk1vZGVscy5Kb2JNb2RlbAIAAAABAAAAYREAAAABAAAAAAAAQACAAAAAAAAAAQEAAABiBwAAAAECAAAAyv4=")
    }

    @Test("BaseCommunication outer shell v1 encoding is stable")
    func communicationShellGolden() throws {
        try assertGolden(
            "BaseCommunication.shell",
            BaseCommunication(id: Self.id1, data: Data([0xCA, 0xFE])),
            pinned: "Ak5CVE4fAAAAU2Vzc2lvbk1vZGVscy5CYXNlQ29tbXVuaWNhdGlvbgIAAAACAAAAaWQRAAAAAQAAAAAAAEAAgAAAAAAAAAEBAAAAYQcAAAABAgAAAMr+")
    }

    @Test("SessionIdentity outer shell v1 encoding is stable")
    func sessionIdentityShellGolden() throws {
        try assertGolden(
            "SessionIdentity.shell",
            SessionIdentity(id: Self.id1, data: Data([0xCA, 0xFE])),
            pinned: "Ak5CVE4gAAAARG91YmxlUmF0Y2hldEtpdC5TZXNzaW9uSWRlbnRpdHkCAAAAAQAAAGERAAAAAQAAAAAAAEAAgAAAAAAAAAEBAAAAYgcAAAABAgAAAMr+")
    }

    // MARK: - TransportEvent (every case)

    @Test("TransportEvent.sessionReestablishment v1 encoding is stable")
    func transportSessionReestablishmentGolden() throws {
        let envelope = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: Self.id1,
            epoch: 3,
            emittedAt: Self.epoch,
            isResponse: false,
            targetDeviceId: Self.id2)
        try assertGolden(
            "TransportEvent.sessionReestablishment",
            TransportEvent.sessionReestablishment(envelope),
            // Phase 2 dropped `requiresPreDecryptionReset` / `"p"`; `_0` associated-value wrapper is unchanged.
            pinned: "Ak5CVE4cAAAAU2Vzc2lvbk1vZGVscy5UcmFuc3BvcnRFdmVudAEAAAABAAAAYYUAAAABAAAAAgAAAF8wdwAAAAEGAAAAAQAAAGsGAAAAAQEAAABhAQAAAGkRAAAAAQAAAAAAAEAAgAAAAAAAAAEBAAAAZQkAAAABAwAAAAAAAAABAAAAdAkAAAABAAAAQBSCxUEBAAAAcgIAAAABAAEAAABkEQAAAAEAAAAAAABAAIAAAAAAAAAC")
    }

    @Test("TransportEvent.linkedDeviceReprovisioning v1 encoding is stable")
    func transportLinkedDeviceReprovisioningGolden() throws {
        let bundle = LinkedDeviceReprovisioningBundle(
            activeUserConfiguration: userConfiguration(),
            issuedByDeviceId: Self.id1,
            issuedAt: Self.epoch,
            targetDeviceId: Self.id2)
        try assertGolden(
            "TransportEvent.linkedDeviceReprovisioning",
            TransportEvent.linkedDeviceReprovisioning(bundle),
            pinned: "Ak5CVE4cAAAAU2Vzc2lvbk1vZGVscy5UcmFuc3BvcnRFdmVudAEAAAABAAAAYgYBAAABAAAAAgAAAF8w+AAAAAEEAAAAFwAAAGFjdGl2ZVVzZXJDb25maWd1cmF0aW9uawAAAAEFAAAAAQAAAGElAAAAASAAAAAREREREREREREREREREREREREREREREREREREREREREQEAAABiBQAAAAEAAAAAAQAAAGMFAAAAAQAAAAABAAAAZAUAAAABAAAAAAEAAABlBQAAAAEAAAAAEAAAAGlzc3VlZEJ5RGV2aWNlSWQRAAAAAQAAAAAAAEAAgAAAAAAAAAEIAAAAaXNzdWVkQXQJAAAAAQAAAEAUgsVBDgAAAHRhcmdldERldmljZUlkEQAAAAEAAAAAAABAAIAAAAAAAAAC")
    }

    @Test("TransportEvent.synchronizeOneTimeKeys v1 encoding is stable")
    func transportSynchronizeOneTimeKeysGolden() throws {
        try assertGolden(
            "TransportEvent.synchronizeOneTimeKeys",
            TransportEvent.synchronizeOneTimeKeys(
                SynchronizationKeyIdentities(
                    senderX25519Id: "sc",
                    senderMLKEMId: "sm",
                    recipientX25519Id: "rc",
                    recipientMLKEMId: "rm")),
            pinned: "Ak5CVE4cAAAAU2Vzc2lvbk1vZGVscy5UcmFuc3BvcnRFdmVudAEAAAABAAAAY1MAAAABAAAAAgAAAF8wRQAAAAEEAAAAAQAAAGEHAAAAAQIAAABzYwEAAABiBwAAAAECAAAAc20BAAAAYwcAAAABAgAAAHJjAQAAAGQHAAAAAQIAAABybQ==")
    }

    @Test("TransportEvent.refreshOneTimeKeys v1 encoding is stable")
    func transportRefreshOneTimeKeysGolden() throws {
        try assertGolden(
            "TransportEvent.refreshOneTimeKeys",
            TransportEvent.refreshOneTimeKeys,
            pinned: "Ak5CVE4cAAAAU2Vzc2lvbk1vZGVscy5UcmFuc3BvcnRFdmVudAEAAAABAAAAZAQAAAAAAAAA")
    }

    @Test("TransportEvent.requestMessageResend v1 bytes are rejected")
    func transportRequestMessageResendGolden() throws {
        // Phase 2: encrypted-retry cases are gone. Keep the pinned bytes and
        // prove schema-2 decode throws as a retired encrypted-retry payload.
        let pinned = "Ak5CVE4cAAAAU2Vzc2lvbk1vZGVscy5UcmFuc3BvcnRFdmVudAEAAAABAAAAZWIAAAABAAAAAgAAAF8wVAAAAAEDAAAAAQAAAGEKAAAAAQUAAABlbnYtMQEAAABiEQAAAAEAAAAAAABAAIAAAAAAAAABAQAAAGMZAAAAAQIAAAABBQAAAGVudi0xAQUAAABlbnYtMg=="
        let data = try #require(Data(base64Encoded: pinned))
        #expect(TransportEvent.carriesRetiredEncryptedRetry(data))
        do {
            _ = try BinaryDecoder().decode(TransportEvent.self, from: data)
            Issue.record("retired requestMessageResend bytes must not decode as TransportEvent")
        } catch {
            #expect(TransportEvent.isRetiredEncryptedRetry(error))
        }
    }

    @Test("TransportEvent.publishedOneTimeKeysReplenished v1 encoding is stable")
    func transportPublishedOneTimeKeysReplenishedGolden() throws {
        try assertGolden(
            "TransportEvent.publishedOneTimeKeysReplenished",
            TransportEvent.publishedOneTimeKeysReplenished,
            pinned: "Ak5CVE4cAAAAU2Vzc2lvbk1vZGVscy5UcmFuc3BvcnRFdmVudAEAAAABAAAAZgQAAAAAAAAA")
    }

    @Test("TransportEvent.messageResendUnavailable v1 bytes are rejected")
    func transportMessageResendUnavailableGolden() throws {
        // Phase 2: encrypted-retry cases are gone. Keep the pinned bytes and
        // prove schema-2 decode throws as a retired encrypted-retry payload.
        let pinned = "Ak5CVE4cAAAAU2Vzc2lvbk1vZGVscy5UcmFuc3BvcnRFdmVudAEAAAABAAAAZ0UAAAABAAAAAgAAAF8wNwAAAAECAAAAAQAAAGERAAAAAQAAAAAAAEAAgAAAAAAAAAEBAAAAYg8AAAABAQAAAAEFAAAAZW52LTE="
        let data = try #require(Data(base64Encoded: pinned))
        #expect(TransportEvent.carriesRetiredEncryptedRetry(data))
        do {
            _ = try BinaryDecoder().decode(TransportEvent.self, from: data)
            Issue.record("retired messageResendUnavailable bytes must not decode as TransportEvent")
        } catch {
            #expect(TransportEvent.isRetiredEncryptedRetry(error))
        }
    }
}

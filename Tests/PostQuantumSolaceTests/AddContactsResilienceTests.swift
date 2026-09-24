//
//  AddContactsResilienceTests.swift
//  post-quantum-solace
//
//  Regression: a linked child device receives the master's whole contact list in
//  one `addContacts` payload. One failing entry used to abort the batch, dropping
//  every later contact and skipping the `requestMyMetadata` that carries the
//  account profile to the new device.
//

import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
import NeedleTailLogger
@testable import PQSSession
import SessionEvents
import SessionModels
import Testing
import Crypto

@Suite("addContacts resilience")
struct AddContactsResilienceTests {

    private static let crypto = NeedleTailCrypto()

    private struct Harness {
        let session = PQSSession()
        let sessionContext: SessionContext
        let cache = MockCache()
        let transport: FailingConfigurationTransport
        let receiver = RecordingReceiver()
        let delegate = RecordingHostDelegate()
        let symmetricKey = SymmetricKey(size: .bits256)
        let logger = NeedleTailLogger()

        init(mySecretName: String, failingSecretNames: Set<String>) throws {
            let crypto = AddContactsResilienceTests.crypto
            let deviceId = UUID()
            let signingKey = crypto.generateCurve25519SigningPrivateKey()
            let longTermKey = crypto.generateCurve25519PrivateKey()
            let finalMLKEMKey = try crypto.generateMLKem1024PrivateKey()

            let sessionUser = try SessionUser(
                secretName: mySecretName,
                deviceId: deviceId,
                deviceKeys: .init(
                    deviceId: deviceId,
                    signingPrivateKey: signingKey.rawRepresentation,
                    longTermPrivateKey: longTermKey.rawRepresentation,
                    oneTimePrivateKeys: [],
                    mlKEMOneTimePrivateKeys: [],
                    finalMLKEMPrivateKey: .init(finalMLKEMKey.encode())
                ))

            sessionContext = SessionContext(
                sessionUser: sessionUser,
                databaseEncryptionKey: SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) },
                sessionContextId: 1,
                activeUserConfiguration: .init(
                    signingPublicKey: signingKey.publicKey.rawRepresentation,
                    signedDevices: [],
                    signedOneTimePublicKeys: [],
                    signedMLKEMOneTimePublicKeys: []
                ),
                registrationState: .registered
            )
            transport = FailingConfigurationTransport(
                configuration: sessionContext.activeUserConfiguration,
                failingSecretNames: failingSecretNames)
        }

        func addContacts(_ infos: [SharedContactInfo]) async throws {
            try await session.addContacts(
                infos,
                sessionContext: sessionContext,
                cache: cache,
                transport: transport,
                receiver: receiver,
                sessionDelegate: delegate,
                symmetricKey: symmetricKey,
                logger: logger)
        }
    }

    private static func info(_ secretName: String) -> SharedContactInfo {
        SharedContactInfo(secretName: secretName, metadata: [:], sharedCommunicationId: UUID())
    }

    @Test("Every contact is adopted when none fail, then the account profile is requested")
    func happyPathAdoptsAllAndRequestsProfile() async throws {
        let harness = try Harness(mySecretName: "me", failingSecretNames: [])

        try await harness.addContacts([Self.info("alice"), Self.info("bob")])

        #expect(await harness.receiver.createdContactNames == ["alice", "bob"])
        #expect(await harness.delegate.metadataRequests == [
            .nickname("alice"), .nickname("bob"), .personalMessage,
        ])
    }

    @Test("A contact whose configuration cannot be fetched does not abort the rest of the batch")
    func failingContactDoesNotAbortBatch() async throws {
        let harness = try Harness(mySecretName: "me", failingSecretNames: ["bob"])

        let thrown = await #expect(throws: PQSError.self) {
            try await harness.addContacts([Self.info("alice"), Self.info("bob"), Self.info("carol")])
        }

        // The failure is reported once, naming only the entries that did not adopt.
        #expect(thrown == .contactSyncIncomplete(failedSecretNames: ["bob"]))

        // Contacts after the failure are still created and announced to the host.
        #expect(await harness.receiver.createdContactNames == ["alice", "carol"])

        // Profile sync still ran: the account metadata request goes out regardless.
        let requests = await harness.delegate.metadataRequests
        #expect(requests.contains(.personalMessage))
        #expect(requests.contains(.nickname("carol")))
        #expect(!requests.contains(.nickname("bob")))
    }

    @Test("The local account entry is skipped without counting as a failure")
    func selfEntryIsSkipped() async throws {
        let harness = try Harness(mySecretName: "me", failingSecretNames: [])

        try await harness.addContacts([Self.info("me"), Self.info("alice")])

        #expect(await harness.receiver.createdContactNames == ["alice"])
        #expect(await harness.delegate.metadataRequests == [.nickname("alice"), .personalMessage])
    }

    @Test("A peer send failure after the row is persisted is not reported as a failed adoption")
    func peerSendFailureAfterPersistIsTolerated() async throws {
        let harness = try Harness(mySecretName: "me", failingSecretNames: [])
        await harness.delegate.setFailingSynchronizeRecipients(["alice"])

        try await harness.addContacts([Self.info("alice"), Self.info("bob")])

        #expect(await harness.receiver.createdContactNames == ["alice", "bob"])
        #expect(await harness.delegate.metadataRequests.contains(.personalMessage))
    }
}

// MARK: - Mocks

/// Serves the harness's own configuration for every peer except the names it is told to fail.
private actor FailingConfigurationTransport: PQSTransport, PQSKeyDirectory, PQSRecoveryTransport {
    struct ConfigurationUnavailable: Error {}

    let configuration: UserConfiguration
    let failingSecretNames: Set<String>

    init(configuration: UserConfiguration, failingSecretNames: Set<String>) {
        self.configuration = configuration
        self.failingSecretNames = failingSecretNames
    }

    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        if failingSecretNames.contains(secretName) {
            throw ConfigurationUnavailable()
        }
        return configuration
    }

    func sendMessage(_: SignedRatchetMessage, metadata _: SignedRatchetMessageMetadata) async throws {}
    func createUploadPacket(secretName _: String, deviceId _: UUID, recipient _: MessageRecipient, metadata _: Data) async throws {}
    func publishUserConfiguration(_: UserConfiguration, recipient _: String, recipient _: UUID) async throws {}
    func fetchOneTimeKeys(for _: String, deviceId _: String) async throws -> OneTimeKeys {
        throw ConfigurationUnavailable()
    }
    func fetchOneTimeKeyIdentities(for _: String, deviceId _: String, type _: KeyKind) async throws -> [UUID] { [] }
    func updateOneTimeKeys(for _: String, deviceId _: String, keys _: [UserConfiguration.SignedOneTimePublicKey]) async throws {}
    func updateOneTimeMLKEMKeys(for _: String, deviceId _: String, keys _: [UserConfiguration.SignedMLKEMOneTimeKey]) async throws {}
    func batchDeleteOneTimeKeys(for _: String, with _: String, type _: KeyKind) async throws {}
    func deleteOneTimeKeys(for _: String, with _: String, type _: KeyKind) async throws {}
    func publishRotatedKeys(for _: String, deviceId _: String, rotated _: RotatedPublicKeys) async throws {}
    func sendOutOfBandResendRequest(failedEnvelopeMessageIds _: [String], to _: String, deviceId _: UUID, requestingDeviceId _: UUID) async throws {}
    func sendOutOfBandResendUnavailable(unavailableEnvelopeMessageIds _: [String], to _: String, deviceId _: UUID, respondingDeviceId _: UUID) async throws {}
}

private actor RecordingReceiver: MessageStoreObserver {
    var createdContactNames: [String] = []

    func createdContact(_ contact: Contact) async throws {
        createdContactNames.append(contact.secretName)
    }

    func createdMessage(_: EncryptedMessage) async {}
    func updatedMessage(_: EncryptedMessage) async {}
    func deletedMessage(_: EncryptedMessage) async {}
    func removedCommunication(_: MessageRecipient) async throws {}
    func synchronize(contact _: Contact, requestFriendship _: Bool, notifyPeerOfCreation _: Bool) async throws {}
    func transportContactMetadata() async throws {}
    func pushContactMetadata(to _: String) async throws {}
    func updateContact(_: Contact) async throws {}
    func contactMetadata(changed _: Contact) async {}
    func updatedCommunication(_: BaseCommunication, members _: Set<String>) async {}
    func createdChannel(_: BaseCommunication) async {}
}

private actor RecordingHostDelegate: MessagingPolicy, RecoveryObserver {
    struct SynchronizeFailed: Error {}

    var metadataRequests: [MessageRecipient] = []
    private var failingSynchronizeRecipients: Set<String> = []

    func setFailingSynchronizeRecipients(_ names: Set<String>) {
        failingSynchronizeRecipients = names
    }

    func requestMetadata(recipient: MessageRecipient) async throws {
        metadataRequests.append(recipient)
    }

    func synchronizeCommunication(recipient: MessageRecipient, sharedIdentifier _: String, metadata _: Data) async throws {
        if case .nickname(let name) = recipient, failingSynchronizeRecipients.contains(name) {
            throw SynchronizeFailed()
        }
    }

    func requestFriendshipStateChange(recipient _: MessageRecipient, blockData _: Data?, metadata _: Data, currentState _: FriendshipMetadata.State) async throws {}
    func deliveryStateChanged(recipient _: MessageRecipient, metadata _: Data) async throws {}
    func createdContact(recipient _: MessageRecipient) async throws {}
    func editMessage(recipient _: MessageRecipient, metadata _: Data) async throws {}
    nonisolated func shouldPersist(transportInfo _: Data?) -> Bool { true }
    nonisolated func shouldReplayNonPersistentOutbound(transportInfo _: Data?) -> Bool { false }
    func retrieveUserInfo(_: Data?) async -> (secretName: String, deviceId: String)? { nil }
    nonisolated func updateCryptoMessageMetadata(_ message: CryptoMessage, sharedMessageId _: String) -> CryptoMessage { message }
    func updateEncryptableMessageMetadata(_ message: EncryptedMessage, transportInfo _: Data?, identity _: SessionIdentity, recipient _: MessageRecipient) async -> EncryptedMessage { message }
    nonisolated func shouldFinishCommunicationSynchronization(_: Data?) -> Bool { false }
    func processMessage(_: CryptoMessage, senderSecretName _: String, senderDeviceId _: UUID) async -> Bool { true }
    func shouldSendAutomaticDeliveryReceipts() async -> Bool { false }

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

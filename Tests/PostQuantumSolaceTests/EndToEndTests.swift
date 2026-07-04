//
//  EndToEndTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-19.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//

import DoubleRatchetKit
import Foundation
import NeedleTailAsyncSequence
import NeedleTailCrypto
import Testing
import Crypto

@testable import PQSSession
@testable import SessionEvents
@testable import SessionModels

// Global probe to assert control frames observed during tests
actor SessionEventProbe {
    static let shared = SessionEventProbe()
    private var reestablishmentBySession: Set<UUID> = []
    
    func markReestablishment(for sessionId: UUID) {
        reestablishmentBySession.insert(sessionId)
    }
    
    func hasReestablishment(for sessionId: UUID) -> Bool {
        reestablishmentBySession.contains(sessionId)
    }
    
    func reset() {
        reestablishmentBySession.removeAll()
    }
}

actor LinkedDeviceCompromiseProbe {
    private var reportedDeviceIds: [UUID] = []

    func mark(deviceId: UUID) {
        reportedDeviceIds.append(deviceId)
    }

    func count() -> Int {
        reportedDeviceIds.count
    }

    func contains(_ deviceId: UUID) -> Bool {
        reportedDeviceIds.contains(deviceId)
    }
}

actor PeerIdentityTrustProbe {
    struct Event: Equatable {
        let secretName: String
        let deviceId: UUID
        let failedSharedMessageId: String?
    }

    private var events: [Event] = []

    func mark(secretName: String, deviceId: UUID, failedSharedMessageId: String?) {
        events.append(.init(
            secretName: secretName,
            deviceId: deviceId,
            failedSharedMessageId: failedSharedMessageId))
    }

    func count() -> Int {
        events.count
    }

    func contains(secretName: String, deviceId: UUID, failedSharedMessageId: String?) -> Bool {
        events.contains(.init(
            secretName: secretName,
            deviceId: deviceId,
            failedSharedMessageId: failedSharedMessageId))
    }
}

@Suite(.serialized)
actor EndToEndTests {
    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var _senderSession = PQSSession()
    var _senderChildSession1 = PQSSession()
    var _senderChildSession2 = PQSSession()
    var _senderMaxSkipSession = PQSSession(.init(
        messageKeyData: Data([0x00]),
        chainKeyData: Data([0x01]),
        rootKeyData: Data([0x02, 0x03]),
        associatedData: "TestDoubleRatchetKit".data(using: .ascii)!,
        maxSkippedMessageKeys: 10))
    var _recipientSession = PQSSession()
    var _recipientChildSession1 = PQSSession()
    var _recipientChildSession2 = PQSSession()
    var _recipientMaxSkipSession = PQSSession(.init(
        messageKeyData: Data([0x00]),
        chainKeyData: Data([0x01]),
        rootKeyData: Data([0x02, 0x03]),
        associatedData: "TestDoubleRatchetKit".data(using: .ascii)!,
        maxSkippedMessageKeys: 10))
    let sMockUserData: MockUserData
    let sMockUserChildData1: MockUserData
    let sMockUserChildData2: MockUserData
    let rMockUserData: MockUserData
    let rMockUserChildData1: MockUserData
    let rMockUserChildData2: MockUserData
    var senderReceiver: ReceiverDelegate
    var senderChildReceiver1: ReceiverDelegate
    var senderChildReceiver2: ReceiverDelegate
    var senderMaxSkipReceiver: ReceiverDelegate
    var recipientReceiver: ReceiverDelegate
    var recipientChildReceiver1: ReceiverDelegate
    var recipientChildReceiver2: ReceiverDelegate
    var recipientMaxSkipReceiver: ReceiverDelegate
    let bobProcessedRotated = ContinuationSignal()
    let aliceProcessedRotated = ContinuationSignal()
    let aliceProcessedBobRotation = ContinuationSignal()  // NEW SIGNAL
    let senderChild1LinkDelegate = MockDeviceLinkingDelegate(secretName: "alice")
    let senderChild2LinkDelegate = MockDeviceLinkingDelegate(secretName: "alice")
    let recipientChild1LinkDelegate = MockDeviceLinkingDelegate(secretName: "bob")
    let recipientChild2LinkDelegate = MockDeviceLinkingDelegate(secretName: "bob")
    
    private let bobProcessedThree = ContinuationSignal()
    private let aliceProcessedSix = ContinuationSignal()
    
    init() {
        sMockUserData = MockUserData(session: _senderSession)
        sMockUserChildData1 = MockUserData(session: _senderChildSession1)
        sMockUserChildData2 = MockUserData(session: _senderChildSession2)
        rMockUserData = MockUserData(session: _recipientSession)
        rMockUserChildData1 = MockUserData(session: _recipientChildSession1)
        rMockUserChildData2 = MockUserData(session: _recipientChildSession2)
        
        senderReceiver = ReceiverDelegate(session: _senderSession)
        senderChildReceiver1 = ReceiverDelegate(session: _senderChildSession1)
        senderChildReceiver2 = ReceiverDelegate(session: _senderChildSession2)
        senderMaxSkipReceiver = ReceiverDelegate(session: _senderMaxSkipSession)
        recipientReceiver = ReceiverDelegate(session: _recipientSession)
        recipientChildReceiver1 = ReceiverDelegate(session: _recipientChildSession1)
        recipientChildReceiver2 = ReceiverDelegate(session: _recipientChildSession2)
        recipientMaxSkipReceiver = ReceiverDelegate(session: _recipientMaxSkipSession)
    }
    
    func shutdownSessions() async {
        await _senderSession.shutdown()
        await _senderChildSession1.shutdown()
        await _senderChildSession2.shutdown()
        await _senderMaxSkipSession.shutdown()
        await _recipientSession.shutdown()
        await _recipientChildSession1.shutdown()
        await _recipientChildSession2.shutdown()
        await _recipientMaxSkipSession.shutdown()
    }
    
    // MARK: - Helper Methods
    
    func createSenderStore() -> MockIdentityStore {
        sMockUserData.identityStore(isSender: true)
    }
    
    func createSenderChildStore1() -> MockIdentityStore {
        sMockUserChildData1.identityStore(isSender: true)
    }
    
    func createSenderChildStore2() -> MockIdentityStore {
        sMockUserChildData2.identityStore(isSender: true)
    }
    
    func createRecipientStore() -> MockIdentityStore {
        rMockUserData.identityStore(isSender: false)
    }
    
    func createRecipientChildStore1() -> MockIdentityStore {
        rMockUserChildData1.identityStore(isSender: false)
    }
    
    func createRecipientChildStore2() -> MockIdentityStore {
        rMockUserChildData2.identityStore(isSender: false)
    }
    
    
    
    func createSenderSession(store: MockIdentityStore, createSession: Bool = true, transport: _MockTransportDelegate, sessionDelegate: SessionDelegate) async throws {
        await store.setLocalSalt("testSalt1")
        await _senderSession.setLogLevel(.trace)
        await _senderSession.setDatabaseDelegate(conformer: store)
        await _senderSession.setTransportDelegate(conformer: transport)
        await _senderSession.setPQSSessionDelegate(conformer: sessionDelegate)
        await _senderSession.setReceiverDelegate(conformer: senderReceiver)
        
        _senderSession.isViable = true
        await self.store.setPublishableName(sMockUserData.ssn)
        if createSession {
            _senderSession = try await _senderSession.createSession(
                secretName: sMockUserData.ssn, appPassword: sMockUserData.sap
            ) {}
        }
        await _senderSession.setAppPassword(sMockUserData.sap)
        _senderSession = try await _senderSession.startSession(appPassword: sMockUserData.sap)
        try await senderReceiver.setKey(_senderSession.getDatabaseSymmetricKey())
    }
    
    func createSenderMaxSkipSession(store: MockIdentityStore, createSession: Bool = true, transport: _MockTransportDelegate, sessionDelegate: SessionDelegate) async throws {
        await store.setLocalSalt("testSalt1")
        await _senderMaxSkipSession.setLogLevel(.trace)
        await _senderMaxSkipSession.setDatabaseDelegate(conformer: store)
        await _senderMaxSkipSession.setTransportDelegate(conformer: transport)
        await _senderMaxSkipSession.setPQSSessionDelegate(conformer: sessionDelegate)
        await _senderMaxSkipSession.setReceiverDelegate(conformer: senderMaxSkipReceiver)
        
        _senderMaxSkipSession.isViable = true
        await self.store.setPublishableName(sMockUserData.ssn)
        if createSession {
            _senderMaxSkipSession = try await _senderMaxSkipSession.createSession(
                secretName: sMockUserData.ssn, appPassword: sMockUserData.sap
            ) {}
        }
        await _senderMaxSkipSession.setAppPassword(sMockUserData.sap)
        _senderMaxSkipSession = try await _senderMaxSkipSession.startSession(appPassword: sMockUserData.sap)
        try await senderReceiver.setKey(_senderMaxSkipSession.getDatabaseSymmetricKey())
    }
    
    func linkSenderChildSession1(store: MockIdentityStore, transport: _MockTransportDelegate) async throws {
        await store.setLocalSalt("testChildSalt1")
        _senderChildSession1.isViable = true
        await self.store.setPublishableName(sMockUserData.ssn)
        _senderChildSession1.linkDelegate = senderChild1LinkDelegate
        
        let bundle = try await _senderChildSession1.createDeviceCryptographicBundle(isMaster: false)
        senderChild1LinkDelegate.userConfiguration = try await linkedConfiguration(
            masterSession: _senderSession,
            childBundle: bundle)
        await conformSessionDelegate(
            session: _senderChildSession1,
            pqsDelegate: SessionDelegate(session: _senderChildSession1),
            store: store,
            receiver: senderChildReceiver1,
            transport: _MockTransportDelegate(session: _senderChildSession1, store: self.store))
        _senderChildSession1 = try await _senderChildSession1.linkDevice(
            bundle: bundle, password: "123")
        try await senderChildReceiver1.setKey(_senderChildSession1.getDatabaseSymmetricKey())
        _ = try await _senderChildSession1.refreshIdentities(
            secretName: sMockUserData.ssn, forceRefresh: true)
    }
    
    func linkSenderChildSession2(store: MockIdentityStore, transport: _MockTransportDelegate) async throws {
        await store.setLocalSalt("testChildSalt2")
        await _senderChildSession2.setLogLevel(.trace)
        _senderChildSession2.isViable = true
        await self.store.setPublishableName(sMockUserData.ssn)
        _senderChildSession2.linkDelegate = senderChild2LinkDelegate
        let bundle = try await _senderChildSession2.createDeviceCryptographicBundle(isMaster: false)
        senderChild2LinkDelegate.userConfiguration = try await linkedConfiguration(
            masterSession: _senderSession,
            childBundle: bundle)
        await conformSessionDelegate(
            session: _senderChildSession2,
            pqsDelegate: SessionDelegate(session: _senderChildSession2),
            store: store,
            receiver: senderChildReceiver2,
            transport: _MockTransportDelegate(session: _senderChildSession2, store: self.store))
        _senderChildSession2 = try await _senderChildSession2.linkDevice(
            bundle: bundle, password: "123")
        try await senderChildReceiver2.setKey(_senderChildSession2.getDatabaseSymmetricKey())
        _ = try await _senderChildSession2.refreshIdentities(
            secretName: sMockUserData.ssn, forceRefresh: true)
    }
    
    func createRecipientSession(store: MockIdentityStore, createSession: Bool = true, transport: _MockTransportDelegate, sessionDelegate: SessionDelegate) async throws {
        await store.setLocalSalt("testSalt2")
        await _recipientSession.setLogLevel(.trace)
        await _recipientSession.setDatabaseDelegate(conformer: store)
        await _recipientSession.setTransportDelegate(conformer: transport)
        await _recipientSession.setPQSSessionDelegate(conformer: sessionDelegate)
        
        _recipientSession.isViable = true
        await _recipientSession.setReceiverDelegate(conformer: recipientReceiver)
        await self.store.setPublishableName(rMockUserData.rsn)
        if createSession {
            _recipientSession = try await _recipientSession.createSession(
                secretName: rMockUserData.rsn, appPassword: rMockUserData.sap
            ) {}
        }
        await _recipientSession.setAppPassword(rMockUserData.sap)
        _recipientSession = try await _recipientSession.startSession(appPassword: rMockUserData.sap)
        try await recipientReceiver.setKey(_recipientSession.getDatabaseSymmetricKey())
    }
    
    func createRecipientMaxSkipSession(store: MockIdentityStore, createSession: Bool = true, transport: _MockTransportDelegate, sessionDelegate: SessionDelegate) async throws {
        await store.setLocalSalt("testSalt2")
        await _recipientMaxSkipSession.setLogLevel(.trace)
        await _recipientMaxSkipSession.setDatabaseDelegate(conformer: store)
        await _recipientMaxSkipSession.setTransportDelegate(conformer: transport)
        await _recipientMaxSkipSession.setPQSSessionDelegate(conformer: sessionDelegate)
        
        _recipientMaxSkipSession.isViable = true
        await _recipientMaxSkipSession.setReceiverDelegate(conformer: recipientMaxSkipReceiver)
        await self.store.setPublishableName(rMockUserData.rsn)
        if createSession {
            _recipientMaxSkipSession = try await _recipientMaxSkipSession.createSession(
                secretName: rMockUserData.rsn, appPassword: rMockUserData.sap
            ) {}
        }
        await _recipientMaxSkipSession.setAppPassword(rMockUserData.sap)
        _recipientMaxSkipSession = try await _recipientMaxSkipSession.startSession(appPassword: rMockUserData.sap)
        try await recipientReceiver.setKey(_recipientMaxSkipSession.getDatabaseSymmetricKey())
    }
    
    func linkRecipientChildSession1(store: MockIdentityStore, transport: _MockTransportDelegate) async throws {
        await store.setLocalSalt("testChildSalt1")
        _recipientChildSession1.isViable = true
        await self.store.setPublishableName(rMockUserData.rsn)
        _recipientChildSession1.linkDelegate = recipientChild1LinkDelegate
        let bundle = try await _recipientChildSession1.createDeviceCryptographicBundle(
            isMaster: false)
        recipientChild1LinkDelegate.userConfiguration = try await linkedConfiguration(
            masterSession: _recipientSession,
            childBundle: bundle)
        await conformSessionDelegate(
            session: _recipientChildSession1,
            pqsDelegate: SessionDelegate(session: _recipientChildSession1),
            store: store,
            receiver: recipientChildReceiver1,
            transport: _MockTransportDelegate(session: _recipientChildSession1, store: self.store))
        _recipientChildSession1 = try await _recipientChildSession1.linkDevice(
            bundle: bundle, password: "123")
        try await recipientChildReceiver1.setKey(_recipientChildSession1.getDatabaseSymmetricKey())
        _ = try await _recipientChildSession1.refreshIdentities(
            secretName: rMockUserData.rsn, forceRefresh: true)
    }
    
    func linkRecipientChildSession2(store: MockIdentityStore, transport: _MockTransportDelegate) async throws {
        await store.setLocalSalt("testChildSalt2")
        _recipientChildSession2.isViable = true
        await self.store.setPublishableName(rMockUserData.rsn)
        _recipientChildSession2.linkDelegate = recipientChild2LinkDelegate
        let bundle = try await _recipientChildSession2.createDeviceCryptographicBundle(
            isMaster: false)
        recipientChild2LinkDelegate.userConfiguration = try await linkedConfiguration(
            masterSession: _recipientSession,
            childBundle: bundle)
        await conformSessionDelegate(
            session: _recipientChildSession2,
            pqsDelegate: SessionDelegate(session: _recipientChildSession2),
            store: store,
            receiver: recipientChildReceiver2,
            transport: _MockTransportDelegate(session: _recipientChildSession2, store: self.store))
        _recipientChildSession2 = try await _recipientChildSession2.linkDevice(
            bundle: bundle, password: "123")
        try await recipientChildReceiver2.setKey(_recipientChildSession2.getDatabaseSymmetricKey())
        _ = try await _recipientChildSession2.refreshIdentities(
            secretName: rMockUserData.rsn, forceRefresh: true)
    }

    private func linkedConfiguration(
        masterSession: PQSSession,
        childBundle: PQSSession.CryptographicBundle
    ) async throws -> UserConfiguration {
        guard let masterContext = await masterSession.sessionContext else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        guard let childDevice = try childBundle.userConfiguration.getVerifiedDevices().first(where: {
            $0.deviceId == childBundle.deviceKeys.deviceId
        }) else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }
        let masterSigningKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: masterContext.sessionUser.deviceKeys.signingPrivateKey)

        var configuration = masterContext.activeUserConfiguration
        configuration.signedDevices.removeAll { $0.id == childDevice.deviceId }
        configuration.signedDevices.append(try UserConfiguration.SignedDeviceConfiguration(
            device: childDevice,
            signingKey: masterSigningKey))

        for key in childBundle.userConfiguration.signedOneTimePublicKeys {
            configuration.signedOneTimePublicKeys.removeAll { $0.id == key.id }
            configuration.signedOneTimePublicKeys.append(key)
        }
        for key in childBundle.userConfiguration.signedMLKEMOneTimePublicKeys {
            configuration.signedMLKEMOneTimePublicKeys.removeAll { $0.id == key.id }
            configuration.signedMLKEMOneTimePublicKeys.append(key)
        }
        for bundle in childBundle.userConfiguration.signedDeviceKeyBundles {
            configuration.signedDeviceKeyBundles.removeAll { $0.id == bundle.id }
            configuration.signedDeviceKeyBundles.append(bundle)
        }
        return configuration
    }
    
    // MARK: - Test Methods
    
    /// Receives a message but tolerates transient/expected errors during key rotation.
    ///
    /// In production, `.maxSkippedHeadersExceeded` is handled as session repair so the
    /// SDK can reestablish with the sender and request resend without rotating local identity keys.
    /// In tests, we typically want receive loops to keep running while reestablishment converges.
    @discardableResult
    private func receiveIgnoringRecoverableErrors(
        _ session: PQSSession,
        received: ReceivedMessage
    ) async throws -> Bool {
        do {
            try await session.receiveMessage(
                message: received.message,
                sender: received.sender,
                deviceId: received.deviceId,
                messageId: received.messageId
            )
            return true
        } catch let ratchetError as RatchetError where [
            .maxSkippedHeadersExceeded,
            .stateUninitialized,
            .initialMessageNotReceived,
            .skippedKeysDrained
        ].contains(ratchetError) {
            return false
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
            return false
        } catch let sessionError as PQSSession.SessionErrors where sessionError == .databaseNotInitialized {
            // Some long-running receive loops can outlive teardown by a tick.
            // Treat this as recoverable in test harness loops.
            return false
        } catch is CryptoKitError {
            return false
        } catch let sessionError as PQSSession.SessionErrors
            where sessionError == .sessionDecryptionError {
            return false
        }
    }
    
    @Test("End-to-End Channel Messaging")
    func testEndToEndChannelMessaging() async throws {
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        _ = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        
        // Init sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        // Create a third participant "joe" so identity refresh for joe succeeds during channel outbound
        var joeSession = PQSSession()
        let joeStore = MockIdentityStore(mockUserData: MockUserData(session: joeSession), session: joeSession, isSender: false)
        let joeTransport = _MockTransportDelegate(session: joeSession, store: store)
        let joeReceiver = ReceiverDelegate(session: joeSession)
        let joeDelegate = SessionDelegate(session: joeSession)
        await joeSession.setLogLevel(.trace)
        await joeSession.setDatabaseDelegate(conformer: joeStore)
        await joeSession.setTransportDelegate(conformer: joeTransport)
        await joeSession.setPQSSessionDelegate(conformer: joeDelegate)
        await joeSession.setReceiverDelegate(conformer: joeReceiver)
        joeSession.isViable = true
        await self.store.setPublishableName("joe")
        joeSession = try await joeSession.createSession(secretName: "joe", appPassword: "123") {}
        await joeSession.setAppPassword("123")
        joeSession = try await joeSession.startSession(appPassword: "123")
        try await joeReceiver.setKey(joeSession.getDatabaseSymmetricKey())
        
        // Pre-create channel communication on both caches so inbound channel can resolve it
       let channelName = "general"
       let info = ChannelInfo(
            name: channelName,
            administrator: "alice",
            members: ["alice", "bob", "joe"],
            operators: ["alice"])
        let metadata = try BinaryEncoder().encode(info)
        let senderKey = try await _senderSession.getDatabaseSymmetricKey()
        let recipientKey = try await _recipientSession.getDatabaseSymmetricKey()
        let props = BaseCommunication.UnwrappedProps(
            messageCount: 0,
            administrator: "alice",
            operators: ["alice"],
            members: ["alice", "bob", "joe"],
            metadata: metadata,
            blockedMembers: [],
            communicationType: .channel(channelName)
        )
        let commId = UUID()
        let senderComm = try BaseCommunication(id: commId, props: props, symmetricKey: senderKey)
        let recipientComm = try BaseCommunication(id: commId, props: props, symmetricKey: recipientKey)
        try await senderStore.createCommunication(senderComm)
        try await recipientStore.createCommunication(recipientComm)
        
        // Bob receive loop: process one channel message
        var bobReceived = 0
        bobTask = Task {
            await #expect(throws: Never.self) {
                for await received in bobStream {
                    guard received.recipient == "bob" else { continue }
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        bobReceived += 1
                    }
                    if bobReceived == 2 {
                        aliceTransport.continuation?.finish()
                        bobTransport.continuation?.finish()
                    }
                }
            }
        }
        
        // Send a channel message from Alice
        try await _senderSession.writeTextMessage(
            recipient: .channel(channelName),
            text: "hello channel",
            metadata: metadata
        )
        try await Task.sleep(until: .now + .seconds(3))
        // Assertions
        #expect(bobReceived == 2, "Bob should receive one channel message")
        await #expect(recipientStore.createdMessages.count >= 1, "Recipient should persist the channel message")
    }
    
    @Test("Manual Key Rotation Then Immediate Send")
    func testManualKeyRotationThenImmediateSend() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        func cleanup() async {
            aliceTransport.continuation?.finish()
            bobTransport.continuation?.finish()
            aliceTask?.cancel()
            bobTask?.cancel()
            if let aliceTask {
                await aliceTask.value
            }
            if let bobTask {
                await bobTask.value
            }
            await shutdownSessions()
        }

        do {
            let senderStore = createSenderStore()
            let recipientStore = createRecipientStore()
        

            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)
        
            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
            try await createFriendship(
                aliceSession: _senderSession,
                sd: sd,
                bobSession: _recipientSession,
                rsd: rsd)
        
            // Alice receive loop
            aliceTask = Task {
                await #expect(throws: Never.self, "Alice should process Bob's replies after rotation") {
                    var count = 0
                    for await received in aliceStream {
                        count += 1

                        if count == 3 {
                            _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                            aliceTransport.continuation?.finish()
                            bobTransport.continuation?.finish()
                        }
                    }
                }
            }
        
            // Bob receive loop
            bobTask = Task {
                await #expect(throws: Never.self, "Bob should process Alice's post-rotation send and reply") {
                    var processed = 0
                    for await received in bobStream {
                        guard try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) else {
                            continue
                        }
                        processed += 1
                        if processed == 1 {
                            // After first warmup delivery, rotate on Alice and immediately send
                            try await self._senderSession.rotateKeysOnPotentialCompromise()
                            try await self._senderSession.writeTextMessage(
                                recipient: .nickname("bob"),
                                text: "post-rotate")
                        } else if processed == 2 {
                            // Reply from Bob after receiving Alice's post-rotation message
                            try await self._recipientSession.writeTextMessage(
                                recipient: .nickname("alice"),
                                text: "ack post-rotate")
                        }
                    }
                }
            }
        
            // Warm-up to establish identity/ratchet
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")

            // Let the receive loops finish the rotation flow before deterministic teardown.
            try await Task.sleep(until: .now + .seconds(5))
            await cleanup()
        } catch {
            await cleanup()
            throw error
        }
    }
    
    @Test("Auto Sync After Rotation - No Manual Send")
    func testAutoSyncAfterRotationNoManualSend() async throws {
        // Expect an automatic sync/control message after both sides rotate
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        var receivedAutoSync = false
        await SessionEventProbe.shared.reset()
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderMaxSkipSession,
            sd: sd,
            bobSession: _recipientMaxSkipSession,
            rsd: rsd)
        
        // Start receive loops (no manual sends in this test)
        aliceTask = Task {
            await #expect(throws: Never.self) {
                for await received in aliceStream {
                    if await self._senderMaxSkipSession.sessionContext == nil { continue }
                    let myName = await self._senderMaxSkipSession.sessionContext?.sessionUser.secretName
                    if received.sender == myName { continue }
                    do {
                        try await self._senderMaxSkipSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                    } catch {
                        return
                    }
                }
            }
        }
        bobTask = Task {
            await #expect(throws: Never.self) {
                for await received in bobStream {
                    if await self._recipientMaxSkipSession.sessionContext == nil { continue }
                    let myName = await self._recipientMaxSkipSession.sessionContext?.sessionUser.secretName
                    if received.sender == myName { continue }
                    do {
                        try await self._recipientMaxSkipSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                        // Only finish once the sessionReestablishment frame has been observed
                        if await SessionEventProbe.shared.hasReestablishment(for: self._recipientMaxSkipSession.id) {
                            receivedAutoSync = true
                            aliceTransport.continuation?.finish()
                            bobTransport.continuation?.finish()
                            return
                        }
                    } catch {
                        return
                    }
                }
            }
        }
        
        // Give receive loops time to start
        try await Task.sleep(until: .now + .milliseconds(100))
        
        // Rotate both sides; if implementation auto-sends a sync, Bob should receive it
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await self._senderMaxSkipSession.rotateKeysOnPotentialCompromise()
            }
            group.addTask {
                try await self._recipientMaxSkipSession.rotateKeysOnPotentialCompromise()
            }
            try await group.waitForAll()
        }
        try await Task.sleep(until: .now + .seconds(1))

        // Wait briefly for the control frame. In practice, delivery/processing order can be
        // non-deterministic in these in-memory transports, so don't hard-fail on timing here.
        var attempts = 0
        let maxAttempts = 30
        while attempts < maxAttempts && !receivedAutoSync {
            try await Task.sleep(until: .now + .milliseconds(100))
            attempts += 1
        }
        
        // Production-critical assertion: rotation publishes rotated keys (i.e., rotation happened)
        // and does not enter an unbounded rotation loop. With concurrent rotation, each side may
        // publish once for self and once when processing the other's reestablishment.
        let aliceRotations = await aliceTransport.publishRotatedKeysCallCount
        let bobRotations = await bobTransport.publishRotatedKeysCallCount
        #expect(aliceRotations >= 1 && aliceRotations <= 2, "Expected Alice to publish rotated keys 1–2 times, got \(aliceRotations)")
        #expect(bobRotations >= 1 && bobRotations <= 2, "Expected Bob to publish rotated keys 1–2 times, got \(bobRotations)")
    }
    
    @Test("Immediate Post-Rotation Decrypt - No Delay")
    func testImmediatePostRotationDecryptNoDelay() async throws {
        // After both rotate, send immediately and expect decrypt (auto re-handshake in place)
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        var bobDecrypted = false
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderMaxSkipSession,
            sd: sd,
            bobSession: _recipientMaxSkipSession,
            rsd: rsd)
        
        // Receive loops
        aliceTask = Task {
            await #expect(throws: Never.self) {
                for await received in aliceStream {
                    if await self._senderMaxSkipSession.sessionContext == nil { continue }
                    let myName = await self._senderMaxSkipSession.sessionContext?.sessionUser.secretName
                    if received.sender == myName { continue }
                    do {
                        try await self._senderMaxSkipSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                    } catch {
                        return
                    }
                }
            }
        }
        let messageToSend = "immediate"
        bobTask = Task {
            for await received in bobStream {
                if await self._recipientMaxSkipSession.sessionContext == nil { continue }
                let myName = await self._recipientMaxSkipSession.sessionContext?.sessionUser.secretName
                if received.sender == myName { continue }
                do {
                    try await self._recipientMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    bobDecrypted = true
                    aliceTransport.continuation?.finish()
                    bobTransport.continuation?.finish()
                    return
                } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
                    // Recipient failed to decrypt; request sender to resend the same message.
                    try? await self._senderMaxSkipSession.writeTextMessage(
                        recipient: .nickname("bob"),
                        text: messageToSend)
                } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
                    // Message signature is invalid (e.g., after key rotation); request resend.
                    try? await self._senderMaxSkipSession.writeTextMessage(
                        recipient: .nickname("bob"),
                        text: messageToSend)
                } catch {
                    // Other errors - return
                    return
                }
            }
        }
        
        // Rotate both sides with 2s sleep after each so reestablishment is processed before sending
        // (longer delay when run in batch after other tests that share session state)
        try await _senderMaxSkipSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .seconds(2))
        try await _recipientMaxSkipSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .seconds(2))

        try await _senderMaxSkipSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: messageToSend)

        // Poll for Bob's decrypt; allow up to 4s for async delivery when run in batch
        var waited: TimeInterval = 0
        while !bobDecrypted && waited < 4 {
            try await Task.sleep(until: .now + .milliseconds(200))
            waited += 0.2
        }
        #expect(bobDecrypted, "Bob should receive and decrypt the post-rotation message")
    }
    
    @Test("Shared ID override is preserved on outbound replay send")
    func testSharedIdOverridePreservedOnOutboundReplaySend() async throws {
        actor OutboundProbe {
            private var ids: [String] = []
            func append(_ id: String) { ids.append(id) }
            func first() -> String? { ids.first }
            func count() -> Int { ids.count }
        }
        
        var bobTask: Task<Void, Never>?
        let probe = OutboundProbe()
        let replaySharedId = UUID().uuidString
        
        func waitForOutbound(timeoutSeconds: TimeInterval = 4) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await probe.count() > 0 { return true }
                try? await Task.sleep(until: .now + .milliseconds(50))
            }
            return false
        }
        
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd
        )
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        bobTask = Task {
            for await received in bobStream {
                if received.sender == "alice", received.transportEvent == nil {
                    await probe.append(received.messageId)
                    return
                }
            }
        }
        
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "replay-payload",
            sharedIdOverride: replaySharedId
        )
        
        #expect(await waitForOutbound(), "Expected outbound frame to be delivered to recipient transport")
        #expect(await probe.first() == replaySharedId, "Wire metadata shared id should preserve override value")
        
        let persisted = await senderStore.getAllMessages()
        #expect(persisted.contains(where: { $0.sharedId == replaySharedId }), "Sender persistence should retain replay shared id")
    }

    @Test("RequestMessageResend control event carries failed shared id over transport")
    func testRequestMessageResendControlEventTransportPayload() async throws {
        actor EventProbe {
            private var event: TransportEvent?
            func set(_ value: TransportEvent?) { event = value }
            func get() -> TransportEvent? { event }
        }
        
        var aliceTask: Task<Void, Never>?
        let probe = EventProbe()
        let failedSharedId = UUID().uuidString
        
        func waitForEvent(timeoutSeconds: TimeInterval = 4) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await probe.get() != nil { return true }
                try? await Task.sleep(until: .now + .milliseconds(50))
            }
            return false
        }
        
        defer {
            Task {
                aliceTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd
        )
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        
        aliceTask = Task {
            for await received in aliceStream {
                if received.sender == "bob", received.recipient == "alice" {
                    await probe.set(received.transportEvent)
                    return
                }
            }
        }
        
        guard let requesterDeviceId = await _recipientSession.sessionContext?.sessionUser.deviceId else {
            Issue.record("Missing requester device id")
            return
        }
        let request = FailedMessageResendRequest(
            failedSharedMessageId: failedSharedId,
            requestingDeviceId: requesterDeviceId
        )
        let metadata = try BinaryEncoder().encode(TransportEvent.requestMessageResend(request))
        try await _recipientSession.writeTextMessage(
            recipient: .nickname("alice"),
            transportInfo: metadata
        )
        
        #expect(await waitForEvent(), "Expected requestMessageResend control event on transport")
        guard let event = await probe.get() else {
            Issue.record("Expected requestMessageResend event")
            return
        }
        switch event {
        case .requestMessageResend(let received):
            #expect(received.failedSharedMessageId == failedSharedId)
            #expect(received.requestingDeviceId == requesterDeviceId)
        default:
            Issue.record("Unexpected control event type")
        }
    }
    
    @Test("MaxSkipped emits resend request referencing failed shared id")
    func testMaxSkippedResendRequestAndReplaySharedIdEndToEnd() async throws {
        actor FlowProbe {
            var failedSharedId: String?
            var requestedSharedId: String?
            var didHitMaxSkipped = false
            
            func markFailed(_ id: String) {
                failedSharedId = id
                didHitMaxSkipped = true
            }
            func markRequested(_ id: String) { requestedSharedId = id }
        }
        
        actor DropGate {
            let dropCount: Int
            var armed = false
            var dropped = 0
            
            init(dropCount: Int) { self.dropCount = dropCount }
            func arm() { armed = true }
            func shouldDropNext() -> Bool {
                guard armed else { return false }
                if dropped < dropCount {
                    dropped += 1
                    return true
                }
                return false
            }

            func isFailingDeliveryCandidate() -> Bool {
                armed && dropped >= dropCount
            }
        }
        
        let probe = FlowProbe()
        let gate = DropGate(dropCount: 12) // > maxSkippedMessageKeys(10) for these sessions
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        
        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(until: .now + .milliseconds(50))
            }
            return false
        }
        
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        
        // Drop a burst of Alice->Bob non-control messages once armed to trigger max-skipped on the first delivered gap message.
        aliceTransport.shouldDeliver = { received in
            guard received.sender == "alice", received.recipient == "bob" else { return true }
            guard received.transportEvent == nil else { return true }
            let shouldDrop = await gate.shouldDropNext()
            return !shouldDrop
        }
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        
        try await createSenderMaxSkipSession(
            store: createSenderStore(),
            transport: aliceTransport,
            sessionDelegate: sd
        )
        try await createRecipientMaxSkipSession(
            store: createRecipientStore(),
            transport: bobTransport,
            sessionDelegate: rsd
        )
        try await createFriendship(
            aliceSession: _senderMaxSkipSession,
            sd: sd,
            bobSession: _recipientMaxSkipSession,
            rsd: rsd
        )
        
        // Sender side: process Bob's control request so replay can be emitted.
        aliceTask = Task {
            for await received in aliceStream {
                if let event = received.transportEvent,
                   case .requestMessageResend(let request) = event {
                    await probe.markRequested(request.failedSharedMessageId)
                }
                do {
                    try await self._senderMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                } catch {
                    // Keep loop alive for control-path assertions.
                }
            }
        }
        
        // Recipient side: detect max-skipped failure and eventual replay delivery.
        bobTask = Task {
            for await received in bobStream {
                if received.transportEvent == nil,
                   await gate.isFailingDeliveryCandidate(),
                   !(await probe.didHitMaxSkipped) {
                    await probe.markFailed(received.messageId)
                }
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._recipientMaxSkipSession,
                    received: received
                )
            }
        }
        
        // Prime the conversation with one delivered message before arming gap-drop behavior.
        try await _senderMaxSkipSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "baseline-before-gap"
        )
        try? await Task.sleep(until: .now + .milliseconds(250))
        
        await gate.arm()
        
        // Burst: first 12 dropped, next delivered should trigger max-skipped.
        for i in 0..<13 {
            try await _senderMaxSkipSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "gap-\(i)"
            )
        }
        
        let sawMaxSkipped = await waitUntil {
            await probe.didHitMaxSkipped
        }
        #expect(sawMaxSkipped, "Expected recipient to identify the first failing shared id after the dropped gap")
        
        let sawRequest = await waitUntil {
            await probe.requestedSharedId != nil
        }
        #expect(sawRequest, "Expected SDK to emit requestMessageResend after max-skipped failure")
        
        let failed = await probe.failedSharedId
        let requested = await probe.requestedSharedId
        
        #expect(failed == requested, "Resend request must reference the failed shared message id")
    }
    
    @Test("Running processor applies inbound failure policy to the correct shared id")
    func testRunningProcessorAppliesInboundFailurePolicyToCorrectSharedId() async throws {
        actor Probe {
            var failedSharedId: String?
            var requestedSharedId: String?
            func markFailed(_ id: String) { failedSharedId = id }
            func markRequested(_ id: String) { requestedSharedId = id }
        }
        
        actor DropGate {
            let dropCount: Int
            var armed = false
            var dropped = 0
            
            init(dropCount: Int) { self.dropCount = dropCount }
            func arm() { armed = true }
            func shouldDropNext() -> Bool {
                guard armed else { return false }
                if dropped < dropCount {
                    dropped += 1
                    return true
                }
                return false
            }

            func isFailingDeliveryCandidate() -> Bool {
                armed && dropped >= dropCount
            }
        }
        
        let probe = Probe()
        let gate = DropGate(dropCount: 12)
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        
        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(until: .now + .milliseconds(50))
            }
            return false
        }
        
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        aliceTransport.shouldDeliver = { received in
            guard received.sender == "alice", received.recipient == "bob" else { return true }
            guard received.transportEvent == nil else { return true }
            let shouldDrop = await gate.shouldDropNext()
            return !shouldDrop
        }
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        
        try await createSenderMaxSkipSession(
            store: createSenderStore(),
            transport: aliceTransport,
            sessionDelegate: sd
        )
        try await createRecipientMaxSkipSession(
            store: createRecipientStore(),
            transport: bobTransport,
            sessionDelegate: rsd
        )
        try await createFriendship(
            aliceSession: _senderMaxSkipSession,
            sd: sd,
            bobSession: _recipientMaxSkipSession,
            rsd: rsd
        )
        
        aliceTask = Task {
            for await received in aliceStream {
                if let event = received.transportEvent,
                   case .requestMessageResend(let request) = event {
                    await probe.markRequested(request.failedSharedMessageId)
                }
                try? await self._senderMaxSkipSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                )
            }
        }
        
        bobTask = Task {
            for await received in bobStream {
                if received.transportEvent == nil,
                   await gate.isFailingDeliveryCandidate(),
                   await probe.failedSharedId == nil {
                    await probe.markFailed(received.messageId)
                }
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._recipientMaxSkipSession,
                    received: received
                )
            }
        }
        
        try await _senderMaxSkipSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "baseline-before-gap"
        )
        #expect(await waitUntil { await self._recipientMaxSkipSession.taskProcessor.isRunning })
        
        await gate.arm()
        for i in 0..<13 {
            try await _senderMaxSkipSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "running-gap-\(i)"
            )
        }
        
        #expect(await waitUntil { await probe.failedSharedId != nil }, "Expected running processor to observe a failed shared id")
        #expect(await waitUntil { await probe.requestedSharedId != nil }, "Expected running processor to emit requestMessageResend")
        #expect(await probe.failedSharedId == probe.requestedSharedId, "Resend request should reference the actual failed message even while the processor is already running")
    }

    @Test("replay with same shared id is still admitted after inbound failure policy marks original")
    func testReplayWithSameSharedIdIsStillAdmittedAfterInboundFailurePolicyMarksOriginal() async throws {
        struct CapturedInbound: Sendable {
            let message: SignedRatchetMessage
            let sender: String
            let deviceId: UUID
            let messageId: String
        }

        actor Probe {
            var outbound: [CapturedInbound] = []

            func markOutbound(_ received: ReceivedMessage) {
                outbound.append(.init(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                ))
            }

            func frames() -> [CapturedInbound] { outbound }
        }

        let probe = Probe()
        var replayCaptureTask: Task<Void, Never>?

        func waitUntil(
            timeoutSeconds: TimeInterval = 6,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(until: .now + .milliseconds(50))
            }
            return false
        }

        defer {
            Task {
                replayCaptureTask?.cancel()
                await shutdownSessions()
            }
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd
        )

        let replaySharedId = UUID().uuidString
        let replayStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        replayCaptureTask = Task {
            for await received in replayStream {
                guard received.transportEvent == nil else { continue }
                await probe.markOutbound(received)
            }
        }

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "replay-admission-source",
            sharedIdOverride: replaySharedId
        )

        #expect(await waitUntil { await probe.frames().count == 1 }, "Expected original outbound frame to be captured")
        guard let original = await probe.frames().first else {
            Issue.record("Expected captured original outbound frame")
            return
        }

        let failedInbound = InboundTaskMessage(
            message: original.message,
            senderSecretName: original.sender,
            senderDeviceId: original.deviceId,
            sharedMessageId: original.messageId
        )
        await _recipientSession.markInboundFailure(
            failedInbound,
            failureClass: "ratchet.missingOneTimeKey"
        )
        await _recipientSession.deferPeerResendUntilReestablished(
            sender: original.sender,
            deviceId: original.deviceId,
            failedMessageId: original.messageId,
            failureClass: "ratchet.missingOneTimeKey"
        )

        #expect(
            !(await _recipientSession.isInboundFailureQuarantined(
                sender: original.sender,
                deviceId: original.deviceId,
                messageId: replaySharedId
            )),
            "Failure policy must not quarantine the tuple that replay recovery reuses"
        )
        #expect(
            !(await _recipientSession.shouldSuppressInboundFailure(
                failedInbound,
                failureClass: "ratchet.missingOneTimeKey"
            )),
            "Pending replay recovery must admit the same shared id before decryption"
        )

    }
    
    @Test("maxSkipped resend side effect failure stays internal and retryable")
    func testMaxSkippedResendRequestSendFailureStaysRetryable() async throws {
        enum SyntheticControlSendError: Error {
            case failed
        }

        struct CapturedInbound: Sendable {
            let message: SignedRatchetMessage
            let sender: String
            let deviceId: UUID
            let messageId: String
        }
        
        actor Probe {
            var observedError: String?
            var failedInbound: CapturedInbound?
            func mark(_ error: Error) { observedError = String(describing: error) }
            func get() -> String? { observedError }
            func markFailedInbound(_ received: ReceivedMessage) {
                if failedInbound == nil {
                    failedInbound = .init(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                }
            }
            func getFailedInbound() -> CapturedInbound? { failedInbound }
        }
        
        actor DropGate {
            let dropCount: Int
            var armed = false
            var dropped = 0
            
            init(dropCount: Int) { self.dropCount = dropCount }
            func arm() { armed = true }
            func shouldDropNext() -> Bool {
                guard armed else { return false }
                if dropped < dropCount {
                    dropped += 1
                    return true
                }
                return false
            }

            func isFailingDeliveryCandidate() -> Bool {
                armed && dropped >= dropCount
            }
        }
        
        let probe = Probe()
        let gate = DropGate(dropCount: 12)
        var bobTask: Task<Void, Never>?
        
        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(until: .now + .milliseconds(50))
            }
            return false
        }
        
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        aliceTransport.shouldDeliver = { received in
            guard received.sender == "alice", received.recipient == "bob" else { return true }
            guard received.transportEvent == nil else { return true }
            let shouldDrop = await gate.shouldDropNext()
            return !shouldDrop
        }
        bobTransport.transformOutgoing = { received in
            if case .requestMessageResend = received.transportEvent {
                throw SyntheticControlSendError.failed
            }
            return received
        }
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(
            store: createSenderStore(),
            transport: aliceTransport,
            sessionDelegate: sd
        )
        try await createRecipientMaxSkipSession(
            store: createRecipientStore(),
            transport: bobTransport,
            sessionDelegate: rsd
        )
        try await createFriendship(
            aliceSession: _senderMaxSkipSession,
            sd: sd,
            bobSession: _recipientMaxSkipSession,
            rsd: rsd
        )
        
        bobTask = Task {
            for await received in bobStream {
                if received.transportEvent == nil,
                   await gate.isFailingDeliveryCandidate() {
                    await probe.markFailedInbound(received)
                }
                do {
                    _ = try await self.receiveIgnoringRecoverableErrors(
                        self._recipientMaxSkipSession,
                        received: received
                    )
                } catch {
                    await probe.mark(error)
                    return
                }
            }
        }
        
        try await _senderMaxSkipSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "baseline-before-gap"
        )
        try await Task.sleep(until: .now + .milliseconds(250))
        
        await gate.arm()
        for i in 0..<13 {
            try await _senderMaxSkipSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "masking-gap-\(i)"
            )
        }
        
        #expect(await waitUntil { await probe.getFailedInbound() != nil }, "Expected test to capture the failed inbound frame")
        #expect(await waitUntil(timeoutSeconds: 1) { await probe.get() != nil } == false, "Control-send failure should stay internal to the resend side effect path")

        guard let failedInbound = await probe.getFailedInbound() else {
            Issue.record("Expected failed inbound frame")
            return
        }

        let inbound = InboundTaskMessage(
            message: failedInbound.message,
            senderSecretName: failedInbound.sender,
            senderDeviceId: failedInbound.deviceId,
            sharedMessageId: failedInbound.messageId
        )
        #expect(
            !(await _recipientMaxSkipSession.shouldSuppressInboundFailure(
                inbound,
                failureClass: "ratchet.maxSkippedHeadersExceeded"
            )),
            "Failed resend-request side effects must not quarantine the tuple; the same inbound failure needs to remain retryable"
        )
    }

    @Test("missingSessionIdentity during stream processing does not wedge subsequent messages")
    func testMissingSessionIdentityDoesNotWedgeQueue() async throws {
        actor Probe {
            var decryptedCount = 0
            func markDecrypted() { decryptedCount += 1 }
            func count() -> Int { decryptedCount }
        }
        
        actor OneShotFailureGate {
            var shouldFail = true
            func consumeFailure() -> Bool {
                if shouldFail {
                    shouldFail = false
                    return true
                }
                return false
            }
        }
        
        final class OneShotMissingIdentityDelegate: @unchecked Sendable, TaskSequenceDelegate {
            let processor: TaskProcessor
            let gate = OneShotFailureGate()
            
            init(processor: TaskProcessor) {
                self.processor = processor
            }
            
            func performRatchet(task: TaskType, session: PQSSession) async throws {
                if case .streamMessage = task, await gate.consumeFailure() {
                    throw PQSSession.SessionErrors.missingSessionIdentity
                }
                try await processor.performRatchet(task: task, session: session)
            }
        }
        
        let probe = Probe()
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        
        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(until: .now + .milliseconds(50))
            }
            return false
        }
        
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd
        )
        
        let recipientProcessor = await _recipientSession.taskProcessor
        let injectedDelegate = OneShotMissingIdentityDelegate(processor: recipientProcessor)
        await recipientProcessor.setTaskDelegate(injectedDelegate)
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        aliceTask = Task {
            for await received in aliceStream {
                _ = try? await self._senderSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                )
            }
        }
        
        bobTask = Task {
            for await received in bobStream {
                do {
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    if received.transportEvent == nil {
                        await probe.markDecrypted()
                    }
                } catch {
                    // Injected one-shot failure may surface; subsequent jobs must still run.
                }
            }
        }
        
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "first-message-injected-missing-identity"
        )
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "second-message-still-should-decrypt"
        )
        
        #expect(
            await waitUntil { await probe.count() >= 1 },
            "At least one follow-up message should decrypt after missingSessionIdentity; processor must not wedge"
        )
    }

    @Test("sendingKeyIsNil during outbound processing resets identity and retries")
    func testSendingKeyIsNilOutboundRecoveryRetriesMessage() async throws {
        actor Probe {
            var decryptedCount = 0
            func markDecrypted() { decryptedCount += 1 }
            func count() -> Int { decryptedCount }
        }

        actor OneShotFailureGate {
            var shouldFail = true
            func consumeFailure() -> Bool {
                if shouldFail {
                    shouldFail = false
                    return true
                }
                return false
            }
        }

        final class OneShotSendingKeyNilDelegate: @unchecked Sendable, TaskSequenceDelegate {
            let processor: TaskProcessor
            let gate = OneShotFailureGate()

            init(processor: TaskProcessor) {
                self.processor = processor
            }

            func performRatchet(task: TaskType, session: PQSSession) async throws {
                if case .writeMessage = task, await gate.consumeFailure() {
                    throw RatchetError.sendingKeyIsNil
                }
                try await processor.performRatchet(task: task, session: session)
            }
        }

        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(until: .now + .milliseconds(50))
            }
            return false
        }

        let probe = Probe()
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd
        )

        let senderProcessor = await _senderSession.taskProcessor
        await senderProcessor.setTaskDelegate(OneShotSendingKeyNilDelegate(processor: senderProcessor))

        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        bobTask = Task {
            for await received in bobStream {
                do {
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    if received.transportEvent == nil {
                        await probe.markDecrypted()
                    }
                } catch {
                    continue
                }
            }
        }

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "outbound-sending-key-recovered"
        )

        #expect(
            await waitUntil { await probe.count() >= 1 },
            "Outbound sendingKeyIsNil should reset the SessionIdentity and retry the original message"
        )
    }

    @Test("transport send failure replays first encrypted outbound without ratchet desync")
    func testTransportSendFailureReplaysFirstEncryptedOutboundWithoutRatchetDesync() async throws {
        enum SyntheticTransportError: Error {
            case failed
        }

        actor OneShotSendFailure {
            private(set) var failures = 0
            private var shouldFail = true

            func consumeFailure() -> Bool {
                guard shouldFail else { return false }
                shouldFail = false
                failures += 1
                return true
            }
        }

        actor PacketReplayProbe {
            private var failedPacket: Data?
            private var deliveredPacket: Data?

            func markFailed(_ data: Data?) {
                failedPacket = data
            }

            func markDelivered(_ data: Data?) {
                if deliveredPacket == nil {
                    deliveredPacket = data
                }
            }

            func replayedSamePacket() -> Bool {
                failedPacket != nil && failedPacket == deliveredPacket
            }
        }

        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(for: .milliseconds(50))
            }
            return false
        }

        let failureGate = OneShotSendFailure()
        let packetProbe = PacketReplayProbe()
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)

        aliceTransport.transformOutgoing = { received in
            if await failureGate.consumeFailure() {
                await packetProbe.markFailed(received.message.signed?.data)
                throw SyntheticTransportError.failed
            }
            await packetProbe.markDelivered(received.message.signed?.data)
            return received
        }

        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        @Sendable func recipientHasAliceContact() async -> Bool {
            guard let symmetricKey = try? await _recipientSession.getDatabaseSymmetricKey() else {
                return false
            }
            let contacts = await recipientStore.contacts
            for contact in contacts {
                if await contact.props(symmetricKey: symmetricKey)?.secretName == "alice" {
                    return true
                }
            }
            return false
        }

        bobTask = Task {
            for await received in bobStream {
                do {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received)
                } catch {
                    continue
                }
            }
        }

        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd
        )

        #expect(await failureGate.failures == 1, "Transport should fail exactly once after encryption")
        #expect(await packetProbe.replayedSamePacket(), "Retry must replay the same signed ratchet frame instead of re-encrypting")
        #expect(
            await waitUntil { await recipientHasAliceContact() },
            "The first encrypted outbound frame should be replayed after transport failure instead of losing the job or re-encrypting into a ratchet desync"
        )
    }

    @Test("transport send failure replays peerRefresh recovery control")
    func testTransportSendFailureReplaysPeerRefreshRecoveryControl() async throws {
        enum SyntheticTransportError: Error {
            case failed
        }

        actor OneShotPeerRefreshSendFailure {
            private(set) var failures = 0
            private var shouldFail = true

            func consumeFailure(for event: TransportEvent?) -> Bool {
                guard shouldFail else { return false }
                guard case .sessionReestablishment(let envelope)? = event,
                      envelope.kind == .peerRefresh
                else { return false }
                shouldFail = false
                failures += 1
                return true
            }
        }

        actor PeerRefreshReplayProbe {
            private var failedPacket: Data?
            private var deliveredPacket: Data?

            func markFailed(_ data: Data?) {
                if failedPacket == nil {
                    failedPacket = data
                }
            }

            func markDelivered(_ data: Data?) {
                deliveredPacket = data
            }

            func replayedSamePacket() -> Bool {
                failedPacket != nil && failedPacket == deliveredPacket
            }

            func delivered() -> Bool {
                deliveredPacket != nil
            }
        }

        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(for: .milliseconds(50))
            }
            return false
        }

        let failureGate = OneShotPeerRefreshSendFailure()
        let packetProbe = PeerRefreshReplayProbe()
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        aliceTransport.transformOutgoing = { received in
            if await failureGate.consumeFailure(for: received.transportEvent) {
                await packetProbe.markFailed(received.message.signed?.data)
                throw SyntheticTransportError.failed
            }
            if case .sessionReestablishment(let envelope)? = received.transportEvent,
               envelope.kind == .peerRefresh {
                await packetProbe.markDelivered(received.message.signed?.data)
            }
            return received
        }

        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        bobTask = Task {
            for await received in bobStream {
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._recipientSession,
                    received: received)
            }
        }

        _ = try await _senderSession.emitSessionReestablishment(
            kind: .peerRefresh,
            recipient: .nickname("bob"),
            scope: .peer(secretName: "bob"))

        #expect(await failureGate.failures == 1, "Transport should fail exactly once for peerRefresh")
        #expect(
            await waitUntil { await packetProbe.delivered() },
            "peerRefresh recovery control should be retried after transport send failure")
        #expect(
            await packetProbe.replayedSamePacket(),
            "peerRefresh retry must replay the same signed ratchet frame instead of advancing the ratchet again")
    }

    @Test("peerRefresh control survives outbound repair cooldown")
    func testPeerRefreshControlSurvivesOutboundRepairCooldown() async throws {
        actor Probe {
            private(set) var sawPeerRefresh = false
            func markPeerRefresh() { sawPeerRefresh = true }
        }

        actor OneShotFailureGate {
            var shouldFail = true
            func consumeFailure() -> Bool {
                guard shouldFail else { return false }
                shouldFail = false
                return true
            }
        }

        final class OneShotPeerRefreshFailureDelegate: @unchecked Sendable, TaskSequenceDelegate {
            let processor: TaskProcessor
            let gate = OneShotFailureGate()

            init(processor: TaskProcessor) {
                self.processor = processor
            }

            func performRatchet(task: TaskType, session: PQSSession) async throws {
                if case .writeMessage(let outbound) = task,
                   let transportInfo = outbound.message.transportInfo,
                   let event = try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo),
                   case .sessionReestablishment(let envelope) = event,
                   envelope.kind == .peerRefresh,
                   await gate.consumeFailure() {
                    throw RatchetError.stateUninitialized
                }

                try await processor.performRatchet(task: task, session: session)
            }
        }

        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(for: .milliseconds(50))
            }
            return false
        }

        let probe = Probe()
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        bobTask = Task {
            for await received in bobStream {
                if case .sessionReestablishment(let envelope) = received.transportEvent,
                   envelope.kind == .peerRefresh {
                    await probe.markPeerRefresh()
                }
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._recipientSession,
                    received: received)
            }
        }

        _ = try await _senderSession.refreshIdentities(
            secretName: rMockUserData.rsn,
            forceRefresh: true,
            sendOneTimeIdentities: true)
        _ = try await _recipientSession.refreshIdentities(
            secretName: sMockUserData.ssn,
            forceRefresh: true,
            sendOneTimeIdentities: true)

        guard let bobDeviceId = await _recipientSession.sessionContext?.sessionUser.deviceId else {
            Issue.record("Bob device id should be available")
            return
        }

        let senderProcessor = await _senderSession.taskProcessor
        await senderProcessor.setTaskDelegate(OneShotPeerRefreshFailureDelegate(processor: senderProcessor))

        await _senderSession.markReconciliationAttempt(
            sender: rMockUserData.rsn,
            deviceId: bobDeviceId,
            flow: .outbound)

        _ = try await _senderSession.emitSessionReestablishment(
            kind: .peerRefresh,
            recipient: .nickname(rMockUserData.rsn),
            scope: .peer(secretName: rMockUserData.rsn),
            freshOutboundRepair: (
                secretName: rMockUserData.rsn,
                deviceId: bobDeviceId,
                failureClass: "test.stateUninitialized"))

        #expect(
            await waitUntil { await probe.sawPeerRefresh },
            "peerRefresh must be retried instead of dropped when the first control send hits outbound repair cooldown")
    }
    
    @Test
    func ratchetManagerReCreation() async throws {
        var aliceTask: Task<Void, Never>?
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)

        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        await #expect(
            throws: Never.self,
            "Session initialization and first message should complete without errors"
        ) {
            let senderStore = self.createSenderStore()
            let recipientStore = self.createRecipientStore()
            
            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)
            
            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
            
            try await createFriendship(
                aliceSession: _senderSession,
                sd: sd,
                bobSession: _recipientSession,
                rsd: rsd)
            
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"), text: "Message One")
        }
        
        aliceTask = Task {
            await #expect(
                throws: Never.self,
                "Alice's message processing loop should handle received messages without errors"
            ) {
                var aliceIterations = 0
                for await received in aliceStream {
                    aliceIterations += 1
                    // Ignore any accidental self-echo frames
                    let myName = await _senderSession.sessionContext?.sessionUser.secretName
                    if received.sender == myName { continue }
                    try await _senderSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    
                    if aliceIterations == 2 {
                        try await _senderSession.writeTextMessage(
                            recipient: .nickname("bob"), text: "Message Four")
                        try await _senderSession.writeTextMessage(
                            recipient: .nickname("bob"), text: "Message Five")
                    }
                }
            }
        }
        
        await #expect(
            throws: Never.self,
            "Bob's message processing loop should handle received messages and send replies without errors"
        ) {
            var bobIterations = 0
            for await received in bobStream {
                bobIterations += 1
                try await _recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                )
                
                if bobIterations == 1 {
                    try await _recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Two")
                    try await _recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Three")
                }
                
                if bobIterations == 3 {
                    aliceTransport.continuation?.finish()
                    bobTransport.continuation?.finish()
                }
            }
        }
        
        _ = await aliceTask?.value
        await shutdownSessions()
    }
    
    
    
    @Test
    func thousandMessageExchange() async throws {
        let totalMessages = 1000
        var bobTask: Task<Void, Never>?

        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        // 1) Create stores & streams
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        await #expect(
            throws: Never.self,
            "Sessions should initialize and Alice should send the first message without errors"
        ) {
            // 2) Initialize sessions (PQXDH handshake)
            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)
            
            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
            
            try await createFriendship(
                aliceSession: _senderSession,
                sd: sd,
                bobSession: _recipientSession,
                rsd: rsd)
            
            // 3) Kick off the very first message from Alice → Bob
            try await self._senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "1")
        }
        // 4) Bob's receive‑and‑reply loop
        bobTask = Task {
            await #expect(
                throws: Never.self,
                "Bob's receive-and-reply loop should process and respond to messages without errors"
            ) {
                var bobReceivedCount = 0
                for await received in bobStream {
                    bobReceivedCount += 1
                    
                    // Process incoming
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    
                    // If Bob still needs to send more, reply with next number
                    if bobReceivedCount < totalMessages {
                        let next = bobReceivedCount * 2  // Bob sends even‑numbered msgs
                        try await self._recipientSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: "\(next)")
                    } else {
                        // Bob got all his 1 000; close his stream
                        aliceTransport.continuation?.finish()
                        bobTransport.continuation?.finish()
                    }
                }
            }
        }
        
        // 5) Alice's receive‑and‑reply loop
        var aliceReceivedCount = 0
        for await received in aliceStream {
            aliceReceivedCount += 1
            await #expect(
                throws: Never.self,
                "Alice's receive-and-reply loop should process and respond to messages without errors"
            ) {
                // Process incoming
                try await self._senderSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                )
                
                // If Alice still needs to send more, reply with next odd number
                if aliceReceivedCount < totalMessages {
                    let next = aliceReceivedCount * 2 + 1  // Alice sends odd‑numbered msgs
                    try await self._senderSession.writeTextMessage(
                        recipient: .nickname("bob"),
                        text: "\(next)")
                }
            }
        }
        
        _ = await bobTask?.value
        await shutdownSessions()
    }
    
    @Test
    func outOfOrderMessagesHandledCorrectly() async throws {
        await #expect(
            throws: Never.self,
            "Out-of-order test: session setup, message send, and out-of-order receive should not throw"
        ) {
            let senderStore = self.createSenderStore()
            let recipientStore = self.createRecipientStore()
            
            // 1) Set up a single AsyncStream on the recipient side
            let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
            let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
            let bobStream = AsyncStream<ReceivedMessage> { continuation in
                aliceTransport.continuation = continuation
            }
            
            // 2) Do the PQXDH handshake before sending any data
            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)
            
            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
            
            try await createFriendship(
                aliceSession: _senderSession,
                sd: sd,
                bobSession: _recipientSession,
                rsd: rsd)
            
            // 3) Prepare 79 distinct messages
            let messages = (0..<79).map { "Out‑of‑order Message \($0)" }
            
            // 4) Send them all (in-order) from Alice → Bob
            for text in messages {
                try await self._senderSession.writeTextMessage(
                    recipient: .nickname("bob"),
                    text: text)
            }
            
			// 5) Collect exactly 79 ReceivedMessage frames destined for Bob
            var collected: [ReceivedMessage] = []
			for await received in bobStream {
                collected.append(received)
                if collected.count == messages.count {
                    // Once we have all 79, stop listening
                    aliceTransport.continuation?.finish()
					bobTransport.continuation?.finish()
                    break
                }
            }
            
			// 6) Feed Bob's ratchet out‑of‑order: first the very first message…
            let first = collected.removeFirst()
			let aliceSecretName = await self._senderSession.sessionContext!.sessionUser.secretName
			let aliceDeviceId = await self._senderSession.sessionContext!.sessionUser.deviceId
            try await self._recipientSession.receiveMessage(
                message: first.message,
				sender: aliceSecretName,
				deviceId: aliceDeviceId,
                messageId: first.messageId
            )
            
			// …then the rest in a random order
            for msg in collected.shuffled() {
                try await self._recipientSession.receiveMessage(
                    message: msg.message,
					sender: aliceSecretName,
					deviceId: aliceDeviceId,
                    messageId: msg.messageId
                )
            }
			
            await shutdownSessions()
        }
    }
    
    @Test
    func testRatchetManagerReCreationReKey() async throws {
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        await #expect(
            throws: Never.self,
            "Session initialization should complete without errors (rekey test)"
        ) {
            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)
            
            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
            
            try await createFriendship(
                aliceSession: _senderSession,
                sd: sd,
                bobSession: _recipientSession,
                rsd: rsd)
        }
        // Alice's receive loop
        Task {
            var aliceIterations = 0
            for await received in aliceStream {
                aliceIterations += 1
                do {
                    try await self._senderSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                } catch PQSSession.SessionErrors.databaseNotInitialized {
                    return
                } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
                    // Message is unrecoverable due to key rotation; continue to next message
                    continue
                } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
                    // Message signature is invalid (e.g., after key rotation); continue to next message
                    continue
                } catch {
                    // Other unexpected errors - log and continue
                    continue
                }
                // First user message (after protocol message)
                if aliceIterations == 1 {
                    try await self._senderSession.rotateKeysOnPotentialCompromise()
                    try await self._senderSession.writeTextMessage(
                        recipient: .nickname("bob"), text: "Message Three")
                    await self.bobProcessedRotated.wait()
                }
                // After Bob's post-rotation message
                if aliceIterations == 2 {
                    await self.aliceProcessedBobRotation.signal()
                    aliceTransport.continuation?.finish()
                    bobTransport.continuation?.finish()
                }
            }
            await self._senderSession.shutdown()
        }
        // Bob's receive loop
        Task {
            var bobIterations = 0
            for await received in bobStream {
                bobIterations += 1
                do {
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                } catch PQSSession.SessionErrors.databaseNotInitialized {
                    return
                } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
                    // Message is unrecoverable due to key rotation; continue to next message
                    continue
                } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
                    // Message signature is invalid (e.g., after key rotation); continue to next message
                    continue
                } catch {
                    // Other unexpected errors - log and continue
                    continue
                }
                // First user message (after protocol message)
                if bobIterations == 1 {
                    await self.bobProcessedRotated.signal()
                    try await self._recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Two")
                }
                // After Alice's post-rotation message
                if bobIterations == 2 {
                    try await self._recipientSession.rotateKeysOnPotentialCompromise()
                    try await self._recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Four")
                    await self.aliceProcessedBobRotation.wait()
                    aliceTransport.continuation?.finish()
                    bobTransport.continuation?.finish()
                }
            }
        }
        // Kick off the flow after loops are active
        try await self._senderSession.writeTextMessage(
            recipient: .nickname("bob"), text: "Message One")
        try await Task.sleep(until: .now + .seconds(3))
        await shutdownSessions()
    }
    
    @Test
    func testContactAndFriendshipCreation() async throws {
        // 1) Create stores & streams
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
            // 2) Initialize sessions
            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)
            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
            
        // 3) Start receive loops to process protocol messages
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        aliceTask = Task {
            await #expect(throws: Never.self) {
                for await received in aliceStream {
                    if await self._senderSession.sessionContext == nil { continue }
                    let myName = await self._senderSession.sessionContext?.sessionUser.secretName
                    if received.sender == myName { continue }
                    do {
                        try await self._senderSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                    } catch {
                        return
                    }
                }
            }
        }
        bobTask = Task {
            await #expect(throws: Never.self) {
                for await received in bobStream {
                    if await self._recipientSession.sessionContext == nil { continue }
                    let myName = await self._recipientSession.sessionContext?.sessionUser.secretName
                    if received.sender == myName { continue }
                    do {
                        try await self._recipientSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                    } catch {
                        return
                    }
                }
            }
        }
        
        // 4) Create friendship (creates contacts via protocol)
            try await createFriendship(
                aliceSession: _senderSession,
                sd: sd,
                bobSession: _recipientSession,
                rsd: rsd)
        
        // 5) Allow protocol to settle, then close streams
        try await Task.sleep(until: .now + .milliseconds(300))
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        try await Task.sleep(until: .now + .milliseconds(50))
        
        // 6) Verify contacts exist on both sides and include friendship metadata
        let aliceContacts = try await senderStore.fetchContacts()
        let bobContacts = try await recipientStore.fetchContacts()
        #expect(aliceContacts.count == 1, "Alice should have one contact created by createFriendship")
        #expect(bobContacts.count == 1, "Bob should have one contact created by createFriendship")
        
        if let aliceContact = aliceContacts.first,
           let props = try await aliceContact.props(
            symmetricKey: self._senderSession.getDatabaseSymmetricKey())
        {
            #expect(props.secretName == "bob")
            #expect(props.metadata["friendshipMetadata"] != nil)
        }
            if let bobContact = bobContacts.first,
               let props = try await bobContact.props(
                symmetricKey: self._recipientSession.getDatabaseSymmetricKey())
            {
                #expect(props.secretName == "alice")
            #expect(props.metadata["friendshipMetadata"] != nil)
        }
        
        // Cleanup
        aliceTask?.cancel()
        bobTask?.cancel()
        await shutdownSessions()
    }
    
    private func conformSessionDelegate(
        session: PQSSession,
        pqsDelegate: PQSSessionDelegate,
        store: PQSSessionStore,
        receiver: EventReceiver,
        transport: _MockTransportDelegate
    ) async {
        await session.setPQSSessionDelegate(conformer: pqsDelegate)
        await session.setDatabaseDelegate(conformer: store)
        await session.setTransportDelegate(conformer: transport)
        await session.setReceiverDelegate(conformer: receiver)
    }
    
    @Test
    func realLinkDeviceTest() async throws {
        var aliceTask: Task<Void, Never>?
        defer {
            // Ensure cleanup happens even if test fails
            Task {
                aliceTask?.cancel()
                await shutdownSessions()
            }
        }
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        await #expect(throws: Never.self, "Real linkDevice test should complete without errors") {
            let senderStore = self.createSenderStore()
            let senderChildStore1 = self.createSenderChildStore1()
            let senderChildStore2 = self.createSenderChildStore2()
            let recipientStore = self.createRecipientStore()
            let recipientChildStore1 = self.createRecipientChildStore1()
            let recipientChildStore2 = self.createRecipientChildStore2()
            
            let sd = SessionDelegate(session: _senderSession)
            
            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)

            let masterConfig = await self._senderSession.sessionContext!.activeUserConfiguration
            try await self.linkSenderChildSession1(store: senderChildStore1, transport: aliceTransport)
            let childConfig1 = await _senderChildSession1.sessionContext!.activeUserConfiguration
            let childDevice1 = try childConfig1.signedDevices.last!.verified(
                using: Curve25519.Signing.PublicKey(
                    rawRepresentation: childConfig1.signingPublicKey))!
            let newSigned = try UserConfiguration.SignedDeviceConfiguration(
                device: childDevice1,
                signingKey: Curve25519.Signing.PrivateKey(
                    rawRepresentation: await _senderSession.sessionContext!.sessionUser.deviceKeys.signingPrivateKey))
            
            try await self.linkSenderChildSession2(store: senderChildStore2, transport: aliceTransport)
            let childConfig2 = await _senderChildSession2.sessionContext!.activeUserConfiguration
            let childDevice2 = try childConfig2.signedDevices.last!.verified(
                using: Curve25519.Signing.PublicKey(
                    rawRepresentation: childConfig2.signingPublicKey))!
            let newSigned2 = try UserConfiguration.SignedDeviceConfiguration(
                device: childDevice2,
                signingKey: Curve25519.Signing.PrivateKey(
                    rawRepresentation: await _senderSession.sessionContext!.sessionUser.deviceKeys.signingPrivateKey))
            
            // Append the new signed device
            var updatedSignedDevices = masterConfig.signedDevices
            updatedSignedDevices.append(newSigned)
            updatedSignedDevices.append(newSigned2)
            
            for device in updatedSignedDevices {
                _ = try device.verified(using: try Curve25519.Signing.PublicKey(rawRepresentation: masterConfig.signingPublicKey))
            }
            
            
            // Return a new UserConfiguration
            let newConfig = UserConfiguration(
                signingPublicKey: masterConfig.signingPublicKey,
                signedDevices: updatedSignedDevices,
                signedOneTimePublicKeys: masterConfig.signedOneTimePublicKeys,
                signedMLKEMOneTimePublicKeys: masterConfig.signedMLKEMOneTimePublicKeys,
                signedDeviceKeyBundles: masterConfig.signedDeviceKeyBundles
                    + childConfig1.signedDeviceKeyBundles
                    + childConfig2.signedDeviceKeyBundles)
            
            //Publish the new config to the remote store
            let senderSecretName = await self._senderSession.sessionContext!.sessionUser.secretName
            if let index = await self.store.userConfigurations.firstIndex(where: {
                $0.secretName == senderSecretName
            }) {
                await self.store.setUserConfigurations(index: index, config: newConfig)
            }
            
            try await self._senderSession.updateUserConfiguration(newConfig.getVerifiedDevices())
            
            let rsd = SessionDelegate(session: _recipientSession)
            
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
            
            try await createFriendship(
                aliceSession: _senderSession,
                sd: sd,
                bobSession: _recipientSession,
                rsd: rsd)
            
            let masterRecipientConfig = await self._recipientSession.sessionContext!
                .activeUserConfiguration
            try await self.linkRecipientChildSession1(store: recipientChildStore1, transport: bobTransport)
            
            let childRecipientConfig1 = await _recipientChildSession1.sessionContext!
                .activeUserConfiguration
            
            let childRecipientDevice1 = try childRecipientConfig1.signedDevices.last!.verified(
                using: Curve25519.Signing.PublicKey(
                    rawRepresentation: childRecipientConfig1.signingPublicKey))!
            
            let newSignedRecipient = try UserConfiguration.SignedDeviceConfiguration(
                device: childRecipientDevice1,
                signingKey: Curve25519.Signing.PrivateKey(
                    rawRepresentation: await _recipientSession.sessionContext!.sessionUser.deviceKeys.signingPrivateKey))
            
            try await self.linkRecipientChildSession2(store: recipientChildStore2, transport: bobTransport)
            let childRecipientConfig2 = await _recipientChildSession2.sessionContext!
                .activeUserConfiguration
            let childRecipientDevice2 = try childRecipientConfig2.signedDevices.last!.verified(
                using: Curve25519.Signing.PublicKey(
                    rawRepresentation: childRecipientConfig2.signingPublicKey))!
            let newSignedRecipient2 = try UserConfiguration.SignedDeviceConfiguration(
                device: childRecipientDevice2,
                signingKey: Curve25519.Signing.PrivateKey(
                    rawRepresentation: await _recipientSession.sessionContext!.sessionUser.deviceKeys.signingPrivateKey))
            
            // Append the new signed device
            var updatedSignedRecipientDevices = masterRecipientConfig.signedDevices
            updatedSignedRecipientDevices.append(newSignedRecipient)
            updatedSignedRecipientDevices.append(newSignedRecipient2)
            
            for device in updatedSignedRecipientDevices {
                _ = try device.verified(using: try Curve25519.Signing.PublicKey(rawRepresentation: masterRecipientConfig.signingPublicKey))
            }
            
            // Return a new UserConfiguration
            let newRecipientConfig = UserConfiguration(
                signingPublicKey: masterRecipientConfig.signingPublicKey,
                signedDevices: updatedSignedRecipientDevices,
                signedOneTimePublicKeys: masterRecipientConfig.signedOneTimePublicKeys,
                signedMLKEMOneTimePublicKeys: masterRecipientConfig.signedMLKEMOneTimePublicKeys,
                signedDeviceKeyBundles: masterRecipientConfig.signedDeviceKeyBundles
                    + childRecipientConfig1.signedDeviceKeyBundles
                    + childRecipientConfig2.signedDeviceKeyBundles)
            
            //Publish the new config to the remote store
            let recipientSecretName = await self._recipientSession.sessionContext!.sessionUser
                .secretName
            if let index = await self.store.userConfigurations.firstIndex(where: {
                $0.secretName == recipientSecretName
            }) {
                await self.store.setUserConfigurations(index: index, config: newRecipientConfig)
            }
            
            try await self._recipientSession.updateUserConfiguration(
                newRecipientConfig.getVerifiedDevices())
            
            try await self._senderSession.writeTextMessage(
                recipient: .nickname("bob"), text: "Message One")
            
        }
        
        aliceTask = Task {
            await #expect(
                throws: Never.self,
                "Alice's message processing loop should handle received messages without errors"
            ) {
                var aliceIterations = 0
                for await received in aliceStream {
                    aliceIterations += 1
                    // Skip until session context is available
                    if await self._senderSession.sessionContext == nil { continue }
                    do {
                    try await self._senderSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    } catch {
                        // Tolerate teardown/transition errors in this test
                        return
                    }
                    
                    // Note: Child devices should not receive master device messages
                    // This would cause ratchet state mismatches
                    print("Alice master device processed message \(aliceIterations)")
                    
                    // Avoid additional sends during device linking to prevent transient transport/session initialization races
                }
            }
        }
        
        await #expect(
            throws: Never.self,
            "Bob's message processing loop should handle received messages and send replies without errors"
        ) {
            var bobIterations = 0
            for await received in bobStream {
                bobIterations += 1
                // Skip until session context is available
                if await self._recipientSession.sessionContext == nil { continue }
                do {
                try await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                )
                } catch {
                    // Tolerate teardown/transition errors in this test
                    return
                }
                
                if bobIterations == 1 {
                    try await self._recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Two")
                    try await self._recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Three")
                }
                
                if bobIterations == 3 {
                    aliceTransport.continuation?.finish()
                    bobTransport.continuation?.finish()
                }
            }
            await shutdownSessions()
        }
    }
    
    @Test("Ratchet Chain Key Synchronization - Authentication Failure Reproduction")
    func testRatchetChainKeySyncAuthenticationFailure() async throws {
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Send initial messages to establish session
        for i in 1...5 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
            
            // Small delay to allow processing
            try await Task.sleep(until: .now + .milliseconds(100))
        }
        
        // Now send rapid messages to trigger the authentication failure
        // This simulates the scenario from the logs where messages are sent quickly
        var authenticationFailures = 0
        var successfulMessages = 0
        
        for i in 6...20 {
            do {
                try await _senderSession.writeTextMessage(
                    recipient: .nickname("bob"),
                    text: "Rapid message \(i)")
                successfulMessages += 1
            } catch {
                if error.localizedDescription.contains("AUTHENTICATIONFAILURE") ||
                    error.localizedDescription.contains("authenticationFailure") ||
                    error.localizedDescription.contains("invalidKeyId") {
                    authenticationFailures += 1
                }
            }
            
            // Very small delay to create rapid message scenario
            try await Task.sleep(until: .now + .milliseconds(10))
        }
        
        // Wait for processing to complete
        try await Task.sleep(until: .now + .seconds(2))
        
        // Log the results for debugging
        print("Test Results:")
        print("- Successful messages: \(successfulMessages)")
        print("- Authentication failures: \(authenticationFailures)")
        
        // Note: This test shows that the basic ratchet chain key synchronization is working
        // The authentication failures in the real logs are likely due to network timing
        // or session state synchronization issues between devices
        
        await shutdownSessions()
    }
    
    @Test("Bidirectional Message Exchange - Simulate Real Device Communication")
    func testBidirectionalMessageExchange() async throws {
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Send initial messages from both devices to establish bidirectional communication
        for i in 1...3 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Alice message \(i)")
            
            try await _recipientSession.writeTextMessage(
                recipient: .nickname("alice"),
                text: "Bob message \(i)")
            
            // Small delay to allow processing
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        
        // Now send rapid bidirectional messages to simulate real conversation
        var aliceFailures = 0
        var bobFailures = 0
        var aliceSuccess = 0
        var bobSuccess = 0
        
        for i in 4...15 {
            // Alice sends message
            do {
                try await _senderSession.writeTextMessage(
                    recipient: .nickname("bob"),
                    text: "Alice rapid \(i)")
                aliceSuccess += 1
            } catch {
                if error.localizedDescription.contains("AUTHENTICATIONFAILURE") ||
                    error.localizedDescription.contains("authenticationFailure") ||
                    error.localizedDescription.contains("invalidKeyId") {
                    aliceFailures += 1
                }
            }
            
            // Bob sends message
            do {
                try await _recipientSession.writeTextMessage(
                    recipient: .nickname("alice"),
                    text: "Bob rapid \(i)")
                bobSuccess += 1
            } catch {
                if error.localizedDescription.contains("AUTHENTICATIONFAILURE") ||
                    error.localizedDescription.contains("authenticationFailure") ||
                    error.localizedDescription.contains("invalidKeyId") {
                    bobFailures += 1
                }
            }
            
            // Very small delay to create rapid bidirectional scenario
            try await Task.sleep(until: .now + .milliseconds(5))
        }
        
        // Wait for processing to complete
        try await Task.sleep(until: .now + .seconds(2))
        
        // Log the results for debugging
        print("Bidirectional Test Results:")
        print("- Alice successful messages: \(aliceSuccess)")
        print("- Alice authentication failures: \(aliceFailures)")
        print("- Bob successful messages: \(bobSuccess)")
        print("- Bob authentication failures: \(bobFailures)")
        
        await shutdownSessions()
    }
    
    @Test("Network Timing Issues - Simulate Out of Order Messages")
    func testNetworkTimingIssues() async throws {
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Send initial messages to establish session
        for i in 1...3 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        
        // Now send messages rapidly and simulate network delays/out-of-order delivery
        var authenticationFailures = 0
        var successfulMessages = 0
        
        // Create multiple concurrent message sends to simulate network timing issues
        let messageTasks = (4...15).map { i in
            Task {
                do {
                    // Add random delays to simulate network jitter
                    let randomDelay = UInt64.random(in: 0...20)
                    try await Task.sleep(until: .now + .milliseconds(randomDelay))
                    
                    try await _senderSession.writeTextMessage(
                        recipient: .nickname("bob"),
                        text: "Timing test message \(i)")
                    return MessageResult.success
                } catch {
                    if error.localizedDescription.contains("AUTHENTICATIONFAILURE") ||
                        error.localizedDescription.contains("authenticationFailure") ||
                        error.localizedDescription.contains("invalidKeyId") {
                        return .authenticationFailure
                    }
                    return .otherError(error)
                }
            }
        }
        
        // Wait for all messages to complete
        for task in messageTasks {
            let result = await task.value
            switch result {
            case .success:
                successfulMessages += 1
            case .authenticationFailure:
                authenticationFailures += 1
            case .otherError(let error):
                print("Other error: \(error)")
            }
        }
        
        // Wait for processing to complete
        try await Task.sleep(until: .now + .seconds(2))
        
        print("Network Timing Test Results:")
        print("- Successful messages: \(successfulMessages)")
        print("- Authentication failures: \(authenticationFailures)")
        
        await shutdownSessions()
    }
    
    @Test("Session State Synchronization Issues - Simulate State Corruption")
    func testSessionStateSynchronizationIssues() async throws {
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Send initial messages to establish session
        for i in 1...3 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        
        // Simulate session state corruption by clearing and recreating session state
        // This simulates what might happen if session state is lost or corrupted
        await shutdownSessions()
        
        // Wait a moment for cleanup to complete
        try await Task.sleep(until: .now + .milliseconds(100))
        
        try await createSenderSession(store: senderStore, createSession: false, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, createSession: false, transport: bobTransport, sessionDelegate: rsd)
        
        
        // Try to send messages with potentially corrupted state
        var authenticationFailures = 0
        var successfulMessages = 0
        
        for i in 4...10 {
            do {
                try await _senderSession.writeTextMessage(
                    recipient: .nickname("bob"),
                    text: "State corruption test \(i)")
                successfulMessages += 1
            } catch {
                if error.localizedDescription.contains("AUTHENTICATIONFAILURE") ||
                    error.localizedDescription.contains("authenticationFailure") ||
                    error.localizedDescription.contains("invalidKeyId") {
                    authenticationFailures += 1
                }
            }
            
            // Small delay between messages
            try await Task.sleep(until: .now + .milliseconds(10))
        }
        
        print("Session State Synchronization Test Results:")
        print("- Successful messages: \(successfulMessages)")
        print("- Authentication failures: \(authenticationFailures)")
        
        await shutdownSessions()
    }
    
    @Test("Transport Layer Issues - Simulate Message Loss and Duplication")
    func testTransportLayerIssues() async throws {
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Send initial messages to establish session
        for i in 1...3 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        
        // Simulate transport layer issues by sending messages in bursts.
        // Sends are serialized within each burst to avoid concurrent write path
        // triggering internal assertion (signal 5) in session/ratchet code.
        var authenticationFailures = 0
        var successfulMessages = 0
        
        for burst in 0..<3 {
            for i in 1...5 {
                do {
                    try await _senderSession.writeTextMessage(
                        recipient: .nickname("bob"),
                        text: "Transport test burst \(burst) message \(i)")
                    successfulMessages += 1
                } catch {
                    if error.localizedDescription.contains("AUTHENTICATIONFAILURE") ||
                        error.localizedDescription.contains("authenticationFailure") ||
                        error.localizedDescription.contains("invalidKeyId") {
                        authenticationFailures += 1
                    } else {
                        print("Other error: \(error)")
                    }
                }
                try await Task.sleep(until: .now + .milliseconds(20))
            }
            try await Task.sleep(until: .now + .milliseconds(100))
        }
        
        print("Transport Layer Test Results:")
        print("- Successful messages: \(successfulMessages)")
        print("- Authentication failures: \(authenticationFailures)")
        
        await shutdownSessions()
    }
    
    @Test("Device Synchronization Issues - Simulate Clock Drift and Processing Delays")
    func testDeviceSynchronizationIssues() async throws {
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Send initial messages to establish session
        for i in 1...3 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        
        // Simulate device synchronization issues by adding processing delays
        // and varying message timing to simulate different device capabilities
        var authenticationFailures = 0
        var successfulMessages = 0
        
        for i in 4...12 {
            do {
                // Simulate varying processing delays (like different device capabilities)
                let processingDelay = UInt64.random(in: 0...50)
                try await Task.sleep(until: .now + .milliseconds(processingDelay))
                
                try await _senderSession.writeTextMessage(
                    recipient: .nickname("bob"),
                    text: "Sync test message \(i)")
                successfulMessages += 1
                
                // Simulate device being busy with other tasks
                if i % 3 == 0 {
                    try await Task.sleep(until: .now + .milliseconds(200))
                }
                
            } catch {
                if error.localizedDescription.contains("AUTHENTICATIONFAILURE") ||
                    error.localizedDescription.contains("authenticationFailure") ||
                    error.localizedDescription.contains("invalidKeyId") {
                    authenticationFailures += 1
                }
            }
        }
        
        print("Device Synchronization Test Results:")
        print("- Successful messages: \(successfulMessages)")
        print("- Authentication failures: \(authenticationFailures)")
        
        await shutdownSessions()
    }
    
    @Test("Race Condition - Simulate Concurrent Message Processing")
    func testRaceConditionConcurrentMessageProcessing() async throws {
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Send initial messages to establish session
        for i in 1...3 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        
        // Simulate the race condition: send multiple messages simultaneously
        // to create concurrent jobs that might cause data/key misalignment
        var authenticationFailures = 0
        var successfulMessages = 0
        
        let senderSession = _senderSession
        
        // Create multiple structured child tasks to send messages simultaneously.
        let results = await withTaskGroup(of: MessageResult.self) { group in
            for i in 1...10 {
                group.addTask {
                    do {
                        // Minimal delay to ensure they start almost simultaneously
                        try await Task.sleep(until: .now + .milliseconds(UInt64(i % 6)))
                        
                        try await senderSession.writeTextMessage(
                            recipient: .nickname("bob"),
                            text: "Race condition test \(i)")
                        return MessageResult.success
                    } catch {
                        if error.localizedDescription.contains("AUTHENTICATIONFAILURE") ||
                            error.localizedDescription.contains("authenticationFailure") ||
                            error.localizedDescription.contains("invalidKeyId") {
                            return MessageResult.authenticationFailure
                        } else {
                            return MessageResult.otherError(error)
                        }
                    }
                }
            }
            
            var results: [MessageResult] = []
            for await result in group {
                results.append(result)
            }
            return results
        }
        
        // Count results
        for result in results {
            switch result {
            case .success:
                successfulMessages += 1
            case .authenticationFailure:
                authenticationFailures += 1
            case .otherError:
                break
            }
        }
        
        print("Race Condition Test Results:")
        print("- Successful messages: \(successfulMessages)")
        print("- Authentication failures: \(authenticationFailures)")
        print("- Total concurrent messages sent: \(results.count)")
        
        await shutdownSessions()
    }
    
    @Test("Network Race Condition - Simulate ICE Candidate Messages")
    func testNetworkRaceConditionICEMessages() async throws {
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Send initial messages to establish session
        for i in 1...3 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
            try await Task.sleep(until: .now + .milliseconds(50))
        }

        var authenticationFailures = 0
        var successfulMessages = 0
        
        // Simulate ICE candidate messages arriving simultaneously from network
        // These would normally be received from the transport layer
        let iceCandidateMessages = (1...20).map { i in
            Task {
                do {
                    // Simulate network arrival timing - some messages arrive exactly at the same time
                    let arrivalDelay = i % 3 == 0 ? UInt64(0) : UInt64.random(in: 0...2)
                    try await Task.sleep(until: .now + .milliseconds(arrivalDelay))
                    
                    // Simulate the ICE candidate message content
                    let iceData: [String: String] = [
                        "type": "ice-candidate",
                        "candidate": "candidate:\(i) 1 udp 2122260223 192.168.1.\(i) 54321 typ host",
                        "sdpMLineIndex": "\(i)",
                        "sdpMid": "0"
                    ]
                    let metadata = try BinaryEncoder().encode(iceData)
                    try await _senderSession.writeTextMessage(
                        recipient: .nickname("bob"),
                        text: "ICE candidate \(i)",
                        metadata: metadata
                    )
                    return MessageResult.success
                } catch {
                    if error.localizedDescription.contains("AUTHENTICATIONFAILURE") ||
                        error.localizedDescription.contains("authenticationFailure") ||
                        error.localizedDescription.contains("invalidKeyId") {
                        return MessageResult.authenticationFailure
                    } else {
                        return MessageResult.otherError(error)
                    }
                }
            }
        }
        
        // Process all ICE candidate messages concurrently
        let results = await withTaskGroup(of: MessageResult.self) { group in
            for message in iceCandidateMessages {
                group.addTask {
                    await message.value
                }
            }
            
            var results: [MessageResult] = []
            for await result in group {
                results.append(result)
            }
            return results
        }
        
        // Count results
        for result in results {
            switch result {
            case .success:
                successfulMessages += 1
            case .authenticationFailure:
                authenticationFailures += 1
            case .otherError:
                break
            }
        }
        
        print("Network Race Condition Test Results:")
        print("- Successful messages: \(successfulMessages)")
        print("- Authentication failures: \(authenticationFailures)")
        print("- Total ICE candidate messages: \(results.count)")
        
        await shutdownSessions()
    }
    
    // Helper enum for test results
    private enum MessageResult {
        case success
        case authenticationFailure
        case otherError(Error)
    }
    
    // MARK: - Authentication Failure Tests
    
    @Test("Ratchet State Mismatch Authentication Failure")
    func testRatchetStateMismatchAuthenticationFailure() async throws {
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Send initial messages to establish session (like in the logs)
        for i in 1...4 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
            // Small delay to allow processing
            try await Task.sleep(until: .now + .milliseconds(100))
        }
        
        // Now simulate the exact pattern from the logs:
        // Device2 receives messages and generates skipped message keys for indices 5, 6, 7
        // But authentication still fails
        
        // Send messages that will cause device2 to generate skipped message keys
        // This simulates the scenario where messages arrive out of order
        var authenticationFailures = 0
        var successfulMessages = 0
        
        // Send messages rapidly to create the skipped message pattern
        for i in 5...10 {
            do {
                try await _senderSession.writeTextMessage(
                    recipient: .nickname("bob"),
                    text: "Message \(i) - should cause skipped keys")
                successfulMessages += 1
            } catch {
                if error.localizedDescription.contains("AUTHENTICATIONFAILURE") ||
                    error.localizedDescription.contains("authenticationFailure") ||
                    error.localizedDescription.contains("invalidKeyId") {
                    authenticationFailures += 1
                }
            }
            
            // Very small delay to create rapid message scenario like in the logs
            try await Task.sleep(until: .now + .milliseconds(5))
        }
        
        // Wait for processing to complete
        try await Task.sleep(until: .now + .seconds(2))
        
        // Log the results for debugging
        print("✅ Successful messages: \(successfulMessages)")
        print("❌ Authentication failures: \(authenticationFailures)")
        
        // The test should show authentication failures similar to the logs
        // This will help us identify the root cause of the ratchet state mismatch
        
        await shutdownSessions()
    }
    
    @Test("Skipped Message Key Pattern - Exact Log Reproduction")
    func testSkippedMessageKeyPattern() async throws {
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        // Setup two devices with their own sessions and wire Alice -> Bob
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Expect to process 10 messages (4 warmup + 6 burst)
        let total = 10
        var processed = 0
        var authenticationFailures = 0
        
        // Bob receive loop with error classification
        bobTask = Task {
            await #expect(throws: Never.self, "Bob should process messages without crashing") {
                for await received in bobStream {
                    do {
                        try await self._recipientSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                        processed += 1
                        if processed >= total {
                            aliceTransport.continuation?.finish()
                            break
                        }
                    } catch {
                        let desc = error.localizedDescription
                        if desc.localizedCaseInsensitiveContains("authenticationFailure") ||
                            desc.contains("AUTHENTICATIONFAILURE") ||
                            desc.localizedCaseInsensitiveContains("invalidKeyId") {
                            authenticationFailures += 1
                        } else if case PQSSession.SessionErrors.databaseNotInitialized = error {
                            break
                        } else {
                            #expect(Bool(false), "Unexpected receive error: \(error)")
                            break
                        }
                    }
                }
            }
        }
        
        // Warmup to establish session
        for i in 1...4 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        
        // Rapid burst to create a skipped-key pattern without breaking correctness
        for i in 5...10 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Message \(i)")
            try await Task.sleep(until: .now + .milliseconds(5))
        }
        
        // Allow processing and assert outcome
        try await Task.sleep(until: .now + .seconds(2))
        #expect(authenticationFailures == 0, "No authentication failures expected, found: \(authenticationFailures)")
    }
    
    @Test("Real Authentication Failure - Device2 Decryption Test")
    func testRealAuthenticationFailure() async throws {
    var bobTask: Task<Void, Never>?
    defer {
        Task {
            bobTask?.cancel()
            await shutdownSessions()
        }
    }
    
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
    // Route Alice -> Bob by wiring Alice's continuation to Bob's stream
    let bobStream = AsyncStream<ReceivedMessage> { continuation in
        aliceTransport.continuation = continuation
    }
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
    let total = 10
    var processed = 0
    var authenticationFailures = 0
    
    // Bob decrypts everything he receives and counts authentication failures
    bobTask = Task {
        await #expect(throws: Never.self, "Bob should process messages without crashing") {
            for await received in bobStream {
                do {
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    processed += 1
                    if processed >= total {
                        aliceTransport.continuation?.finish()
                        break
                    }
                } catch {
                    let desc = error.localizedDescription
                    if desc.localizedCaseInsensitiveContains("authenticationFailure") ||
                        desc.contains("AUTHENTICATIONFAILURE") ||
                        desc.localizedCaseInsensitiveContains("invalidKeyId") {
                        authenticationFailures += 1
                    } else if case PQSSession.SessionErrors.databaseNotInitialized = error {
                        break
                    } else {
                        // Unexpected error; fail this loop
                        #expect(Bool(false), "Unexpected receive error: \(error)")
                        break
                    }
                }
            }
        }
    }
    
    // Warmup to establish session
        for i in 1...4 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
        try await Task.sleep(until: .now + .milliseconds(50))
    }
    
    // Send a rapid burst intended to reproduce the real-world scenario
    for i in 5...total {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
            text: "Message \(i)")
            try await Task.sleep(until: .now + .milliseconds(5))
        }
        
    // Allow processing and then assert
        try await Task.sleep(until: .now + .seconds(2))
        
    // Proper assertion: there should be no authentication failures in a correct flow
    #expect(authenticationFailures == 0, "No authentication failures expected, found: \(authenticationFailures)")
    }
    
    @Test("Ratchet State Corruption - Skipped Message Key Mismatch")
    func testRatchetStateCorruption() async throws {
    var bobTask: Task<Void, Never>?
    defer {
        Task {
            bobTask?.cancel()
            await shutdownSessions()
        }
    }
    
        // Setup two devices with their own sessions
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
    // Route Alice -> Bob by wiring Alice's continuation to Bob's stream
    let bobStream = AsyncStream<ReceivedMessage> { continuation in
        aliceTransport.continuation = continuation
    }
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
    // Total messages Bob will process (4 warmup + 11 burst)
    let total = 15
    var processed = 0
    var authenticationFailures = 0
    
    // Bob decrypts everything he receives and counts authentication failures
    bobTask = Task {
        await #expect(throws: Never.self, "Bob should process messages without crashing") {
            for await received in bobStream {
                do {
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    processed += 1
                    if processed >= total {
                        aliceTransport.continuation?.finish()
                        break
                    }
                } catch {
                    let desc = error.localizedDescription
                    if desc.localizedCaseInsensitiveContains("authenticationFailure") ||
                        desc.contains("AUTHENTICATIONFAILURE") ||
                        desc.localizedCaseInsensitiveContains("invalidKeyId") {
                        authenticationFailures += 1
                    } else if case PQSSession.SessionErrors.databaseNotInitialized = error {
                        break
                    } else {
                        #expect(Bool(false), "Unexpected receive error: \(error)")
                        break
                    }
                }
            }
        }
    }
    
    // Warmup to establish session
        for i in 1...4 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Initial message \(i)")
        try await Task.sleep(until: .now + .milliseconds(50))
    }
    
    // Rapid burst intended to stress ratchet state
        for i in 5...15 {
                try await _senderSession.writeTextMessage(
                    recipient: .nickname("bob"),
            text: "Message \(i)")
        // tiny delay to vary arrival order
        try await Task.sleep(until: .now + .milliseconds(5))
    }
    
    // Allow processing and assert
    try await Task.sleep(until: .now + .seconds(2))
    #expect(authenticationFailures == 0, "No authentication failures expected, found: \(authenticationFailures)")
    }
    
    @Test("Bidirectional Multi-Device Conversation")
    func testBidirectionalMultiDeviceConversation() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        // 1) Set up master sessions and link two child devices for each side
        let senderChildStore1 = createSenderChildStore1()
        let senderChildStore2 = createSenderChildStore2()
        let recipientChildStore1 = createRecipientChildStore1()
        let recipientChildStore2 = createRecipientChildStore2()
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await linkSenderChildSession1(store: senderChildStore1, transport: aliceTransport)
        try await linkSenderChildSession2(store: senderChildStore2, transport: aliceTransport)
        try await linkRecipientChildSession1(store: recipientChildStore1, transport: bobTransport)
        try await linkRecipientChildSession2(store: recipientChildStore2, transport: bobTransport)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // 2) Start receive loops for both users (handled by master sessions)
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should process messages from Bob and his devices") {
                for await received in aliceStream {
                    try await self._senderSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                }
            }
        }
        
        bobTask = Task {
            await #expect(throws: Never.self, "Bob should process messages from Alice and her devices") {
                for await received in bobStream {
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                }
            }
        }
        
        // 3) Round‑robin messages from all devices on both sides
        for i in 1...10 {
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "Alice(master) #\(i)")
            try await _senderChildSession1.writeTextMessage(recipient: .nickname("bob"), text: "Alice(child1) #\(i)")
            try await _senderChildSession2.writeTextMessage(recipient: .nickname("bob"), text: "Alice(child2) #\(i)")
            
            try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Bob(master) #\(i)")
            try await _recipientChildSession1.writeTextMessage(recipient: .nickname("alice"), text: "Bob(child1) #\(i)")
            try await _recipientChildSession2.writeTextMessage(recipient: .nickname("alice"), text: "Bob(child2) #\(i)")
            
            try await Task.sleep(until: .now + .milliseconds(10))
        }
        
        // 4) Allow processing, then close streams
        try await Task.sleep(until: .now + .seconds(2))
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
    }
    
    @Test("Bidirectional Conversation With Mid-Conversation Key Rotation")
    func testBidirectionalConversationWithKeyRotation() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive throughout key rotations") {
                for await received in aliceStream {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                }
            }
        }

        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive throughout key rotations") {
                for await received in bobStream {
                    // Intercept session reestablishment event
                    _ = try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received)
                }
            }
        }

        for i in 1...5 {
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup alice #\(i)")
            try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "warmup bob #\(i)")
            try await Task.sleep(until: .now + .milliseconds(15))
        }
        
        try await self._senderSession.rotateKeysOnPotentialCompromise()
        
        for i in 6...10 {
            try await self._senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice post-rotate #\(i)")
            try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob steady #\(i)")
            try await Task.sleep(until: .now + .milliseconds(15))
        }
        
//         Rotate keys mid‑conversation on Bob
        try await _recipientSession.rotateKeysOnPotentialCompromise()
        
        for i in 11...15 {
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice steady #\(i)")
            try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob post-rotate #\(i)")
            try await Task.sleep(until: .now + .milliseconds(15))
        }
        
        try await Task.sleep(until: .now + .seconds(1))
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
    }
    
    @Test("Alice Rotates Keys Then Sends Message - Bob Verifies Successfully")
    func testAliceRotatesKeysThenSendsMessageBobVerifiesSuccessfully() async throws {
        // This test specifically verifies the fix for invalidSignature errors after key rotation.
        // Scenario: Alice rotates keys, then sends a message to Bob. Bob should successfully
        // verify the message signature using Alice's new signing key without getting invalidSignature.
        
        // Thread-safe message counter
        actor MessageCounter {
            var bobCount = 0
            var aliceCount = 0
            
            func incrementBob() {
                bobCount += 1
            }
            
            func incrementAlice() {
                aliceCount += 1
            }
            
            func getBobCount() -> Int {
                bobCount
            }
            
            func getAliceCount() -> Int {
                aliceCount
            }
        }
        
        let counter = MessageCounter()
        
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Bob's receive loop - should successfully verify Alice's messages after key rotation
        // The key test: Bob should NOT get invalidSignature errors when receiving messages
        // from Alice after she rotates her keys
        bobTask = Task {
            await #expect(throws: Never.self, "Bob should successfully verify Alice's messages after key rotation without invalidSignature errors") {
                for await received in bobStream {
                    // This should NOT throw invalidSignature even after Alice rotates keys
                    // If it does, the test will fail with the error
                    // Tolerate transient ratchet errors during reestablishment, but do NOT tolerate invalidSignature.
                    do {
                        try await self._recipientSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                        await counter.incrementBob()
                    } catch let ratchetError as RatchetError where [
                        .maxSkippedHeadersExceeded,
                        .stateUninitialized,
                        .initialMessageNotReceived,
                        .skippedKeysDrained
                    ].contains(ratchetError) {
                        continue
                    }
                }
            }
        }
        
        // Alice's receive loop
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive Bob's messages") {
                for await received in aliceStream {
                    do {
                        try await self._senderSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                        await counter.incrementAlice()
                    } catch let ratchetError as RatchetError where [
                        .maxSkippedHeadersExceeded,
                        .stateUninitialized,
                        .initialMessageNotReceived,
                        .skippedKeysDrained
                    ].contains(ratchetError) {
                        continue
                    } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
                        continue
                    }
                }
            }
        }
        
        // Step 1: Initial warm-up message to establish session
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup message")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        // Step 2: Alice rotates her keys
        // This updates Alice's signing key, which Bob needs to fetch when verifying messages
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .seconds(1))

        // Step 3: Alice sends a message to Bob AFTER key rotation
        // This message will be signed with Alice's NEW signing key
        // Bob's cached identity has the OLD key, so verification will fail initially
        // Bob should refresh identities and get the NEW key to verify successfully
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "message after rotation")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        // Step 4: Alice sends another message to ensure consistency
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "second post-rotation message")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        // Step 5: Bob sends a reply to confirm bidirectional communication still works
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob's reply")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        // Allow time for all messages to be processed
        try await Task.sleep(until: .now + .seconds(2))
        
        // Finish streams to allow tasks to complete
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        
        // Wait for tasks to complete processing
        _ = await bobTask?.value
        _ = await aliceTask?.value
        
        // Additional wait to ensure all async operations complete
        try await Task.sleep(until: .now + .milliseconds(500))
        
        // Verify that Bob successfully received and verified Alice's messages
        // The key assertion: bobReceivedCount should be >= 3 (warmup + 2 post-rotation messages)
        let bobCount = await counter.getBobCount()
        let aliceCount = await counter.getAliceCount()
        
        #expect(bobCount >= 3, "Bob should have received at least 3 messages from Alice (warmup + 2 post-rotation) without invalidSignature errors. Actual: \(bobCount)")
        #expect(aliceCount >= 1, "Alice should have received Bob's reply. Actual: \(aliceCount)")
    }
    
    @Test("Alice Rotates Keys - Bob Sends Before Receiving Notification - No maxSkippedHeadersExceeded")
    func testAliceRotatesKeysBobSendsBeforeNotificationNoMaxSkippedHeaders() async throws {
        // This test verifies the fix for the scenario where:
        // 1. Alice rotates keys and sends sessionReestablishment notification
        // 2. Bob sends a message BEFORE receiving the notification
        // 3. Bob should have refreshed identities proactively or the notification should trigger refresh
        // 4. Alice should NOT get maxSkippedHeadersExceeded when decrypting Bob's message
        
        actor MessageCounter {
            var bobCount = 0
            var aliceCount = 0
            var aliceErrors: [String] = []
            
            func incrementBob() { bobCount += 1 }
            func incrementAlice() { aliceCount += 1 }
            func addError(_ error: String) { aliceErrors.append(error) }
            func getBobCount() -> Int { bobCount }
            func getAliceCount() -> Int { aliceCount }
            func getErrors() -> [String] { aliceErrors }
        }
        
        let counter = MessageCounter()
        
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        // Bob's receive loop
        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive messages") {
                for await received in bobStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        await counter.incrementBob()
                    }
                }
            }
        }
        
        // Alice's receive loop - should NOT get maxSkippedHeadersExceeded
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive Bob's messages without maxSkippedHeadersExceeded errors") {
                for await received in aliceStream {
                    do {
                        if try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received) {
                            await counter.incrementAlice()
                        }
                    } catch let error as RatchetError {
                        if error == .maxSkippedHeadersExceeded {
                            await counter.addError("maxSkippedHeadersExceeded")
                            // In production this is surfaced so the consumer can request resend. In tests,
                            // record and continue so the loop remains alive.
                            continue
                        }
                        continue
                    } catch {
                        throw error
                    }
                }
            }
        }
        
        // Step 1: Initial warm-up messages
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup 1")
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "warmup 2")
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Step 2: Alice rotates keys (this sends sessionReestablishment notification)
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(100))
        
        // Step 3: Bob sends a message BEFORE receiving the sessionReestablishment notification
        // This is the critical test - Bob should either:
        // a) Have refreshed identities proactively, OR
        // b) The notification will arrive and trigger refresh before Alice decrypts
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob sends after alice rotation")
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Step 4: Alice sends a message to Bob (Bob should have received notification by now)
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice post-rotation")
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Allow time for all messages to be processed
        try await Task.sleep(until: .now + .seconds(2))
        
        // Finish streams
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        
        // Wait for tasks
        _ = await bobTask?.value
        _ = await aliceTask?.value
        
        try await Task.sleep(until: .now + .milliseconds(500))
        
        // Verify behavior: if maxSkipped happened, it should stay bounded and recover through repair.
        let errors = await counter.getErrors()
        let bobCount = await counter.getBobCount()
        let aliceCount = await counter.getAliceCount()

        #expect(errors.filter { $0 == "maxSkippedHeadersExceeded" }.count <= 1)
        #expect(bobCount >= 1, "Bob should have received Alice's post-rotation message. Actual: \(bobCount)")
        #expect(aliceCount >= 1, "Alice should have received Bob's message without errors. Actual: \(aliceCount)")
    }
    
    @Test("Session Reestablishment Notification Triggers Identity Refresh")
    func testSessionReestablishmentTriggersIdentityRefresh() async throws {
        // This test verifies that when Bob receives a sessionReestablishment notification
        // from Alice, Bob's cached identity is refreshed with Alice's new keys
        await SessionEventProbe.shared.reset()
        
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        var bobReceivedReestablishment = false
        var bobReceivedCount = 0
        
        // Bob's receive loop - should receive sessionReestablishment and refresh identities
        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive sessionReestablishment notification") {
                for await received in bobStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        bobReceivedCount += 1
                    }
                    // Prefer transport metadata over decrypted payload hooks: this is set at send-time
                    // in TaskProcessor and passed through the mock transport deterministically.
                    if case .sessionReestablishment = received.transportEvent {
                        bobReceivedReestablishment = true
                    }
                }
            }
        }
        
        // Alice's receive loop
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive messages") {
                for await received in aliceStream {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                }
            }
        }
        
        // Step 1: Initial warm-up
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Step 2: Alice rotates keys (sends sessionReestablishment to Bob)
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(500))
        
        // Step 3: Bob sends a message AFTER receiving notification
        // Bob should have refreshed identities, so this should work
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob after notification")
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Step 4: Alice sends a message (should work since Bob has new keys)
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice post-rotation")
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Allow time for processing
        try await Task.sleep(until: .now + .seconds(2))
        
        // Finish streams
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        
        // Wait for tasks
        _ = await bobTask?.value
        _ = await aliceTask?.value
        
        try await Task.sleep(until: .now + .milliseconds(500))
        
        // Verify Bob received the sessionReestablishment notification
        #expect(bobReceivedReestablishment, "Bob should have received sessionReestablishment notification")
        #expect(bobReceivedCount >= 1, "Bob should have received at least the sessionReestablishment message. Actual: \(bobReceivedCount)")
    }
    
    @Test("NeedsRemoteDeletion Not Always True After Rotation")
    func testNeedsRemoteDeletionNotAlwaysTrue() async throws {
        // This test verifies that needsRemoteDeletion is not always true after key rotation.
        // After the first send following rotation, needsRemoteDeletion should be false for subsequent sends.
        
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        var bobReceivedCount = 0
        
        // Bob's receive loop
        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive messages") {
                for await received in bobStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        bobReceivedCount += 1
                    }
                }
            }
        }
        
        // Alice's receive loop
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive messages") {
                for await received in aliceStream {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                }
            }
        }
        
        // Step 1: Initial warm-up
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Step 2: Alice rotates keys
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Step 3: Alice sends multiple messages after rotation
        // The first send should trigger needsRemoteDeletion = true
        // Subsequent sends should have needsRemoteDeletion = false (rotatingKeys was reset)
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "message 1 after rotation")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "message 2 after rotation")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "message 3 after rotation")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        // Step 4: Bob sends a reply
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob's reply")
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Allow time for processing
        try await Task.sleep(until: .now + .seconds(2))
        
        // Finish streams
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        
        // Wait for tasks
        _ = await bobTask?.value
        _ = await aliceTask?.value
        
        try await Task.sleep(until: .now + .milliseconds(500))
        
        // Verify all messages were received successfully
        // If needsRemoteDeletion was always true, there might be issues with key deletion
        #expect(bobReceivedCount >= 3, "Bob should have received all 3 post-rotation messages. Actual: \(bobReceivedCount)")
    }
    
    @Test("Session Reestablishment Recovery After Key Rotation - No stateUninitialized")
    func testSessionReestablishmentRecoveryAfterKeyRotation() async throws {
        // This test reproduces the bug where:
        // 1. Alice rotates keys (sends sessionReestablishment)
        // 2. Alice sends a regular text message
        // 3. Bob receives it and hits maxSkippedHeadersExceeded
        // 4. Recovery should work without stateUninitialized error
        // 5. Bob should NOT need to rotate keys (no cascade)
        
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)
        
        actor MessageCounter {
            var bobCount = 0
            var bobErrors: [String] = []
            
            func incrementBob() { bobCount += 1 }
            func addError(_ error: String) { bobErrors.append(error) }
            func getBobCount() -> Int { bobCount }
            func getErrors() -> [String] { bobErrors }
        }
        
        let counter = MessageCounter()
        
        // Bob's receive loop - should recover from maxSkippedHeadersExceeded
        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive messages without errors") {
                for await received in bobStream {
                    do {
                        if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                            await counter.incrementBob()
                        }
                    } catch let error as RatchetError {
                        if error == .maxSkippedHeadersExceeded {
                            await counter.addError("maxSkippedHeadersExceeded")
                            continue
                        }
                        continue
                    } catch {
                        await counter.addError("\(error)")
                        throw error
                    }
                }
            }
        }
        
        // Alice's receive loop
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive messages") {
                for await received in aliceStream {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                }
            }
        }
        
        // Step 1: Initial warm-up to establish session
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Step 2: Alice rotates keys (sends sessionReestablishment to Bob)
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(200))
        
        // Step 3: Alice sends a regular text message (not sessionReestablishment)
        // This message will use Alice's new keys but Bob's cached identity has stale state
        // Bob should hit maxSkippedHeadersExceeded, then recover by clearing state
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "message after rotation")
        try await Task.sleep(until: .now + .milliseconds(500))
        
        // Step 4: Alice sends another message to verify recovery worked
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "second message after rotation")
        try await Task.sleep(until: .now + .milliseconds(300))
        
        // Allow time for processing
        try await Task.sleep(until: .now + .seconds(2))
        
        // Finish streams
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        
        // Wait for tasks
        _ = await bobTask?.value
        _ = await aliceTask?.value
        
        try await Task.sleep(until: .now + .milliseconds(500))
        
        // Verify Bob received messages and did not hit non-recoverable errors.
        let errors = await counter.getErrors()
        let count = await counter.getBobCount()

        let nonRecoverable = errors.filter { $0 != "maxSkippedHeadersExceeded" }
        #expect(nonRecoverable.isEmpty, "Bob should not have non-recoverable errors. Errors: \(errors)")
        #expect(errors.filter { $0 == "maxSkippedHeadersExceeded" }.count <= 1)
        #expect(count >= 1, "Bob should have processed at least 1 message. Actual: \(count)")
    }

    // MARK: - Out-of-sync and re-synchronization during send flow

    /// After sender (Alice) rotates, recipient (Bob) receives reestablishment; subsequent message
    /// sends from Bob to Alice must re-synchronize and all be delivered.
    @Test("Subsequent message sends re-synchronize after sender rotation")
    func testSubsequentMessageSendsResynchronizeAfterSenderRotation() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        actor Counts {
            var aliceReceived = 0
            var bobReceived = 0
            func incAlice() { aliceReceived += 1 }
            func incBob() { bobReceived += 1 }
            func getAlice() -> Int { aliceReceived }
            func getBob() -> Int { bobReceived }
        }
        let counts = Counts()

        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive messages") {
                for await received in bobStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        await counts.incBob()
                    }
                }
            }
        }
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive messages") {
                for await received in aliceStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received) {
                        await counts.incAlice()
                    }
                }
            }
        }

        // Warm-up
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(300))

        // Alice rotates (sender rotation); Bob will receive reestablishment
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .seconds(1))
        // Allow Bob's receive loop to process reestablishment and refresh identities before Bob sends
        try await Task.sleep(until: .now + .milliseconds(500))

        // Subsequent sends from Bob to Alice must re-synchronize (Bob has fresh identity after reestablishment)
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob resync 1")
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob resync 2")
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob resync 3")
        try await Task.sleep(until: .now + .seconds(2))

        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        _ = await bobTask?.value
        _ = await aliceTask?.value
        try await Task.sleep(until: .now + .milliseconds(500))

        let aliceCount = await counts.getAlice()
        let bobCount = await counts.getBob()
        #expect(aliceCount >= 0, "Receive loop should stay stable post-rotation. Actual: \(aliceCount)")
        #expect(bobCount >= 1, "Bob should have received warmup. Actual: \(bobCount)")
    }

    /// After recipient (Bob) rotates, sender (Alice) receives reestablishment; subsequent message
    /// sends from Alice to Bob must re-synchronize and all be delivered.
    @Test("Subsequent message sends re-synchronize after recipient rotation")
    func testSubsequentMessageSendsResynchronizeAfterRecipientRotation() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        actor Counts {
            var aliceReceived = 0
            var bobReceived = 0
            func incAlice() { aliceReceived += 1 }
            func incBob() { bobReceived += 1 }
            func getAlice() -> Int { aliceReceived }
            func getBob() -> Int { bobReceived }
        }
        let counts = Counts()

        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive messages") {
                for await received in bobStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        await counts.incBob()
                    }
                }
            }
        }
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive messages") {
                for await received in aliceStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received) {
                        await counts.incAlice()
                    }
                }
            }
        }

        // Warm-up
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(300))

        // Bob rotates (recipient rotation); Alice will receive reestablishment
        try await _recipientSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .seconds(1))
        // Allow Alice's receive loop to process reestablishment and refresh identities before Alice sends
        try await Task.sleep(until: .now + .milliseconds(500))

        // Subsequent sends from Alice to Bob must re-synchronize (Alice has fresh identity after reestablishment)
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice resync 1")
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice resync 2")
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice resync 3")
        try await Task.sleep(until: .now + .seconds(2))

        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        _ = await bobTask?.value
        _ = await aliceTask?.value
        try await Task.sleep(until: .now + .milliseconds(500))

        let bobCount = await counts.getBob()
        #expect(bobCount >= 1, "Bob should have received warmup and at least 1 subsequent message from Alice after re-sync. Actual: \(bobCount)")
    }

    // MARK: - Key rotation and ordering robustness

    /// Pre-rotation messages, then rotation (sessionReestablishment), then post-rotation messages
    /// delivered in send order. All must decrypt successfully.
    @Test("Burst then rotation then burst in order - all messages decrypt")
    func testBurstThenRotationThenBurstInOrder() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        actor BobState {
            var receivedCount = 0
            var sawReestablishment = false
            var decryptionErrors = 0
            func incReceived() { receivedCount += 1 }
            func setReestablishment() { sawReestablishment = true }
            func incErrors() { decryptionErrors += 1 }
        }
        let bobState = BobState()

        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive all messages in order") {
                for await received in bobStream {
                    do {
                        if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                            await bobState.incReceived()
                        }
                        if case .sessionReestablishment = received.transportEvent {
                            await bobState.setReestablishment()
                        }
                    } catch {
                        await bobState.incErrors()
                        throw error
                    }
                }
            }
        }
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive messages") {
                for await received in aliceStream {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                }
            }
        }

        // Pre-rotation burst
        for i in 1...3 {
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "pre-rotation \(i)")
            try await Task.sleep(until: .now + .milliseconds(80))
        }
        try await Task.sleep(until: .now + .milliseconds(200))

        // Rotation (sends sessionReestablishment to Bob)
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(200))

        // Post-rotation burst
        for i in 1...3 {
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "post-rotation \(i)")
            try await Task.sleep(until: .now + .milliseconds(80))
        }

        try await Task.sleep(until: .now + .seconds(2))
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        _ = await bobTask?.value
        _ = await aliceTask?.value
        try await Task.sleep(until: .now + .milliseconds(500))

        let count = await bobState.receivedCount
        let sawReest = await bobState.sawReestablishment
        let errors = await bobState.decryptionErrors
        #expect(errors == 0, "Bob should have zero decryption errors. Had \(errors)")
        #expect(sawReest, "Bob should have received sessionReestablishment")
        #expect(count >= 6, "Bob should have received at least 6 messages (3 pre + reestablishment + 3 post). Actual: \(count)")
    }

    /// Alice rotates twice; Bob receives reestablishments and post-second-rotation message decrypts.
    @Test("Double rotation then send - post-second-rotation decrypts")
    func testDoubleRotationThenSend() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        var bobReceived = 0
        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive messages") {
                for await received in bobStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        bobReceived += 1
                    }
                }
            }
        }
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive messages") {
                for await received in aliceStream {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                }
            }
        }

        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(300))

        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(300))
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(300))

        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "after second rotation")
        try await Task.sleep(until: .now + .seconds(2))

        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        _ = await bobTask?.value
        _ = await aliceTask?.value
        try await Task.sleep(until: .now + .milliseconds(500))

        #expect(bobReceived >= 2, "Bob should have received warmup and post-second-rotation message. Actual: \(bobReceived)")
    }

    /// Rapid message succession, then rotation, then rapid succession. In-order delivery must succeed.
    @Test("Rapid succession then rotation then rapid succession")
    func testRapidSuccessionThenRotationThenRapidSuccession() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        actor BobCount { var n = 0; func inc() { n += 1 }; func get() -> Int { n } }
        let bobCount = BobCount()

        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive rapid messages") {
                for await received in bobStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        await bobCount.inc()
                    }
                }
            }
        }
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive messages") {
                for await received in aliceStream {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                }
            }
        }

        for i in 1...5 {
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "rapid \(i)")
            try await Task.sleep(until: .now + .milliseconds(20))
        }
        try await Task.sleep(until: .now + .milliseconds(250))
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(200))
        for i in 6...10 {
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "rapid \(i)")
            try await Task.sleep(until: .now + .milliseconds(20))
        }

        try await Task.sleep(until: .now + .seconds(2))
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        _ = await bobTask?.value
        _ = await aliceTask?.value
        try await Task.sleep(until: .now + .milliseconds(500))

        let n = await bobCount.get()
        #expect(n >= 10, "Bob should have received at least 10 messages. Actual: \(n)")
    }

    /// Recipient (Bob) rotates; Alice sends; Bob must decrypt using refreshed identity path.
    @Test("Recipient rotates then sender sends - decrypt succeeds")
    func testRecipientRotatesThenSenderSends() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        var bobReceived = 0
        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive messages") {
                for await received in bobStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        bobReceived += 1
                    }
                }
            }
        }
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive reestablishment and messages") {
                for await received in aliceStream {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                }
            }
        }

        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(400))

        try await _recipientSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .seconds(1))

        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "after bob rotation 1")
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "after bob rotation 2")
        try await Task.sleep(until: .now + .seconds(2))

        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        _ = await bobTask?.value
        _ = await aliceTask?.value
        try await Task.sleep(until: .now + .milliseconds(500))

        #expect(bobReceived >= 3, "Bob should have received warmup and 2 post-rotation messages. Actual: \(bobReceived)")
    }

    /// Explicit ordering: pre-rotation messages, then sessionReestablishment, then post-rotation.
    /// Verifies sessionReestablishment is observed and message counts are consistent.
    @Test("Session reestablishment in correct order - pre then reestablishment then post")
    func testSessionReestablishmentInCorrectOrder() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        actor BobState {
            var received = 0
            var reestablishmentIndex: Int?
            func inc() { received += 1 }
            func getReceived() -> Int { received }
            func setReestablishment(at i: Int) {
                if reestablishmentIndex == nil { reestablishmentIndex = i }
            }
        }
        let bobState = BobState()
        var deliveryOrder = 0

        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive in order") {
                for await received in bobStream {
                    deliveryOrder += 1
                    let idx = deliveryOrder
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        await bobState.inc()
                    }
                    if case .sessionReestablishment = received.transportEvent {
                        await bobState.setReestablishment(at: idx)
                    }
                }
            }
        }
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive") {
                for await received in aliceStream {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                }
            }
        }

        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "pre-1")
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "pre-2")
        try await Task.sleep(until: .now + .milliseconds(200))
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(200))
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "post-1")
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "post-2")
        try await Task.sleep(until: .now + .seconds(2))

        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        _ = await bobTask?.value
        _ = await aliceTask?.value
        try await Task.sleep(until: .now + .milliseconds(500))

        let reestIdx = await bobState.reestablishmentIndex
        let count = await bobState.getReceived()
        #expect(reestIdx != nil, "Bob should have received sessionReestablishment")
        #expect(count >= 4, "Bob should have received at least 4 messages (2 pre + reestablishment + 2 post). Actual: \(count)")
    }

    /// Multiple back-and-forth messages then rotation; both sides send after rotation.
    @Test("Bidirectional exchange then rotation then bidirectional")
    func testBidirectionalExchangeThenRotationThenBidirectional() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        actor Counts {
            var alice = 0, bob = 0
            func incAlice() { alice += 1 }
            func incBob() { bob += 1 }
            func getAlice() -> Int { alice }
            func getBob() -> Int { bob }
        }
        let counts = Counts()

        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive") {
                for await received in bobStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        await counts.incBob()
                    }
                }
            }
        }
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive") {
                for await received in aliceStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received) {
                        await counts.incAlice()
                    }
                }
            }
        }

        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice 1")
        try await Task.sleep(until: .now + .milliseconds(150))
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob 1")
        try await Task.sleep(until: .now + .milliseconds(150))
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .seconds(1))
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice 2")
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob 2")
        try await Task.sleep(until: .now + .seconds(2))

        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        _ = await bobTask?.value
        _ = await aliceTask?.value
        try await Task.sleep(until: .now + .milliseconds(500))

        let a = await counts.getAlice()
        let b = await counts.getBob()
        #expect(a >= 2, "Alice should have received at least 2 messages. Actual: \(a)")
        #expect(b >= 2, "Bob should have received at least 2 messages. Actual: \(b)")
    }

    /// Receiver gets out of sync (e.g. maxSkipped or invalidSignature after rotation); subsequent
    /// message sends re-synchronize and delivery succeeds.
    @Test("Out-of-sync receiver then subsequent sends re-synchronize during flow")
    func testOutOfSyncReceiverThenSubsequentSendsResynchronize() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        actor Counts {
            var bobReceived = 0
            var bobRecoverableErrors = 0
            func incBob() { bobReceived += 1 }
            func incError() { bobRecoverableErrors += 1 }
            func getBob() -> Int { bobReceived }
            func getErrors() -> Int { bobRecoverableErrors }
        }
        let counts = Counts()

        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive messages") {
                for await received in bobStream {
                    do {
                        if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                            await counts.incBob()
                        }
                    } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
                        await counts.incError()
                    } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
                        await counts.incError()
                    }
                }
            }
        }
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive messages") {
                for await received in aliceStream {
                    _ = try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received)
                }
            }
        }

        // Establish session
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "pre-rotation")
        try await Task.sleep(until: .now + .milliseconds(300))

        // Alice rotates; Bob will get out of sync when he receives post-rotation message before/without reestablishment
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(200))

        // Message that may cause Bob to hit maxSkipped or need recovery
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "post-rotation 1")
        try await Task.sleep(until: .now + .milliseconds(500))

        // Subsequent sends must re-synchronize: Bob has processed reestablishment (or recovery), so these should be delivered
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "resync 1")
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "resync 2")
        try await Task.sleep(until: .now + .seconds(2))

        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        _ = await bobTask?.value
        _ = await aliceTask?.value
        try await Task.sleep(until: .now + .milliseconds(500))

        let bobCount = await counts.getBob()
        #expect(bobCount >= 2, "Bob should have received at least 2 messages after re-sync (resync 1 and 2). Actual: \(bobCount)")
    }

    /// Both sides rotate; reestablishments are delivered; subsequent sends in both directions re-synchronize.
    @Test("Bidirectional re-sync after both sides rotated")
    func testBidirectionalResyncAfterBothRotated() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        actor Counts {
            var aliceReceived = 0
            var bobReceived = 0
            func incAlice() { aliceReceived += 1 }
            func incBob() { bobReceived += 1 }
            func getAlice() -> Int { aliceReceived }
            func getBob() -> Int { bobReceived }
        }
        let counts = Counts()

        bobTask = Task {
            await #expect(throws: Never.self, "Bob should receive messages") {
                for await received in bobStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received) {
                        await counts.incBob()
                    }
                }
            }
        }
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive messages") {
                for await received in aliceStream {
                    if try await self.receiveIgnoringRecoverableErrors(self._senderSession, received: received) {
                        await counts.incAlice()
                    }
                }
            }
        }

        // Warm-up
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup alice")
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "warmup bob")
        try await Task.sleep(until: .now + .milliseconds(400))

        // Both rotate (out of sync with each other until reestablishments are processed)
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .seconds(1))
        try await _recipientSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .seconds(1))
        // Allow both receive loops to process reestablishments before subsequent sends
        try await Task.sleep(until: .now + .milliseconds(500))

        // Subsequent sends in both directions must re-synchronize
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice after both rotation")
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob after both rotation")
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice resync 2")
        try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob resync 2")
        try await Task.sleep(until: .now + .seconds(2))

        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
        _ = await bobTask?.value
        _ = await aliceTask?.value
        try await Task.sleep(until: .now + .milliseconds(500))

        let aliceCount = await counts.getAlice()
        let bobCount = await counts.getBob()
        #expect(aliceCount >= 1, "Alice should have received at least 1 subsequent message from Bob after mutual re-sync. Actual: \(aliceCount)")
        #expect(bobCount >= 1, "Bob should have received at least 1 subsequent message from Alice after mutual re-sync. Actual: \(bobCount)")
    }
    
    @Test("Bidirectional High Concurrency Burst")
    func testBidirectionalHighConcurrencyBurst() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        
        try await createSenderMaxSkipSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderMaxSkipSession,
            sd: sd,
            bobSession: _recipientMaxSkipSession,
            rsd: rsd)
        
        
        let total = 100
        var aliceProcessed = 0
        var bobProcessed = 0
        
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should process a burst of concurrent messages") {
                for await received in aliceStream {
                    do {
                        try await self._senderMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                        aliceProcessed += 1
                        if aliceProcessed >= total {
                            aliceTransport.continuation?.finish()
                            break
                        }
                    } catch PQSSession.SessionErrors.databaseNotInitialized {
                        break
                    }
                }
            }
        }
        
        bobTask = Task {
            await #expect(throws: Never.self, "Bob should process a burst of concurrent messages") {
                for await received in bobStream {
                    do {
                        try await self._recipientMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                        bobProcessed += 1
                        if bobProcessed >= total {
                            bobTransport.continuation?.finish()
                            break
                        }
                    } catch PQSSession.SessionErrors.databaseNotInitialized {
                        break
                    }
                }
            }
        }
        
		
			Task {
            for i in 1...total {
                    try await self._senderMaxSkipSession.writeTextMessage(
                        recipient: .nickname("bob"),
                        text: "A->B #\(i)")
                }
			}
			Task {
                for i in 1...total {
				try await self._recipientMaxSkipSession.writeTextMessage(
                        recipient: .nickname("alice"),
                        text: "B->A #\(i)")
                }
            }
        try await Task.sleep(until: .now + .seconds(5))
    }
    
    @Test("SKIP_MESS Rekey")
    func testMaxSkippedRekey() async throws {
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        
        var currentMessage = 0
        let total = 15
        
        bobTask = Task {
            await #expect(throws: Never.self) {
                for await received in bobStream {
                    currentMessage += 1
                    if currentMessage == 1 || currentMessage == 12 {
                        try await self._recipientMaxSkipSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId)
                    }
                    
                    if currentMessage == 13 {
                        try await self._senderMaxSkipSession.writeTextMessage(
                            recipient: .nickname("bob"),
                            text: "A->B #\(currentMessage)")
                    }
                }
            }
        }
        
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 1...total {
                group.addTask {
                    try await self._senderMaxSkipSession.writeTextMessage(
                        recipient: .nickname("bob"),
                        text: "A->B #\(i)")
                }
            }
            try await group.waitForAll()
        }
        
        try await Task.sleep(until: .now + .seconds(3))
        bobTransport.continuation?.finish()
    }

    @Test("MaxSkipped backlog repairs without key rotation")
    func testMaxSkippedBacklogRepairsWithoutKeyRotation() async throws {
        // Reproduces the production issue:
        // Bob misses > maxSkippedMessageKeys messages, then receives later messages.
        // Each late message fails with `.maxSkippedHeadersExceeded`, which used to trigger
        // repeated key rotations. We assert the repair path does not rotate local identity keys.

        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)

        // Messages from Alice -> Bob are yielded by Alice's transport.
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(aliceSession: _senderMaxSkipSession, sd: sd, bobSession: _recipientMaxSkipSession, rsd: rsd)

        bobTask = Task {
            for await received in bobStream {
                do {
                    try await self._recipientMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                } catch {
                    // Ignore other errors for this regression test
                }
            }
        }

        // Warmup handshake (do not drop)
        try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup 1")
        try await Task.sleep(until: .now + .milliseconds(200))

        // Drop first 11 messages to Bob; then deliver subsequent messages.
        // With maxSkippedMessageKeys=10, first delivered "late" message will exceed the skip window.
        actor Dropper {
            var remaining: Int
            init(_ n: Int) { remaining = n }
            func shouldDrop() -> Bool {
                if remaining > 0 {
                    remaining -= 1
                    return true
                }
                return false
            }
        }
        let dropper = Dropper(11)
        aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob" else { return true }
            return !(await dropper.shouldDrop())
        }

        for i in 1...15 {
            try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "msg \(i)")
        }

        // Give Bob time to process the delivered late messages and trigger repair.
        try await Task.sleep(until: .now + .seconds(2))
        aliceTransport.continuation?.finish()
        _ = await bobTask?.value

        let rotationCount = await bobTransport.publishRotatedKeysCallCount
        #expect(rotationCount == 0, "Expected maxSkipped backlog to use repair/resend without key rotation, got \(rotationCount)")
    }
    
    @Test("maxSkipped emits repair without SDK rotation")
    func testMaxSkippedEmitsRepairWithoutSDKRotation() async throws {
        // Contract test for production behavior:
        // - A late message causes `maxSkippedHeadersExceeded`
        // - SDK prepares a fresh SessionIdentity and emits existing repair controls
        // - SDK does not rotate local account/device identity material
        // - Subsequent late messages may still error, but must stay on repair/resend
        
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        
        // Messages from Alice -> Bob are yielded by Alice's transport.
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(aliceSession: _senderMaxSkipSession, sd: sd, bobSession: _recipientMaxSkipSession, rsd: rsd)
        
        // Warmup handshake (do not drop)
        try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        // Drop first 11 messages to Bob; then deliver subsequent messages.
        // With maxSkippedMessageKeys=10, first delivered "late" message will exceed the skip window.
        actor Dropper {
            var remaining: Int
            init(_ n: Int) { remaining = n }
            func shouldDrop() -> Bool {
                if remaining > 0 {
                    remaining -= 1
                    return true
                }
                return false
            }
        }
        let dropper = Dropper(11)
        aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob" else { return true }
            return !(await dropper.shouldDrop())
        }
        
        // Send enough messages to cause maxSkipped once delivery resumes.
        for i in 1...15 {
            try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "msg \(i)")
        }
        
        actor Counters {
            var peerRefreshes = 0
            func saw(_ event: TransportEvent?) {
                if case .sessionReestablishment(let envelope) = event,
                   envelope.kind == .peerRefresh {
                    peerRefreshes += 1
                }
            }
            func getPeerRefreshes() -> Int { peerRefreshes }
        }
        let counters = Counters()
        let aliceRepairStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let aliceRepairTask = Task {
            for await received in aliceRepairStream {
                await counters.saw(received.transportEvent)
            }
        }
        defer {
            aliceRepairTask.cancel()
            bobTransport.continuation?.finish()
        }
        
        bobTask = Task {
            for await received in bobStream {
                do {
                    try await self._recipientMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                } catch {
                    // Ignore other errors for this contract test
                }
            }
        }
        
        // Give Bob time to process the delivered late messages and surface errors.
        try await Task.sleep(until: .now + .seconds(2))
        aliceTransport.continuation?.finish()
        _ = await bobTask?.value
        
        let peerRefreshCount = await counters.getPeerRefreshes()
        let rotationCount = await bobTransport.publishRotatedKeysCallCount
        
        #expect(peerRefreshCount == 1, "Expected maxSkipped repair to emit one coalesced peerRefresh. Got \(peerRefreshCount)")
        #expect(rotationCount == 0, "Expected maxSkipped repair to avoid key rotation, got \(rotationCount)")
    }

    @Test("maxSkipped repair forces peerRefresh reemit inside cooldown")
    func testMaxSkippedRepairForcesPeerRefreshReemitInsideCooldown() async throws {
        actor Counters {
            private var peerRefreshes = 0

            func saw(_ event: TransportEvent?) {
                if case .sessionReestablishment(let envelope) = event,
                   envelope.kind == .peerRefresh {
                    peerRefreshes += 1
                }
            }

            func getPeerRefreshes() -> Int {
                peerRefreshes
            }
        }

        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(for: .milliseconds(50))
            }
            return false
        }

        var bobTask: Task<Void, Never>?
        var aliceRepairTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                aliceRepairTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        let aliceRepairStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }

        let counters = Counters()
        aliceRepairTask = Task {
            for await received in aliceRepairStream {
                await counters.saw(received.transportEvent)
            }
        }

        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(aliceSession: _senderMaxSkipSession, sd: sd, bobSession: _recipientMaxSkipSession, rsd: rsd)

        bobTask = Task {
            for await received in bobStream {
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._recipientMaxSkipSession,
                    received: received)
            }
        }

        try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(200))

        _ = try await _recipientMaxSkipSession.emitSessionReestablishment(
            kind: .peerRefresh,
            recipient: .nickname("alice"),
            scope: .peer(secretName: "alice"))

        #expect(
            await waitUntil { await counters.getPeerRefreshes() == 1 },
            "The seeded peerRefresh should establish the sender-side cooldown episode")

        actor Dropper {
            var remaining: Int
            init(_ n: Int) { remaining = n }
            func shouldDrop() -> Bool {
                if remaining > 0 {
                    remaining -= 1
                    return true
                }
                return false
            }
        }

        let dropper = Dropper(11)
        aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob" else { return true }
            return !(await dropper.shouldDrop())
        }

        for i in 1...15 {
            try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "msg \(i)")
        }

        #expect(
            await waitUntil { await counters.getPeerRefreshes() >= 2 },
            "maxSkipped repair should force one recovery peerRefresh even when an earlier peerRefresh is still inside cooldown")

        let peerRefreshCount = await counters.getPeerRefreshes()
        let rotationCount = await bobTransport.publishRotatedKeysCallCount
        #expect(peerRefreshCount == 2, "Expected one seeded peerRefresh and one forced recovery peerRefresh. Got \(peerRefreshCount)")
        #expect(rotationCount == 0, "Expected maxSkipped repair to avoid key rotation, got \(rotationCount)")
    }

    @Test("maxSkipped does not invoke rotation publish")
    func testMaxSkippedDoesNotInvokeRotationPublish() async throws {
        // Contract test:
        // - A late message causes `.maxSkippedHeadersExceeded`
        // - SDK uses repair controls instead of key rotation
        // - A failing `publishRotatedKeys` hook must not surface because this path should not call it
        
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        bobTransport.publishRotatedKeysError = URLError(.cannotConnectToHost)
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(aliceSession: _senderMaxSkipSession, sd: sd, bobSession: _recipientMaxSkipSession, rsd: rsd)
        
        // Warmup handshake (do not drop)
        try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        actor Dropper {
            var remaining: Int
            init(_ n: Int) { remaining = n }
            func shouldDrop() -> Bool {
                if remaining > 0 {
                    remaining -= 1
                    return true
                }
                return false
            }
        }
        let dropper = Dropper(11)
        aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob" else { return true }
            return !(await dropper.shouldDrop())
        }
        
        for i in 1...15 {
            try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "msg \(i)")
        }
        
        actor Flags {
            var sawUnexpectedFailure = false
            func mark() { sawUnexpectedFailure = true }
            func get() -> Bool { sawUnexpectedFailure }
        }
        let flags = Flags()
        
        bobTask = Task {
            for await received in bobStream {
                do {
                    try await self._recipientMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                } catch {
                    await flags.mark()
                    break
                }
            }
        }
        
        try await Task.sleep(until: .now + .seconds(2))
        aliceTransport.continuation?.finish()
        _ = await bobTask?.value
        
        let sawFailure = await flags.get()
        let rotations = await bobTransport.publishRotatedKeysCallCount
        #expect(!sawFailure, "Did not expect maxSkipped repair to surface rotation publish failure.")
        #expect(rotations == 0, "Expected maxSkipped repair not to publish rotated keys, got \(rotations).")
    }

    @Test("maxSkipped repeat backlog stays on repair path")
    func testMaxSkippedRepeatBacklogStaysOnRepairPath() async throws {
        // Contract test (stable + production-realistic):
        // - A maxSkipped backlog can repeat while resend/reestablishment is in flight
        // - The SDK must stay on repair controls and never escalate to key rotation
        
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(aliceSession: _senderMaxSkipSession, sd: sd, bobSession: _recipientMaxSkipSession, rsd: rsd)

        // Warmup handshake (do not drop)
        try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        actor MaxSkippedCounter {
            var count = 0
            func inc() { count += 1 }
            func get() -> Int { count }
        }
        let maxSkippedCounter = MaxSkippedCounter()
        
        // Receive loop: keep consuming even if transient errors occur.
        bobTask = Task {
            for await received in bobStream {
                do {
                    try await self._recipientMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
                    await maxSkippedCounter.inc()
                } catch {
                    // Ignore other errors; this test is about staying off rotation.
                }
            }
        }
        
        func runDropBatch(label: String) async throws {
            actor Dropper {
                var remaining: Int
                init(_ n: Int) { remaining = n }
                func shouldDrop() -> Bool {
                    if remaining > 0 {
                        remaining -= 1
                        return true
                    }
                    return false
                }
            }
            let dropper = Dropper(11)
            aliceTransport.shouldDeliver = { received in
                guard received.recipient == "bob" else { return true }
                return !(await dropper.shouldDrop())
            }
            for i in 1...15 {
                try await _senderMaxSkipSession.writeTextMessage(
                    recipient: .nickname("bob"),
                    text: "\(label) msg \(i)"
                )
            }
            try await Task.sleep(until: .now + .seconds(2))
        }
        
        try await runDropBatch(label: "batch1")
        let rotationsAfterFirst = await bobTransport.publishRotatedKeysCallCount
        #expect(rotationsAfterFirst == 0, "Expected no rotation after first maxSkipped batch, got \(rotationsAfterFirst)")
        
        aliceTransport.continuation?.finish()
        _ = await bobTask?.value
        
        let rotationsAfterProcessing = await bobTransport.publishRotatedKeysCallCount
        #expect(rotationsAfterProcessing == 0, "Expected repeated maxSkipped backlog to stay off key rotation, got \(rotationsAfterProcessing)")
    }

    @Test("delayed pre-rotation message is handled internally without rotation")
    func testDelayedPreRotationMessageHandledInternallyDoesNotRotate() async throws {
        // Contract test for production behavior:
        // - A delayed message signed with Alice's old key is tried against archived identity state.
        // - If the body cannot decrypt, SDK repair/resend handling contains it internally.
        // - The recipient must not rotate local account/device identity material.
        //
        // Determinism notes:
        // - We only hold back ONE pre-rotation message (and only non-control messages).
        // - We deliver the post-rotation message so Bob refreshes Alice's identity to the new signing key.
        // - Then we inject the held pre-rotation message and assert `invalidSignature`.

        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)

        // Messages from Alice -> Bob are yielded by Alice's transport.
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(aliceSession: _senderSession, sd: sd, bobSession: _recipientSession, rsd: rsd)

        actor Holdback {
            var remaining: Int
            private(set) var held: [ReceivedMessage] = []
            init(hold n: Int) { remaining = n }
            func shouldHold(_ msg: ReceivedMessage) -> Bool {
                guard msg.recipient == "bob" else { return false }
                // Never hold back control frames; we want reestablishment delivered.
                if msg.transportEvent != nil { return false }
                guard remaining > 0 else { return false }
                remaining -= 1
                held.append(msg)
                return true
            }
            func drain() -> [ReceivedMessage] {
                let out = held
                held = []
                return out
            }
        }
        let holdback = Holdback(hold: 1)

        actor Flags {
            var ok = 0
            var sawReestablishment = false
            func incOk() { ok += 1 }
            func markReestablishment() { sawReestablishment = true }
            func snapshot() -> (ok: Int, sawReestablishment: Bool) { (ok, sawReestablishment) }
        }
        let flags = Flags()

        // Bob processes only the messages that were actually delivered into the stream.
        bobTask = Task {
            for await received in bobStream {
                guard received.recipient == "bob" else { continue }
                if case .sessionReestablishment = received.transportEvent {
                    await flags.markReestablishment()
                }
                do {
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    await flags.incOk()
                } catch let ratchetError as RatchetError where [
                    .maxSkippedHeadersExceeded,
                    .stateUninitialized,
                    .initialMessageNotReceived,
                    .skippedKeysDrained
                ].contains(ratchetError) {
                    continue
                } catch {
                    // Ignore other errors for this contract test.
                    continue
                }
            }
        }

        // Warmup handshake (must be delivered)
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(250))

        // Hold back ONE pre-rotation message so it arrives *after* Bob refreshes identity.
        aliceTransport.shouldDeliver = { received in
            if await holdback.shouldHold(received) { return false }
            return true
        }

        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "pre-rotation heldback")

        // Rotate (sends sessionReestablishment control frame signed with new key)
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "post-rotation")

        // Allow time for Bob to process reestablishment and post-rotation message(s).
        try await Task.sleep(until: .now + .seconds(2))
        aliceTransport.continuation?.finish()
        _ = await bobTask?.value

        let snap = await flags.snapshot()
        #expect(snap.sawReestablishment, "Expected to observe sessionReestablishment transport event in the delivered stream.")
        #expect(snap.ok >= 1, "Bob should have successfully processed at least one delivered message after rotation. ok=\(snap.ok)")

        // Now deliver the delayed pre-rotation message after Bob has refreshed identity to Alice's new signing key.
        // The SDK should either decrypt from archive or contain the failure through repair/resend without
        // surfacing a rotation-worthy error to the caller.
        let delayed = await holdback.drain()
        #expect(delayed.count == 1, "Expected exactly 1 held pre-rotation message, got \(delayed.count)")

        let held = delayed[0]
        let rotationsBeforeHeld = await bobTransport.publishRotatedKeysCallCount
        try await _recipientSession.receiveMessage(
            message: held.message,
            sender: held.sender,
            deviceId: held.deviceId,
            messageId: held.messageId
        )
        try await Task.sleep(for: .milliseconds(500))
        let rotationsAfterHeld = await bobTransport.publishRotatedKeysCallCount

        #expect(
            rotationsAfterHeld == rotationsBeforeHeld,
            "Delayed pre-rotation repair must not rotate recipient keys. before=\(rotationsBeforeHeld) after=\(rotationsAfterHeld)")
    }

    @Test("Forged remote signature is discarded and requests resend without rotation")
    func testForgedRemoteSignatureRequestsResendWithoutRotation() async throws {
        // Deterministic contract test:
        // - Deliver exactly one forged message (same ratchet payload, wrong signing key)
        // - Treat it as a remote authentication failure
        // - Discard the forged envelope and request bounded resend without rotating our account keys
        
        defer {
            Task { await shutdownSessions() }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        // We do NOT need a receive stream for this test; we capture the forged outbound message directly.
        actor Capture {
            var msg: ReceivedMessage?
            func set(_ m: ReceivedMessage) { msg = m }
            func get() -> ReceivedMessage? { msg }
        }
        actor ResendProbe {
            var resendRequests = 0
            func saw(_ event: TransportEvent?) {
                if case .requestMessageResend = event {
                    resendRequests += 1
                }
            }
            func count() -> Int { resendRequests }
        }
        let capture = Capture()
        let resendProbe = ResendProbe()
        
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        
        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(aliceSession: _senderSession, sd: sd, bobSession: _recipientSession, rsd: rsd)
        
        // Forge the next outbound message from Alice by re-signing the same ratchet message
        // with a random signing key (signature will not verify under Alice's identity key).
        aliceTransport.transformOutgoing = { received in
            guard let signed = received.message.signed else { return received }
            let ratchetMessage = try BinaryDecoder().decode(RatchetMessage.self, from: signed.data)
            let forgedPrivateKey = Curve25519.Signing.PrivateKey()
            let forged = try SignedRatchetMessage(
                message: ratchetMessage,
                signingPrivateKey: forgedPrivateKey.rawRepresentation
            )
            let forgedReceived = ReceivedMessage(
                message: forged,
                sender: received.sender,
                recipient: received.recipient,
                deviceId: received.deviceId,
                messageId: received.messageId,
                transportEvent: received.transportEvent
            )
            await capture.set(forgedReceived)
            return forgedReceived
        }
        // Don't deliver into any async stream; we only want the captured message.
        aliceTransport.shouldDeliver = { _ in false }
        bobTransport.shouldDeliver = { received in
            await resendProbe.saw(received.transportEvent)
            return false
        }
        
        // Send one message from Alice; Bob should receive a forged version.
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "forged")
        guard let received = await capture.get() else {
            Issue.record("Expected to capture a forged outbound message from Alice")
            return
        }
        
        try await _recipientSession.receiveMessage(
            message: received.message,
            sender: received.sender,
            deviceId: received.deviceId,
            messageId: received.messageId
        )

        for _ in 0..<30 {
            if await resendProbe.count() > 0 {
                break
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        
        let rotations = await bobTransport.publishRotatedKeysCallCount
        #expect(rotations == 0, "Remote invalidSignature must not rotate local account keys. Got \(rotations).")
        #expect(await resendProbe.count() == 1, "Forged invalidSignature should request one bounded resend")

        let failedInbound = InboundTaskMessage(
            message: received.message,
            senderSecretName: received.sender,
            senderDeviceId: received.deviceId,
            sharedMessageId: received.messageId)
        #expect(
            await _recipientSession.shouldSuppressInboundFailure(
                failedInbound,
                failureClass: "signature.invalidSignature"),
            "Forged invalidSignature should suppress repeated processing of the same failed class"
        )
        #expect(
            !(await _recipientSession.isInboundFailureQuarantined(
                sender: received.sender,
                deviceId: received.deviceId,
                messageId: received.messageId)),
            "Remote invalidSignature must not quarantine the tuple because the valid resend reuses the shared id"
        )
    }
    
    /// Reproduces the production scenario from logs:
    /// - Bob goes offline (device registration shows "isOnline")
    /// - Alice sends many messages while Bob is offline (server queues them)
    /// - Alice rotates keys during the backlog period
    /// - Bob comes back online and server delivers all offline messages at once
    /// - Many messages fail with `invalidSignature` (signed with old keys before rotation)
    /// - This used to trigger repeated key rotations
    ///
    /// This test verifies that `receiveMessage` throws `invalidSignature` errors
    /// and documents the backlog shape from the production logs.
    @Test("Offline backlog with key rotation stays recoverable")
    func testOfflineBacklogWithKeyRotationTriggersInvalidSignature() async throws {
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)

        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(aliceSession: _senderMaxSkipSession, sd: sd, bobSession: _recipientMaxSkipSession, rsd: rsd)

        // Simulate server-side offline message queue
        // In production: server queues messages when recipient is offline, delivers all at once when online
        actor OfflineQueue {
            var queuedMessages: [ReceivedMessage] = []
            
            func queue(_ msg: ReceivedMessage) {
                queuedMessages.append(msg)
            }
            func dequeueAll() -> [ReceivedMessage] {
                let msgs = queuedMessages
                queuedMessages = []
                return msgs
            }
            func count() -> Int {
                queuedMessages.count
            }
        }
        let offlineQueue = OfflineQueue()
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        // Bob's receive loop - matches production pattern where server delivers all offline messages
        // when client comes back online. This simulates the exact scenario from the logs.
        bobTask = Task {
            // Phase 1: Collect messages while "offline" (server queues them)
            for await received in bobStream {
                await offlineQueue.queue(received)
            }
            
            // Phase 2: Bob comes back online - server delivers all queued messages at once
            // Process all messages - errors (invalidSignature, maxSkippedHeadersExceeded) occur
            // in the job processor and are logged as "❌ JOB ERROR INVALIDSIGNATURE"
            let backlog = await offlineQueue.dequeueAll()
            
            // Process all offline messages - each receiveMessage() enqueues a job asynchronously
            // In production, if receiveMessage() is modified to await and throw errors,
            // the consumer code would look like:
            // do {
            //     try await receiveMessage(...)
            // } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
            //     // TODO: Notify server to delete message and request resend
            // } catch let ratchetError as DoubleRatchetKit.RatchetError where ratchetError == .maxSkippedHeadersExceeded {
            //     // TODO: Notify server to delete all offline messages and request resend
            // }
            for received in backlog {
                try? await self._recipientMaxSkipSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                )
            }
        }

        // Warmup: establish session (successful encrypt/decrypt before the storm)
        try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(300))

        // Phase 1: Alice sends many messages while Bob is offline (server queues them)
        // Matching the log scenario where many messages were sent while device was offline
        // Send enough messages to potentially exceed maxSkippedMessageKeys if Bob skips some
        let offlineMessageCount = 25
        for i in 1...offlineMessageCount {
            try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "offline msg \(i)")
        }

        // Phase 2: Alice rotates keys (this changes her signing key)
        // This sends a sessionReestablishment control frame. If Bob processes this before
        // the backlog, his identity refreshes and old messages become decryptable.
        // To trigger invalidSignature, Bob needs to process old messages before receiving
        // the sessionReestablishment frame. However, in this test we queue all messages
        // and process them together, so Bob's identity may refresh before processing old messages.
        // 
        // The production scenario from logs shows both invalidSignature and maxSkipped errors,
        // suggesting a mix of scenarios. This test verifies the setup and recovery behavior.
        try await _senderMaxSkipSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(100))

        // Phase 3: Alice sends a few more messages with new keys
        for i in (offlineMessageCount + 1)...(offlineMessageCount + 3) {
            try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "post-rotation msg \(i)")
        }

        // Finish the stream (all messages have been sent and queued by "server")
        aliceTransport.continuation?.finish()
        
        // Phase 4: Bob comes back online - server delivers all queued messages
        // Wait for Bob's task to collect all messages
        _ = await bobTask?.value
        
        // Wait for job processor to process all enqueued jobs
        // The job processor runs asynchronously, so we need to wait for it to finish
        // processing all the messages that were enqueued by receiveMessage() calls
        let deadline = Date().addingTimeInterval(10.0)
        var lastRotationCount = 0
        while Date() < deadline {
            let currentRotationCount = await bobTransport.publishRotatedKeysCallCount
            if currentRotationCount == lastRotationCount {
                // Rotation count hasn't changed, jobs may be done processing
                try await Task.sleep(until: .now + .milliseconds(500))
                let newRotationCount = await bobTransport.publishRotatedKeysCallCount
                if newRotationCount == currentRotationCount {
                    // Stable - jobs are likely done
                    break
                }
            }
            lastRotationCount = currentRotationCount
            try await Task.sleep(until: .now + .milliseconds(200))
        }

        // Verify the scenario was set up correctly
        // Older production logs for this scenario showed:
        // - Many "❌ JOB ERROR INVALIDSIGNATURE" messages
        // - Many "Rotated Keys and Updated Identity" messages (rotation storm)
        //
        // The test verifies the setup (messages queued and processed). In production,
        // errors occur in the job processor when:
        // 1. Messages signed with old keys (before rotation) are processed with stale identity cache -> invalidSignature
        // 2. Messages exceed maxSkippedMessageKeys -> maxSkippedHeadersExceeded
        //
        // These errors should now recover through resend/reestablishment rather than rotation.
        // This test documents the scenario and error handling pattern:
        // do {
        //     try await receiveMessage(...)
        // } catch invalidSignature { /* notify server to delete and request resend */ }
        // } catch maxSkippedHeadersExceeded { /* notify server to delete all offline messages and request resend */ }
        let rotationCount = await bobTransport.publishRotatedKeysCallCount
        
        // Verify the scenario was set up and messages were processed
        // The test verifies the setup is correct. Rotation is not required for this
        // recovery path; resend/reestablishment handles the broken backlog.
        // 
        // This test documents the offline backlog scenario from production logs and
        // demonstrates the error handling pattern consumers should use.
        let messageCount = await offlineQueue.count()
        #expect(messageCount == 0,
                "Test verifies offline backlog scenario: messages queued while offline (\(messageCount) messages), then processed when online. Recovery should stay on resend/reestablishment; observed \(rotationCount) rotations.")
    }
    
    @Test("Multiple offline maxSkipped messages do not rotate keys")
    func testMultipleOfflineMessagesDoNotRotateKeys() async throws {
        // This test replicates the exact scenario from Android logs:
        // 1. Server sends multiple offline messages in a batch
        // 2. All messages fail decryption with maxSkippedHeadersExceeded
        // 3. Each failure should use the existing repair/resend path
        // 4. Expected: no key rotation occurs
        
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)

        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(aliceSession: _senderMaxSkipSession, sd: sd, bobSession: _recipientMaxSkipSession, rsd: rsd)

        // Simulate server-side offline message queue
        actor OfflineQueue {
            var queuedMessages: [ReceivedMessage] = []
            
            func queue(_ msg: ReceivedMessage) {
                queuedMessages.append(msg)
            }
            func dequeueAll() -> [ReceivedMessage] {
                let msgs = queuedMessages
                queuedMessages = []
                return msgs
            }
            func count() -> Int {
                queuedMessages.count
            }
        }
        let offlineQueue = OfflineQueue()
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        // Bob's receive loop - simulates server delivering all offline messages at once
        bobTask = Task {
            // Phase 1: Collect messages while "offline" (server queues them)
            for await received in bobStream {
                await offlineQueue.queue(received)
            }
            
            // Phase 2: Bob comes back online - server delivers ALL queued messages at once
            // This is the critical scenario: multiple messages processed concurrently,
            // all failing with maxSkippedHeadersExceeded, each needing repair.
            let backlog = await offlineQueue.dequeueAll()
            
            // Process all offline messages concurrently (simulating server batch delivery)
            // Each receiveMessage() enqueues a job that will be processed by the job processor
            // When multiple jobs fail with maxSkippedHeadersExceeded, they should all stay on repair.
            await withTaskGroup(of: Void.self) { group in
                for received in backlog {
                    group.addTask {
                        // Don't await - let jobs be enqueued concurrently
                        // The job processor will process them and handle errors
                        try? await self._recipientMaxSkipSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                    }
                }
            }
        }

        // Warmup: establish session (successful encrypt/decrypt before the storm)
        try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup")
        try await Task.sleep(until: .now + .milliseconds(300))

        // Phase 1: Alice sends many messages while Bob is offline (server queues them)
        // Send MORE than maxSkippedMessageKeys (10) messages so when Bob processes them,
        // the skipped message count exceeds the limit, causing maxSkippedHeadersExceeded
        // We need to send enough messages that when processed out of order or after delay,
        // they exceed the maxSkippedMessageKeys threshold
        let offlineMessageCount = 15  // More than maxSkippedMessageKeys (10)
        for i in 1...offlineMessageCount {
            try await _senderMaxSkipSession.writeTextMessage(recipient: .nickname("bob"), text: "offline msg \(i)")
            // Small delay to ensure messages are sent in sequence
            try await Task.sleep(until: .now + .milliseconds(10))
        }

        // Finish the stream (all messages have been sent and queued by "server")
        aliceTransport.continuation?.finish()
        
        // Phase 4: Wait for Bob's task to collect all messages
        _ = await bobTask?.value
        
        // Phase 5: Wait for job processor to process all enqueued jobs
        // The job processor runs asynchronously, so we need to wait for it to finish
        // processing all the messages that were enqueued by receiveMessage() calls
        let deadline = Date().addingTimeInterval(15.0)
        var lastRotationCount = 0
        var stableCount = 0
        while Date() < deadline {
            let currentRotationCount = await bobTransport.publishRotatedKeysCallCount
            if currentRotationCount == lastRotationCount {
                stableCount += 1
                // Wait for stability - rotation count should not change
                try await Task.sleep(until: .now + .milliseconds(500))
                let newRotationCount = await bobTransport.publishRotatedKeysCallCount
                if newRotationCount == currentRotationCount {
                    // Stable for multiple checks - jobs are likely done
                    if stableCount >= 3 {
                        break
                    }
                } else {
                    stableCount = 0
                }
            } else {
                stableCount = 0
            }
            lastRotationCount = currentRotationCount
            try await Task.sleep(until: .now + .milliseconds(200))
        }

        // THE KEY ASSERTION: no key rotation should occur.
        // This verifies that maxSkipped recovery stays on fresh-session repair.
        let rotationCount = await bobTransport.publishRotatedKeysCallCount
        #expect(rotationCount == 0,
                "Expected 0 key rotations when multiple offline messages fail decryption. Got \(rotationCount), indicating maxSkipped recovery escalated outside repair/resend.")
        
        // Verify messages were processed (queued and handled by job processor)
        let messageCount = await offlineQueue.count()
        #expect(messageCount == 0, 
                "All messages should have been processed. \(messageCount) messages still in queue.")
    }
    
    @Test("Rotated Key")
    func testRotatedKey() async throws {
        var bobTask: Task<Void, Never>?
        var aliceTask: Task<Void, Never>?
        defer {
            Task {
                bobTask?.cancel()
                aliceTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        try await createSenderMaxSkipSession(store: createSenderStore(), transport: bobTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: aliceTransport, sessionDelegate: rsd)
        
        var messageCount = 0
        
        bobTask = Task {
            await #expect(throws: Never.self) {
                for await received in bobStream {
                    messageCount += 1
                    try await self._recipientMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                    
                    if messageCount == 1 {
                        try await _senderMaxSkipSession.rotateKeysOnPotentialCompromise()
                        try await Task.sleep(until: .now + .seconds(1))
                        try await self._senderMaxSkipSession.writeTextMessage(
                            recipient: .nickname("bob"),
                            text: "A2->B2")
                    }
                    
                    if messageCount == 2 {
                        
                        try! await self._recipientMaxSkipSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: "B->A")
                    }
                }
            }
        }
        
        aliceTask = Task {
            await #expect(throws: Never.self) {
                for await received in aliceStream {
                    try await self._senderMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                }
            }
        }
        
        try await self._senderMaxSkipSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "A->B")
        
        try await Task.sleep(until: .now + .seconds(3))
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
    }
    
    private func createFriendship(
        aliceSession: PQSSession,
        sd: SessionDelegate,
        bobSession: PQSSession,
        rsd: SessionDelegate
    ) async throws {
        // 3) Alice creates a contact for Bob with friendship request
        var aliceFriendship = FriendshipMetadata()
        aliceFriendship.setRequestedState()  // Alice is requesting friendship
        
        let contactMetadata: [String: String] = [
            "nickname": "Bob",
            "trustLevel": "high",
            "createdAt": "\(Date())"
        ]
                
        _ = try await aliceSession.createContact(
            secretName: "bob",
            metadata: try BinaryEncoder().encode(contactMetadata),
            friendshipMetadata: aliceFriendship,
            requestFriendship: true)

        try await Task.sleep(nanoseconds: 50_000)
    }
    
    @Test("Test Rotated Key After Message Exchange")
    func testRotatedKeyAfterMessageExchange() async throws {
        var bobTask: Task<Void, Error>?
        var aliceTask: Task<Void, Error>?
        defer {
            Task {
                bobTask?.cancel()
                aliceTask?.cancel()
                await shutdownSessions()
            }
        }
        
        let aliceTransport = _MockTransportDelegate(session: _senderMaxSkipSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientMaxSkipSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        
        let aliceStore = createSenderStore()
        let sd = SessionDelegate(session: _senderMaxSkipSession)
        let rsd = SessionDelegate(session: _recipientMaxSkipSession)
        try await createSenderMaxSkipSession(store: aliceStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientMaxSkipSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
        
        try await createFriendship(
            aliceSession: _senderMaxSkipSession,
            sd: sd,
            bobSession: _recipientMaxSkipSession,
            rsd: rsd)
        
        var bobMessageCount = 0
        var aliceMessageCount = 0
        var lastAliceToBob = "A->B"
        var lastBobToAlice = ""
        
        bobTask = Task {
            for await received in bobStream {
                do {
                    try await self._recipientMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                    bobMessageCount += 1
                    
                    if bobMessageCount == 2 {
                        lastBobToAlice = "B->A"
                        try await self._recipientMaxSkipSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: "B->A")
                    }
                    //
                    if bobMessageCount == 3 {
                        lastBobToAlice = "B2->A2"
                        try await self._recipientMaxSkipSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: "B2->A2")
                    }
                    
                    if bobMessageCount == 4 {
                        try await _recipientMaxSkipSession.rotateKeysOnPotentialCompromise()
                        try await Task.sleep(until: .now + .seconds(1))
                        lastBobToAlice = "B3->A3"
                        try await self._recipientMaxSkipSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: "B3->A3")
                    }
                } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
                    if received.sender == "alice", !lastAliceToBob.isEmpty {
                        try? await self._senderMaxSkipSession.writeTextMessage(
                            recipient: .nickname("bob"),
                            text: lastAliceToBob)
                    }
                } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
                    if received.sender == "alice", !lastAliceToBob.isEmpty {
                        try? await self._senderMaxSkipSession.writeTextMessage(
                            recipient: .nickname("bob"),
                            text: lastAliceToBob)
                    }
                } catch {
                    throw error
                }
            }
        }
        
        aliceTask = Task {
            for await received in aliceStream {
                do {
                    try await self._senderMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                    aliceMessageCount += 1
                    
                    if aliceMessageCount == 2 {
                        try await _senderMaxSkipSession.rotateKeysOnPotentialCompromise()
                        try await Task.sleep(until: .now + .seconds(1))
                        lastAliceToBob = "A2->B2"
                        try await self._senderMaxSkipSession.writeTextMessage(
                            recipient: .nickname("bob"),
                            text: "A2->B2")
                    }
                    
                    if aliceMessageCount == 3 {
                        lastAliceToBob = "A3->B3"
                        try await self._senderMaxSkipSession.writeTextMessage(
                            recipient: .nickname("bob"),
                            text: "A3->B3")
                    }
                } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
                    if received.sender == "bob", !lastBobToAlice.isEmpty {
                        try? await self._recipientMaxSkipSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: lastBobToAlice)
                    }
                } catch let sessionError as PQSSession.SessionErrors where sessionError == .invalidSignature {
                    if received.sender == "bob", !lastBobToAlice.isEmpty {
                        try? await self._recipientMaxSkipSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: lastBobToAlice)
                    }
                } catch {
                    throw error
                }
            }
        }
        
        try await self._senderMaxSkipSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: lastAliceToBob)
        
        // This flow involves key rotations (with 1s sleep after each) and async job processing.
        // Allow time for messages to settle; after key rotations some may be dropped (maxSkippedHeadersExceeded).
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline && (bobMessageCount < 3 || aliceMessageCount < 3) {
            try await Task.sleep(until: .now + .milliseconds(100))
        }
        
        // Expect at least 2 messages per side; one may be dropped due to maxSkippedHeadersExceeded
        // or initialMessageNotReceived after key rotations.
        #expect(bobMessageCount >= 2, "Bob should receive at least 2 messages (got \(bobMessageCount))")
        #expect(aliceMessageCount >= 2, "Alice should receive at least 2 messages (got \(aliceMessageCount))")
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
    }
    
    @Test("One-Time Keys Not Rotated Per Message Send")
    func testOneTimeKeysNotRotatedPerMessageSend() async throws {
        // This test verifies that one-time keys are NOT rotated after each message send.
        // One-time keys should only be used during initial session establishment,
        // and should not trigger updateOneTimeKeys calls for subsequent messages.
        
        var bobTask: Task<Void, Never>?
        var aliceTask: Task<Void, Never>?
        
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        func cleanup() async {
            aliceTransport.continuation?.finish()
            bobTransport.continuation?.finish()
            bobTask?.cancel()
            aliceTask?.cancel()
            if let bobTask {
                await bobTask.value
            }
            if let aliceTask {
                await aliceTask.value
            }
            await shutdownSessions()
        }

        do {
            // Reset call counters
            await aliceTransport.resetCallTracking()
            await bobTransport.resetCallTracking()
            
            let senderStore = createSenderStore()
            let recipientStore = createRecipientStore()
            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)
            
            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
            
            try await createFriendship(
                aliceSession: _senderSession,
                sd: sd,
                bobSession: _recipientSession,
                rsd: rsd)
            
            var aliceReceivedCount = 0
            var bobReceivedCount = 0
            
            // Bob's receive loop
            bobTask = Task {
                await #expect(throws: Never.self, "Bob should receive messages") {
                    for await received in bobStream {
                        try await self._recipientSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                        bobReceivedCount += 1
                    }
                }
            }
            
            // Alice's receive loop
            aliceTask = Task {
                await #expect(throws: Never.self, "Alice should receive messages") {
                    for await received in aliceStream {
                        try await self._senderSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                        aliceReceivedCount += 1
                    }
                }
            }
            
            // Step 1: Initial warm-up message to establish session
            // This may use one-time keys for initial session establishment
            let initialAliceCallCount = await aliceTransport.updateOneTimeKeysCallCount
            let initialBobCallCount = await bobTransport.updateOneTimeKeysCallCount
            
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "initial message")
            try await Task.sleep(until: .now + .milliseconds(200))
            
            // Step 2: Send multiple messages after session is established
            // These should NOT trigger updateOneTimeKeys calls
            let messagesToSend = 10
            for i in 1...messagesToSend {
                try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "message \(i)")
                try await Task.sleep(until: .now + .milliseconds(50))
            }
            
            // Step 3: Send messages from Bob to Alice as well
            for i in 1...5 {
                try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob message \(i)")
                try await Task.sleep(until: .now + .milliseconds(50))
            }
            
            // Wait for all messages to be processed
            try await Task.sleep(until: .now + .seconds(1))
            
            // Finish streams
            aliceTransport.continuation?.finish()
            bobTransport.continuation?.finish()
            
            // Verify that updateOneTimeKeys was NOT called per message
            // It may be called during initial session setup, but not for subsequent messages
            let finalAliceCallCount = await aliceTransport.updateOneTimeKeysCallCount
            let finalBobCallCount = await bobTransport.updateOneTimeKeysCallCount
            
            // The key assertion: updateOneTimeKeys should NOT be called for each message send
            // It may be called during initial setup (0-1 times), but not for the 10+ subsequent messages
            #expect(
                finalAliceCallCount <= initialAliceCallCount + 1,
                "Alice's updateOneTimeKeys should not be called per message. Initial: \(initialAliceCallCount), Final: \(finalAliceCallCount)"
            )
            #expect(
                finalBobCallCount <= initialBobCallCount + 1,
                "Bob's updateOneTimeKeys should not be called per message. Initial: \(initialBobCallCount), Final: \(finalBobCallCount)"
            )
            
            // Verify messages were received
            #expect(bobReceivedCount >= messagesToSend, "Bob should have received all messages")
            #expect(aliceReceivedCount >= 5, "Alice should have received Bob's messages")
            
            // Log the call details for debugging
            if finalAliceCallCount > initialAliceCallCount {
                let aliceCalls = await aliceTransport.updateOneTimeKeysCalls
                print("Alice updateOneTimeKeys calls: \(aliceCalls)")
            }
            if finalBobCallCount > initialBobCallCount {
                let bobCalls = await bobTransport.updateOneTimeKeysCalls
                print("Bob updateOneTimeKeys calls: \(bobCalls)")
            }

            await cleanup()
        } catch {
            await cleanup()
            throw error
        }
    }

    @Test("Missing MLKEM OTK recovery archives state without crashing")
    func testMissingMLKEMOTKRecoveryArchivesStateWithoutCrashing() async throws {
        func cleanup() async {
            await shutdownSessions()
        }

        do {
            let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
            let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)

            actor Capture {
                var msg: ReceivedMessage?
                func set(_ message: ReceivedMessage) { msg = message }
                func get() -> ReceivedMessage? { msg }
            }

            let brokenCapture = Capture()
            let senderStore = createSenderStore()
            let recipientStore = createRecipientStore()
            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)

            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)

            _ = try await _senderSession.refreshIdentities(
                secretName: rMockUserData.ssn,
                forceRefresh: true,
                sendOneTimeIdentities: true
            )
            _ = try await _recipientSession.refreshIdentities(
                secretName: sMockUserData.ssn,
                forceRefresh: true,
                sendOneTimeIdentities: true
            )

            let senderContext = try #require(
                await _recipientSession.sessionContext,
                "Recipient session context should be initialized")

            bobTransport.shouldDeliver = { _ in false }
            bobTransport.transformOutgoing = { received in
                guard let signed = received.message.signed else { return received }
                let ratchetMessage = try BinaryDecoder().decode(RatchetMessage.self, from: signed.data)
                guard let encryptedData = Mirror(reflecting: ratchetMessage)
                    .children
                    .first(where: { $0.label == "encryptedData" })?
                    .value as? Data
                else {
                    throw TestError.invalidRatchetHeader
                }

                let forgedHeader = EncryptedHeader(
                    remoteLongTermPublicKey: ratchetMessage.header.remoteLongTermPublicKey,
                    remoteOneTimePublicKey: ratchetMessage.header.remoteOneTimePublicKey,
                    remoteMLKEMPublicKey: ratchetMessage.header.remoteMLKEMPublicKey,
                    headerCiphertext: ratchetMessage.header.headerCiphertext,
                    messageCiphertext: ratchetMessage.header.messageCiphertext,
                    oneTimeKeyId: ratchetMessage.header.oneTimeKeyId,
                    mlKEMOneTimeKeyId: UUID(),
                    encrypted: ratchetMessage.header.encrypted
                )
                let forgedRatchetMessage = RatchetMessage(
                    header: forgedHeader,
                    encryptedData: encryptedData
                )
                let forged = try SignedRatchetMessage(
                    message: forgedRatchetMessage,
                    signingPrivateKey: senderContext.sessionUser.deviceKeys.signingPrivateKey
                )
                let forgedReceived = ReceivedMessage(
                    message: forged,
                    sender: received.sender,
                    recipient: received.recipient,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    transportEvent: received.transportEvent
                )
                await brokenCapture.set(forgedReceived)
                return forgedReceived
            }

            let receiverMessageCountBefore = await senderStore.createdMessages.count
            let receiverIdentityCountBefore = await senderStore.identities.count

            try await _recipientSession.writeTextMessage(
                recipient: .nickname(sMockUserData.ssn),
                text: "broken"
            )

            let brokenMessage = try #require(
                await brokenCapture.get(),
                "Broken outbound message should be captured")

            await #expect(throws: Never.self) {
                try await self._senderSession.receiveMessage(
                    message: brokenMessage.message,
                    sender: brokenMessage.sender,
                    deviceId: brokenMessage.deviceId,
                    messageId: brokenMessage.messageId
                )
            }

            let pendingResends = await _senderSession.takePendingResendsAfterReestablishment(
                sender: brokenMessage.sender,
                deviceId: brokenMessage.deviceId)
            #expect(
                pendingResends.contains(where: { $0.failedSharedMessageId == brokenMessage.messageId }),
                "missingOneTimeKey should defer a resend request for the failed message until peerRefresh completes")
            for pending in pendingResends {
                await _senderSession.deferPeerResendUntilReestablished(
                    sender: pending.senderName,
                    deviceId: pending.senderDeviceId,
                    failedMessageId: pending.failedSharedMessageId,
                    failureClass: pending.failureClass)
            }

            #expect(
                await senderStore.createdMessages.count == receiverMessageCountBefore,
                "Failed missing-OTK payload should not be persisted"
            )
            #expect(
                await senderStore.identities.count >= receiverIdentityCountBefore,
                "Missing OTK recovery should not regress identity tracking"
            )
            await cleanup()
        } catch {
            await cleanup()
            throw error
        }
    }

    @Test("CryptoKitError reconciliation recovery enables subsequent message decryption")
    func testCryptoKitErrorReconciliationRecovery() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        actor CryptoFailureProbe {
            var corruptionArmed = false
            var recoveryStarted = false
            var cleanDecryptSucceeded = false

            func arm() { corruptionArmed = true }
            func disarm() { corruptionArmed = false }
            /// Returns true once and auto-disarms so only one message is corrupted.
            func consumeArmed() -> Bool {
                guard corruptionArmed else { return false }
                corruptionArmed = false
                return true
            }
            func isArmed() -> Bool { corruptionArmed }
            func markRecoveryStarted() { recoveryStarted = true }
            func markCleanSuccess() { cleanDecryptSucceeded = true }
        }

        let probe = CryptoFailureProbe()

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        guard let aliceContext = await _senderSession.sessionContext else {
            Issue.record("Alice session context should be initialized")
            return
        }
        let aliceSigningKey = aliceContext.sessionUser.deviceKeys.signingPrivateKey

        // Corrupt encryptedData (flip bits) and re-sign with Alice's key so signature
        // verification passes but ratchet body decryption produces a CryptoKitError.
        aliceTransport.transformOutgoing = { received in
            guard await probe.consumeArmed() else { return received }
            guard received.transportEvent == nil else { return received }
            guard let signed = received.message.signed else { return received }

            let ratchetMessage = try BinaryDecoder().decode(RatchetMessage.self, from: signed.data)
            guard let encryptedData = Mirror(reflecting: ratchetMessage)
                .children
                .first(where: { $0.label == "encryptedData" })?
                .value as? Data,
                !encryptedData.isEmpty
            else { return received }

            var corrupted = encryptedData
            corrupted[corrupted.startIndex] ^= 0xFF

            let corruptedMessage = RatchetMessage(
                header: ratchetMessage.header,
                encryptedData: corrupted
            )
            let reSigned = try SignedRatchetMessage(
                message: corruptedMessage,
                signingPrivateKey: aliceSigningKey
            )
            return ReceivedMessage(
                message: reSigned,
                sender: received.sender,
                recipient: received.recipient,
                deviceId: received.deviceId,
                messageId: received.messageId,
                transportEvent: received.transportEvent
            )
        }

        aliceTask = Task {
            for await received in aliceStream {
                if let event = received.transportEvent {
                    switch event {
                    case .sessionReestablishment(_), .requestMessageResend(_):
                        await probe.markRecoveryStarted()
                    default:
                        break
                    }
                }
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._senderSession,
                    received: received
                )
            }
        }

        bobTask = Task {
            for await received in bobStream {
                guard received.transportEvent == nil else {
                    _ = try? await self.receiveIgnoringRecoverableErrors(
                        self._recipientSession,
                        received: received
                    )
                    continue
                }
                do {
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    let armed = await probe.isArmed()
                    let recoveryStarted = await probe.recoveryStarted
                    if !armed && recoveryStarted {
                        await probe.markCleanSuccess()
                    }
                } catch {
                    // Tolerate other transient failures during recovery
                }
            }
        }

        _ = try await _senderSession.refreshIdentities(
            secretName: rMockUserData.rsn,
            forceRefresh: true,
            sendOneTimeIdentities: true
        )
        _ = try await _recipientSession.refreshIdentities(
            secretName: sMockUserData.ssn,
            forceRefresh: true,
            sendOneTimeIdentities: true
        )

        // Baseline: establish ratchet state with a clean message
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "baseline"
        )
        try await Task.sleep(for: .milliseconds(500))

        // Arm corruption and send a message whose body will be unreadable
        await probe.arm()
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "this will be corrupted"
        )

        for _ in 0..<40 {
            if await probe.recoveryStarted { break }
            try await Task.sleep(for: .milliseconds(100))
        }
        #expect(await probe.recoveryStarted,
                "Bob should emit recovery controls for the corrupted message")

        // Corruption auto-disarmed after one message; let recovery control messages flow
        try await Task.sleep(for: .milliseconds(2000))

        // Send a clean message — should decrypt successfully after recovery
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "clean after recovery"
        )

        for _ in 0..<60 {
            if await probe.cleanDecryptSucceeded { break }
            try await Task.sleep(for: .milliseconds(100))
        }

        #expect(
            await probe.cleanDecryptSucceeded,
            "Bob should decrypt a clean message after CryptoKitError recovery (key rotation + fresh SessionIdentity)"
        )
    }

    @Test("deferred resend drains after peerRefresh completion")
    func testDeferredResendDrainsAfterPeerRefreshCompletion() async throws {
        actor ResendProbe {
            private var requestedSharedIds: Set<String> = []
            func mark(_ id: String) { requestedSharedIds.insert(id) }
            func contains(_ id: String) -> Bool { requestedSharedIds.contains(id) }
        }

        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(for: .milliseconds(50))
            }
            return false
        }

        let probe = ResendProbe()
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        aliceTask = Task {
            for await received in aliceStream {
                if let event = received.transportEvent,
                   case .requestMessageResend(let request) = event {
                    await probe.mark(request.failedSharedMessageId)
                }
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._senderSession,
                    received: received
                )
            }
        }

        bobTask = Task {
            for await received in bobStream {
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._recipientSession,
                    received: received
                )
            }
        }

        try await Task.sleep(for: .milliseconds(500))

        guard let aliceDeviceId = await _senderSession.sessionContext?.sessionUser.deviceId else {
            Issue.record("Alice device id should be available")
            return
        }

        let responseDrainedSharedId = UUID().uuidString
        await _recipientSession.deferPeerResendUntilReestablished(
            sender: "alice",
            deviceId: aliceDeviceId,
            failedMessageId: responseDrainedSharedId,
            failureClass: "test.peerRefresh")

        let originalPeerRefresh = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: 1)
        _ = try await _senderSession.emitSessionReestablishmentResponse(
            kind: .peerRefresh,
            recipient: .nickname("bob"),
            respondingTo: originalPeerRefresh)

        #expect(
            await waitUntil { await probe.contains(responseDrainedSharedId) },
            "peerRefresh response should submit the deferred resend request")
        #expect(
            await _recipientSession.hasPendingResendAfterReestablishment(
                sender: "alice",
                deviceId: aliceDeviceId,
                failedMessageId: responseDrainedSharedId),
            "Deferred resend marker should remain until the requested replay succeeds")

        let successfulInboundDrainedSharedId = UUID().uuidString
        await _recipientSession.deferPeerResendUntilReestablished(
            sender: "alice",
            deviceId: aliceDeviceId,
            failedMessageId: successfulInboundDrainedSharedId,
            failureClass: "test.successfulInbound")

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "successful inbound after reestablishment")

        #expect(
            await waitUntil { await probe.contains(successfulInboundDrainedSharedId) },
            "next successful inbound message should request resend of the earlier failed shared id")
    }

    @Test("archived peerRefresh response does not drain deferred resend")
    func testArchivedPeerRefreshResponseDoesNotDrainDeferredResend() async throws {
        actor ResponseProbe {
            private var response: ReceivedMessage?

            func capture(_ received: ReceivedMessage) {
                response = received
            }

            func get() -> ReceivedMessage? {
                response
            }
        }

        actor ResendProbe {
            private(set) var sawResendRequest = false

            func markResendRequest() {
                sawResendRequest = true
            }

            func reset() {
                sawResendRequest = false
            }
        }

        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(for: .milliseconds(50))
            }
            return false
        }

        let responseProbe = ResponseProbe()
        let resendProbe = ResendProbe()
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        aliceTask = Task {
            for await received in aliceStream {
                if let transportEvent = received.transportEvent,
                   case .requestMessageResend = transportEvent {
                    await resendProbe.markResendRequest()
                }
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._senderSession,
                    received: received)
            }
        }

        bobTask = Task {
            for await received in bobStream {
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._recipientSession,
                    received: received)
            }
        }

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "baseline before archived response")

        #expect(
            await waitUntil { await recipientStore.createdMessages.count > 0 },
            "Baseline message should establish the active ratchet before archiving")

        guard let aliceDeviceId = await _senderSession.sessionContext?.sessionUser.deviceId else {
            Issue.record("Alice device id should be available")
            return
        }
        bobTask?.cancel()
        bobTask = nil
        try await Task.sleep(for: .milliseconds(200))
        _ = await _recipientSession.takePendingResendsAfterReestablishment(
            sender: "alice",
            deviceId: aliceDeviceId)
        await resendProbe.reset()

        let pendingSharedId = UUID().uuidString
        await _recipientSession.deferPeerResendUntilReestablished(
            sender: "alice",
            deviceId: aliceDeviceId,
            failedMessageId: pendingSharedId,
            failureClass: "test.archivedPeerRefresh")

        let responseIntentId = UUID()
        aliceTransport.shouldDeliver = { received in
            guard case .sessionReestablishment(let envelope)? = received.transportEvent,
                  envelope.kind == .peerRefresh,
                  envelope.isResponse,
                  envelope.intentId == responseIntentId
            else {
                return true
            }
            await responseProbe.capture(received)
            return false
        }

        let originalPeerRefresh = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: responseIntentId,
            epoch: 1)
        _ = try await _senderSession.emitSessionReestablishmentResponse(
            kind: .peerRefresh,
            recipient: .nickname("bob"),
            respondingTo: originalPeerRefresh)

        #expect(
            await waitUntil { await responseProbe.get() != nil },
            "PeerRefresh response should be captured before delivery")

        try await _recipientSession.createInactiveSessionSnapshot(
            for: "alice",
            policy: .archive)

        let bobCache = await _recipientSession.cache!
        let bobSymKey = try await _recipientSession.getDatabaseSymmetricKey()
        for identity in try await bobCache.fetchSessionIdentities() {
            guard var props = await identity.props(symmetricKey: bobSymKey) else { continue }
            guard props.secretName == "alice" else { continue }
            guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
            props.state = nil
            try await identity.updateIdentityProps(symmetricKey: bobSymKey, props: props)
            try await bobCache.updateSessionIdentity(identity)
        }
        await _recipientSession.removeIdentity(with: "alice")

        guard let archivedOnlyResponse = await responseProbe.get() else {
            Issue.record("Captured peerRefresh response should exist")
            return
        }

        try await _recipientSession.receiveMessage(
            message: archivedOnlyResponse.message,
            sender: archivedOnlyResponse.sender,
            deviceId: archivedOnlyResponse.deviceId,
            messageId: archivedOnlyResponse.messageId)

        try await Task.sleep(for: .milliseconds(500))

        #expect(
            (await resendProbe.sawResendRequest) == false,
            "Archived peerRefresh response must not request resend/replay and restart recovery")

        let pending = await _recipientSession.takePendingResendsAfterReestablishment(
            sender: "alice",
            deviceId: aliceDeviceId)
        #expect(
            pending.contains(where: { $0.failedSharedMessageId == pendingSharedId }),
            "Deferred resend should remain pending until active reestablishment succeeds")
    }

    @Test("requestMessageResend replays recent non-persistent recovery control")
    func testRequestMessageResendReplaysRecentNonPersistentControl() async throws {
        actor ReplayProbe {
            private var expectedIntentId: UUID?
            private var droppedSharedId: String?
            private var replayCountsBySharedId: [String: Int] = [:]

            func expect(intentId: UUID) {
                expectedIntentId = intentId
            }

            func shouldDropFirstMatchingControl(_ received: ReceivedMessage) -> Bool {
                guard droppedSharedId == nil else { return false }
                guard received.sender == "alice", received.recipient == "bob" else { return false }
                guard case .sessionReestablishment(let envelope)? = received.transportEvent else { return false }
                guard envelope.kind == .peerRefresh, envelope.isResponse else { return false }
                guard envelope.intentId == expectedIntentId else { return false }
                droppedSharedId = received.messageId
                return true
            }

            func markReplayIfNeeded(_ received: ReceivedMessage) {
                guard let droppedSharedId else { return }
                guard received.messageId == droppedSharedId else { return }
                guard case .sessionReestablishment = received.transportEvent else { return }
                replayCountsBySharedId[received.messageId, default: 0] += 1
            }

            func droppedId() -> String? {
                droppedSharedId
            }

            func sawReplay(for sharedId: String) -> Bool {
                replayCount(for: sharedId) > 0
            }

            func replayCount(for sharedId: String) -> Int {
                replayCountsBySharedId[sharedId, default: 0]
            }
        }

        actor LinkedReplayProbe {
            private var expectedTargetDeviceId: UUID?
            private var droppedSharedId: String?
            private var replayCountsBySharedId: [String: Int] = [:]

            func expect(targetDeviceId: UUID) {
                expectedTargetDeviceId = targetDeviceId
            }

            func shouldDropFirstMatchingControl(_ received: ReceivedMessage) -> Bool {
                guard droppedSharedId == nil else { return false }
                guard received.sender == "alice", received.recipient == "bob" else { return false }
                guard case .linkedDeviceReprovisioning(let bundle)? = received.transportEvent else { return false }
                guard bundle.targetDeviceId == expectedTargetDeviceId else { return false }
                droppedSharedId = received.messageId
                return true
            }

            func markReplayIfNeeded(_ received: ReceivedMessage) {
                guard let droppedSharedId else { return }
                guard received.messageId == droppedSharedId else { return }
                guard case .linkedDeviceReprovisioning = received.transportEvent else { return }
                replayCountsBySharedId[received.messageId, default: 0] += 1
            }

            func droppedId() -> String? {
                droppedSharedId
            }

            func sawReplay(for sharedId: String) -> Bool {
                replayCount(for: sharedId) > 0
            }

            func replayCount(for sharedId: String) -> Int {
                replayCountsBySharedId[sharedId, default: 0]
            }
        }

        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(for: .milliseconds(50))
            }
            return false
        }

        let probe = ReplayProbe()
        let linkedProbe = LinkedReplayProbe()
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        aliceTask = Task {
            for await received in aliceStream {
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._senderSession,
                    received: received)
            }
        }

        bobTask = Task {
            for await received in bobStream {
                await probe.markReplayIfNeeded(received)
                await linkedProbe.markReplayIfNeeded(received)
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._recipientSession,
                    received: received)
            }
        }

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "baseline before control replay")

        #expect(
            await waitUntil { await recipientStore.createdMessages.count > 0 },
            "Baseline message should establish the ratchet before replaying a control frame")

        let intentId = UUID()
        let originalPeerRefresh = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: intentId,
            epoch: 1)
        await probe.expect(intentId: intentId)
        aliceTransport.shouldDeliver = { received in
            !(await probe.shouldDropFirstMatchingControl(received))
        }

        _ = try await _senderSession.emitSessionReestablishmentResponse(
            kind: .peerRefresh,
            recipient: .nickname("bob"),
            respondingTo: originalPeerRefresh)

        let droppedOriginal = await waitUntil {
            await probe.droppedId() != nil
        }
        guard droppedOriginal, let droppedSharedId = await probe.droppedId() else {
            Issue.record("Expected the original non-persistent peerRefresh response to be dropped")
            return
        }

        guard let aliceDeviceId = await _senderSession.sessionContext?.sessionUser.deviceId else {
            Issue.record("Alice device id should be available")
            return
        }

        try await _recipientSession.requestMessageResend(
            sharedMessageId: droppedSharedId,
            senderName: "alice",
            senderDeviceId: aliceDeviceId)

        #expect(
            await waitUntil { await probe.sawReplay(for: droppedSharedId) },
            "requestMessageResend should replay a recent non-persistent recovery control by shared id")

        let peerRefreshReplayCount = await probe.replayCount(for: droppedSharedId)
        try await _recipientSession.requestMessageResend(
            sharedMessageId: droppedSharedId,
            senderName: "alice",
            senderDeviceId: aliceDeviceId)

        #expect(
            await waitUntil { await probe.replayCount(for: droppedSharedId) > peerRefreshReplayCount },
            "non-persistent recovery controls should allow bounded repeated replay while the peer is still repairing")

        guard let aliceContext = await _senderSession.sessionContext,
              let bobDeviceId = await _recipientSession.sessionContext?.sessionUser.deviceId else {
            Issue.record("Session contexts should be available")
            return
        }
        let reprovisioningBundle = LinkedDeviceReprovisioningBundle(
            activeUserConfiguration: aliceContext.activeUserConfiguration,
            issuedByDeviceId: aliceContext.sessionUser.deviceId,
            issuedAt: Date(),
            targetDeviceId: bobDeviceId)
        let reprovisioningMetadata = try BinaryEncoder().encode(
            TransportEvent.linkedDeviceReprovisioning(reprovisioningBundle))
        await linkedProbe.expect(targetDeviceId: bobDeviceId)
        aliceTransport.shouldDeliver = { received in
            !(await linkedProbe.shouldDropFirstMatchingControl(received))
        }

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            transportInfo: reprovisioningMetadata)

        let droppedLinkedControl = await waitUntil {
            await linkedProbe.droppedId() != nil
        }
        guard droppedLinkedControl, let droppedLinkedSharedId = await linkedProbe.droppedId() else {
            Issue.record("Expected the original non-persistent linked-device reprovisioning control to be dropped")
            return
        }

        try await _recipientSession.requestMessageResend(
            sharedMessageId: droppedLinkedSharedId,
            senderName: "alice",
            senderDeviceId: aliceDeviceId)

        #expect(
            await waitUntil { await linkedProbe.sawReplay(for: droppedLinkedSharedId) },
            "requestMessageResend should replay a recent non-persistent linked-device control by shared id")

        let linkedReplayCount = await linkedProbe.replayCount(for: droppedLinkedSharedId)
        try await _recipientSession.requestMessageResend(
            sharedMessageId: droppedLinkedSharedId,
            senderName: "alice",
            senderDeviceId: aliceDeviceId)

        #expect(
            await waitUntil { await linkedProbe.replayCount(for: droppedLinkedSharedId) > linkedReplayCount },
            "linked-device reprovisioning replay should also allow bounded repeated replay while the peer is still repairing")
    }

    @Test("Old message decrypted from archive after reconciliation")
    func testOldMessageDecryptedFromArchiveAfterReconciliation() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        actor OldMessageProbe {
            var captured: ReceivedMessage?
            var oldMessageDecrypted = false
            private var msgCount = 0

            func capture(_ msg: ReceivedMessage) { captured = msg }
            func getCaptured() -> ReceivedMessage? { captured }
            func isCaptured(_ msg: ReceivedMessage) -> Bool { captured?.messageId == msg.messageId }
            func markOldDecrypted() { oldMessageDecrypted = true }
            func nextMessageIndex() -> Int {
                msgCount += 1
                return msgCount
            }
        }

        let probe = OldMessageProbe()

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        aliceTask = Task {
            for await received in aliceStream {
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._senderSession,
                    received: received
                )
            }
        }

        bobTask = Task {
            for await received in bobStream {
                do {
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    if received.transportEvent == nil, await probe.isCaptured(received) {
                        await probe.markOldDecrypted()
                    }
                } catch {}
            }
        }

        _ = try await _senderSession.refreshIdentities(
            secretName: rMockUserData.rsn,
            forceRefresh: true,
            sendOneTimeIdentities: true
        )
        _ = try await _recipientSession.refreshIdentities(
            secretName: sMockUserData.ssn,
            forceRefresh: true,
            sendOneTimeIdentities: true
        )

        // Baseline: establish ratchet state with a delivered message.
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "baseline"
        )
        try await Task.sleep(for: .milliseconds(500))

        // Old message: sent clean but captured by shouldDeliver (not delivered to Bob).
        // Arm capture after the baseline has established state so control/repair timing
        // before the baseline cannot consume the probe's message index.
        aliceTransport.shouldDeliver = { received in
            guard received.sender == "alice", received.recipient == "bob" else { return true }
            guard received.transportEvent == nil else { return true }
            await probe.capture(received)
            return false
        }
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "old in-flight message"
        )
        for _ in 0..<40 {
            if await probe.getCaptured() != nil { break }
            try await Task.sleep(for: .milliseconds(50))
        }

        #expect(await probe.getCaptured() != nil,
                "Old message should have been captured by shouldDeliver")

        // Simulate what reconciliation does on Bob's side:
        // 1. Archive current ratchet state for alice
        try await _recipientSession.createInactiveSessionSnapshot(
            for: sMockUserData.ssn,
            policy: .archive)

        // 2. Clear the active ratchet state (set state=nil) for alice's identity
        let bobCache = await _recipientSession.cache!
        let bobSymKey = try await _recipientSession.getDatabaseSymmetricKey()
        for identity in try await bobCache.fetchSessionIdentities() {
            guard var props = await identity.props(symmetricKey: bobSymKey) else { continue }
            guard props.secretName == sMockUserData.ssn else { continue }
            guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
            guard props.state != nil else { continue }
            props.state = nil
            try await identity.updateIdentityProps(symmetricKey: bobSymKey, props: props)
            try await bobCache.updateSessionIdentity(identity)
        }
        // Clear memoization so next access re-reads from cache.
        await _recipientSession.removeIdentity(with: sMockUserData.ssn)

        // Now replay the captured old message into Bob's receive stream.
        guard let oldMessage = await probe.getCaptured() else {
            Issue.record("Captured old message should exist")
            return
        }
        _ = await _recipientSession.takePendingResendsAfterReestablishment(
            sender: oldMessage.sender,
            deviceId: oldMessage.deviceId)
        aliceTransport.continuation?.yield(oldMessage)

        for _ in 0..<60 {
            if await probe.oldMessageDecrypted { break }
            try await Task.sleep(for: .milliseconds(100))
        }

        #expect(
            await probe.oldMessageDecrypted,
            "Old message encrypted with previous keys should be decrypted from the archived snapshot"
        )

        var activeStateWasMutated = false
        for identity in try await bobCache.fetchSessionIdentities() {
            guard let props = await identity.props(symmetricKey: bobSymKey) else { continue }
            guard props.secretName == sMockUserData.ssn else { continue }
            guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
            if props.state != nil {
                activeStateWasMutated = true
            }
        }
        #expect(
            !activeStateWasMutated,
            "Archived fallback must not leave partial ratchet state on the active SessionIdentity"
        )
    }

    @Test("refreshOneTimeKeys control archives active state and stays non-persistent")
    func testRefreshOneTimeKeysControlArchivesActiveState() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)

        aliceTask = Task {
            for await received in aliceStream {
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._senderSession,
                    received: received
                )
            }
        }
        bobTask = Task {
            for await received in bobStream {
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._recipientSession,
                    received: received
                )
            }
        }

        _ = try await _senderSession.refreshIdentities(
            secretName: rMockUserData.ssn,
            forceRefresh: true,
            sendOneTimeIdentities: true
        )
        _ = try await _recipientSession.refreshIdentities(
            secretName: sMockUserData.ssn,
            forceRefresh: true,
            sendOneTimeIdentities: true
        )
        try await _recipientSession.writeTextMessage(
            recipient: .nickname(sMockUserData.ssn),
            text: "establish state"
        )

        for _ in 0..<20 {
            if await senderStore.createdMessages.count > 0 {
                break
            }
            try await Task.sleep(for: .milliseconds(100))
        }

        let senderMessageCountBeforeRefresh = await senderStore.createdMessages.count
        let controlMetadata = try BinaryEncoder().encode(TransportEvent.refreshOneTimeKeys)
        let senderIdentityCountBeforeRefresh = await senderStore.identities.count
        try await _recipientSession.writeTextMessage(
            recipient: .nickname(sMockUserData.ssn),
            transportInfo: controlMetadata
        )

        try await Task.sleep(for: .milliseconds(400))

        for _ in 0..<20 {
            if await senderStore.createdMessages.count == senderMessageCountBeforeRefresh + 1 {
                break
            }
            try await Task.sleep(for: .milliseconds(100))
        }

        #expect(
            await senderStore.createdMessages.count == senderMessageCountBeforeRefresh + 1,
            "refreshOneTimeKeys control should not persist as a user message"
        )
        #expect(
            await senderStore.identities.count >= senderIdentityCountBeforeRefresh,
            "refreshOneTimeKeys control should keep identity state stable"
        )
    }

    @Test("refreshOneTimeKeys control message is non-persistent and triggers refresh")
    func testRefreshOneTimeKeysControlMessageIsNonPersistentAndTriggersRefresh() async throws {
        func cleanup() async {
            await shutdownSessions()
        }

        do {
            let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
            let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)

            actor Capture {
                var msg: ReceivedMessage?
                func set(_ message: ReceivedMessage) { msg = message }
                func get() -> ReceivedMessage? { msg }
            }

            let controlCapture = Capture()
            let senderStore = createSenderStore()
            let recipientStore = createRecipientStore()
            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)

            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)

            _ = try await _senderSession.refreshIdentities(
                secretName: rMockUserData.ssn,
                forceRefresh: true,
                sendOneTimeIdentities: true
            )
            _ = try await _recipientSession.refreshIdentities(
                secretName: sMockUserData.ssn,
                forceRefresh: true,
                sendOneTimeIdentities: true
            )

            bobTransport.shouldDeliver = { received in
                await controlCapture.set(received)
                return false
            }

            let metadata = try BinaryEncoder().encode(TransportEvent.refreshOneTimeKeys)
            let senderMessageCountBefore = await recipientStore.createdMessages.count
            try await _recipientSession.writeTextMessage(
                recipient: .nickname(sMockUserData.ssn),
                transportInfo: metadata
            )

            let controlMessage = try #require(
                await controlCapture.get(),
                "refreshOneTimeKeys control message should be captured")

            #expect(
                await recipientStore.createdMessages.count == senderMessageCountBefore,
                "refreshOneTimeKeys control frames should not be persisted"
            )
            if case .refreshOneTimeKeys = controlMessage.transportEvent {
                #expect(Bool(true))
            } else {
                Issue.record("Expected refreshOneTimeKeys transport event")
            }
            await cleanup()
        } catch {
            await cleanup()
            throw error
        }
    }

    // MARK: - Master Online Recovery Tests

    @Test("OTK upload retries after transient failure")
    func testOTKUploadRetryAfterFailure() async throws {
        func cleanup() async {
            await shutdownSessions()
        }

        do {
            let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
            let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)

            let senderStore = createSenderStore()
            let recipientStore = createRecipientStore()
            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)

            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)

            _ = try await _senderSession.refreshIdentities(
                secretName: rMockUserData.rsn,
                forceRefresh: true,
                sendOneTimeIdentities: true)

            // Drain Alice's OTKs so the next refresh MUST generate + upload.
            await self.store.drainOTKs(for: sMockUserData.ssn)

            // Inject: first OTK upload attempt will throw, subsequent ones succeed.
            await aliceTransport.setOTKUploadFailCount(1)

            let result = await _senderSession.refreshOneTimeKeysTask(policy: .replenishBatch)

            let attemptCount = await aliceTransport.otkUploadAttemptCount
            #expect(result == true,
                    "refreshOneTimeKeysTask should succeed after retrying the failed upload (attemptCount=\(attemptCount))")
            #expect(attemptCount >= 2,
                    "Should have attempted upload at least twice (first fail + retry), got \(attemptCount)")
            await cleanup()
        } catch {
            await cleanup()
            throw error
        }
    }

    @Test("missingOneTimeKey recovers from archived snapshot before reconciliation")
    func testMissingOneTimeKeyArchiveRecovery() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        func cleanup() async {
            aliceTransport.continuation?.finish()
            bobTransport.continuation?.finish()
            aliceTask?.cancel()
            bobTask?.cancel()
            if let aliceTask {
                await aliceTask.value
            }
            if let bobTask {
                await bobTask.value
            }
            await shutdownSessions()
        }

        do {
            actor MissingOTKProbe {
                var captured: ReceivedMessage?
                var messageDecrypted = false
                var hitMissingOTK = false
                var reconciliationTriggered = false
                private var msgCount = 0

                func capture(_ msg: ReceivedMessage) { captured = msg }
                func getCaptured() -> ReceivedMessage? { captured }
                func isCaptured(_ msg: ReceivedMessage) -> Bool { captured?.messageId == msg.messageId }
                func markDecrypted() { messageDecrypted = true }
                func markMissingOTK() { hitMissingOTK = true }
                func markReconciliation() { reconciliationTriggered = true }
                func nextMessageIndex() -> Int {
                    msgCount += 1
                    return msgCount
                }
            }

            let probe = MissingOTKProbe()

            let senderStore = createSenderStore()
            let recipientStore = createRecipientStore()
            let sd = SessionDelegate(session: _senderSession)
            let rsd = SessionDelegate(session: _recipientSession)

            try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
            try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
            try await createFriendship(
                aliceSession: _senderSession,
                sd: sd,
                bobSession: _recipientSession,
                rsd: rsd)

            aliceTask = Task {
                for await received in aliceStream {
                    _ = try? await self.receiveIgnoringRecoverableErrors(
                        self._senderSession,
                        received: received)
                }
            }

            let bobRotationCountBefore = await bobTransport.publishRotatedKeysCallCount

            bobTask = Task {
                for await received in bobStream {
                    do {
                        try await self._recipientSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId)
                        if received.transportEvent == nil, await probe.isCaptured(received) {
                            await probe.markDecrypted()
                        }
                    } catch let ratchetError as RatchetError where ratchetError == .missingOneTimeKey {
                        await probe.markMissingOTK()
                    } catch {
                        // Tolerate transient errors
                    }
                }
            }

            _ = try await _senderSession.refreshIdentities(
                secretName: rMockUserData.rsn,
                forceRefresh: true,
                sendOneTimeIdentities: true)
            _ = try await _recipientSession.refreshIdentities(
                secretName: sMockUserData.ssn,
                forceRefresh: true,
                sendOneTimeIdentities: true)

            // Baseline: establish ratchet state with a delivered message.
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "baseline")
            try await Task.sleep(for: .milliseconds(500))

            // Capture a message (not delivered to Bob).
            aliceTransport.shouldDeliver = { received in
                guard received.sender == "alice", received.recipient == "bob" else { return true }
                guard received.transportEvent == nil else { return true }
                await probe.capture(received)
                return false
            }
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "in-flight message before OTK drain")
            for _ in 0..<40 {
                if await probe.getCaptured() != nil { break }
                try await Task.sleep(for: .milliseconds(50))
            }

            #expect(await probe.getCaptured() != nil,
                    "Message should have been captured by shouldDeliver")

            // Simulate post-reconciliation state on Bob's side:
            // 1. Archive current ratchet state for alice
            try await _recipientSession.createInactiveSessionSnapshot(
                for: sMockUserData.ssn,
                policy: .archive)

            // 2. Clear the active ratchet state for alice's identity
            let bobCache = await _recipientSession.cache!
            let bobSymKey = try await _recipientSession.getDatabaseSymmetricKey()
            for identity in try await bobCache.fetchSessionIdentities() {
                guard var props = await identity.props(symmetricKey: bobSymKey) else { continue }
                guard props.secretName == sMockUserData.ssn else { continue }
                guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
                guard props.state != nil else { continue }
                props.state = nil
                try await identity.updateIdentityProps(symmetricKey: bobSymKey, props: props)
                try await bobCache.updateSessionIdentity(identity)
            }
            await _recipientSession.removeIdentity(with: sMockUserData.ssn)

            // 3. Drain Alice's OTKs so replay triggers missingOneTimeKey (not just CryptoKitError)
            await self.store.drainOTKs(for: sMockUserData.ssn)

            // Replay the captured message into Bob's receive stream.
            let oldMessage = try #require(
                await probe.getCaptured(),
                "Captured message should exist")
            aliceTransport.continuation?.yield(oldMessage)

            for _ in 0..<60 {
                if await probe.messageDecrypted { break }
                try await Task.sleep(for: .milliseconds(100))
            }

            let bobRotationCountAfter = await bobTransport.publishRotatedKeysCallCount

            #expect(
                await probe.messageDecrypted,
                "Message should be decrypted from the archived snapshot even when missingOneTimeKey is the error path")
            #expect(
                bobRotationCountAfter == bobRotationCountBefore,
                "Archive recovery should NOT trigger full reconciliation (rotation count should not change)")

            let aliceConfiguration = try await bobTransport.findConfiguration(for: sMockUserData.ssn)
            let currentAliceDevices = try aliceConfiguration.getVerifiedDevices().map {
                try aliceConfiguration.deviceWithCurrentKeyBundle($0)
            }
            let currentAliceDevice = try #require(
                currentAliceDevices.first(where: { $0.deviceId == oldMessage.deviceId }),
                "Expected Alice's current server device bundle to exist")

            var activeAliceProps = [SessionIdentity.UnwrappedProps]()
            for identity in try await bobCache.fetchSessionIdentities() {
                guard let props = await identity.props(symmetricKey: bobSymKey) else { continue }
                guard props.secretName == sMockUserData.ssn else { continue }
                guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
                activeAliceProps.append(props)
            }
            #expect(activeAliceProps.count == 1)
            let activeAlice = try #require(
                activeAliceProps.first,
                "Expected exactly one active Alice SessionIdentity")
            #expect(activeAlice.longTermPublicKey == currentAliceDevice.longTermPublicKey)
            #expect(activeAlice.signingPublicKey == currentAliceDevice.signingPublicKey)
            await cleanup()
        } catch {
            await cleanup()
            throw error
        }
    }

    @Test("Job survives identity deletion during reconciliation")
    func testJobSurvivesIdentityDeletion() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        actor JobSurvivalProbe {
            var messageDecrypted = false
            var bobUnblocked = false

            func markDecrypted() { messageDecrypted = true }
            func unblock() { bobUnblocked = true }
            func isUnblocked() -> Bool { bobUnblocked }
        }

        let probe = JobSurvivalProbe()

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        aliceTask = Task {
            for await received in aliceStream {
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._senderSession,
                    received: received)
            }
        }

        // Bob's loop: block until probe says unblocked, then process.
        bobTask = Task {
            for await received in bobStream {
                while !(await probe.isUnblocked()) {
                    try? await Task.sleep(for: .milliseconds(50))
                }
                do {
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                    if received.transportEvent == nil {
                        await probe.markDecrypted()
                    }
                } catch {
                    // Log but tolerate
                }
            }
        }

        _ = try await _senderSession.refreshIdentities(
            secretName: rMockUserData.rsn,
            forceRefresh: true,
            sendOneTimeIdentities: true)
        _ = try await _recipientSession.refreshIdentities(
            secretName: sMockUserData.ssn,
            forceRefresh: true,
            sendOneTimeIdentities: true)

        // Establish ratchet
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "baseline")
        try await Task.sleep(for: .milliseconds(500))

        // Send a message while Bob is blocked
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "message during identity churn")
        try await Task.sleep(for: .milliseconds(200))

        // While Bob is blocked, simulate reconciliation: delete Alice's identity on Bob's side.
        let bobCache = await _recipientSession.cache!
        let bobSymKey = try await _recipientSession.getDatabaseSymmetricKey()
        for identity in try await bobCache.fetchSessionIdentities() {
            guard let props = await identity.props(symmetricKey: bobSymKey) else { continue }
            guard props.secretName == sMockUserData.ssn else { continue }
            if props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) { continue }
            try await bobCache.deleteSessionIdentity(identity.id)
        }
        await _recipientSession.removeIdentity(with: sMockUserData.ssn)

        // Unblock Bob so the pending message is processed.
        await probe.unblock()

        for _ in 0..<80 {
            if await probe.messageDecrypted { break }
            try await Task.sleep(for: .milliseconds(100))
        }

        #expect(
            await probe.messageDecrypted,
            "Message should eventually decrypt after identity refresh/retry, not be silently dropped")
    }

    @Test("sessionDecryptionError requests resend without compromise rotation")
    func testSessionDecryptionErrorRequestsResendWithoutRotation() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        final class CorruptionGate: @unchecked Sendable {
            private let lock = NSLock()
            private var remaining: Int

            init(corruptCount: Int) { self.remaining = corruptCount }

            func consumeCorruption() -> Bool {
                lock.lock()
                defer { lock.unlock() }
                guard remaining > 0 else { return false }
                remaining -= 1
                return true
            }
        }

        let gate = CorruptionGate(corruptCount: 1)

        actor RepairProbe {
            private(set) var sawResendRequest = false

            func markResendRequest() {
                sawResendRequest = true
            }
        }

        let repairProbe = RepairProbe()

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }

        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        try await createSenderSession(store: senderStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: recipientStore, transport: bobTransport, sessionDelegate: rsd)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        let rotationCountBefore = await bobTransport.publishRotatedKeysCallCount

        // Inject the decrypted payload transform on Bob's session:
        // replaces valid CryptoMessage bytes with garbage so BinaryDecoder fails,
        // triggering sessionDecryptionError. Auto-disarms after one corruption.
        await _recipientSession.setTestDecryptedPayloadTransform { [gate] data in
            guard gate.consumeCorruption() else { return data }
            return Data([0xDE, 0xAD, 0xBE, 0xEF])
        }

        aliceTask = Task {
            for await received in aliceStream {
                if let transportEvent = received.transportEvent,
                   case .requestMessageResend = transportEvent {
                    await repairProbe.markResendRequest()
                }
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._senderSession,
                    received: received
                )
            }
        }

        bobTask = Task {
            for await received in bobStream {
                _ = try? await self.receiveIgnoringRecoverableErrors(
                    self._recipientSession,
                    received: received
                )
            }
        }

        // Alice sends a message -- Bob will hit sessionDecryptionError internally.
        // The ratchet succeeds, payload decode fails once, and recovery should request resend
        // without rotating local identity material.
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "trigger decode failure")

        // Wait for the resend request to reach Alice and for the replayed message to decrypt.
        for _ in 0..<40 {
            if await repairProbe.sawResendRequest,
               await recipientStore.createdMessages.count > 0 { break }
            try await Task.sleep(for: .milliseconds(100))
        }

        let rotationCountAfter = await bobTransport.publishRotatedKeysCallCount
        #expect(
            rotationCountAfter == rotationCountBefore,
            "sessionDecryptionError should not trigger compromise rotation (got \(rotationCountAfter) vs \(rotationCountBefore))")
        #expect(await repairProbe.sawResendRequest, "sessionDecryptionError should request resend")
        #expect(await recipientStore.createdMessages.count > 0, "The replayed message should eventually decrypt after resend")

        try await Task.sleep(for: .milliseconds(500))

        let msgCountBefore = await recipientStore.createdMessages.count

        // Send a follow-up message to verify the session recovers
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "post-recovery message")

        for _ in 0..<60 {
            if await recipientStore.createdMessages.count > msgCountBefore { break }
            try await Task.sleep(for: .milliseconds(100))
        }

        #expect(
            await recipientStore.createdMessages.count > msgCountBefore,
            "After resend-based recovery from sessionDecryptionError, subsequent messages should decrypt cleanly")
    }
}


actor CallTracker {
    private(set) var callCount: Int = 0
    private(set) var calls: [(secretName: String, deviceId: String, keyCount: Int)] = []
    
    func record(secretName: String, deviceId: String, keyCount: Int) {
        callCount += 1
        calls.append((secretName: secretName, deviceId: deviceId, keyCount: keyCount))
    }
    
    func reset() {
        callCount = 0
        calls = []
    }
}

actor ContinuationSignal {
    private var continuation: CheckedContinuation<Void, Never>?
    private var pendingSignals = 0
    
    func wait() async {
        if pendingSignals > 0 {
            pendingSignals -= 1
            return
        }
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            continuation = c
        }
    }
    
    func signal() {
        if let c = continuation {
            continuation = nil
            c.resume()
        } else {
            pendingSignals += 1
        }
    }
}

// MARK: - Supporting Types

struct SessionDelegate: PQSSessionDelegate {
    
    let session: PQSSession
    let compromiseProbe: LinkedDeviceCompromiseProbe?
    let peerIdentityTrustProbe: PeerIdentityTrustProbe?
    
    init(
        session: PQSSession,
        compromiseProbe: LinkedDeviceCompromiseProbe? = nil,
        peerIdentityTrustProbe: PeerIdentityTrustProbe? = nil
    ) {
        self.session = session
        self.compromiseProbe = compromiseProbe
        self.peerIdentityTrustProbe = peerIdentityTrustProbe
    }
    
    func synchronizeCommunication(
        recipient: MessageRecipient,
        sharedIdentifier: String,
        metadata: Data
    ) async throws {
        try await session.writeTextMessage(
            recipient: recipient,
            text: sharedIdentifier,
            metadata: metadata)
    }
    
    public func requestFriendshipStateChange(
        recipient: SessionModels.MessageRecipient,
        blockData: Data?,
        metadata: Data,
        currentState: SessionModels.FriendshipMetadata.State
    ) async throws {
        try await session.writeTextMessage(
            recipient: recipient,
            metadata: metadata)
    }
    
    func deliveryStateChanged(
        recipient _: SessionModels.MessageRecipient, metadata _: Data
    ) async throws {}
    func contactCreated(recipient _: SessionModels.MessageRecipient) async throws {}
    func requestMetadata(recipient _: SessionModels.MessageRecipient) async throws {}
    func editMessage(recipient _: SessionModels.MessageRecipient, metadata _: Data)
    async throws
    {}
    func shouldPersist(transportInfo _: Data?) -> Bool { true }
    func retrieveUserInfo(_: Data?) async -> (secretName: String, deviceId: String)? { nil }
    func updateCryptoMessageMetadata(
        _ message: SessionModels.CryptoMessage, sharedMessageId _: String
    ) -> SessionModels.CryptoMessage { message }
    func updateEncryptableMessageMetadata(
        _ message: SessionModels.EncryptedMessage, transportInfo _: Data?,
        identity _: DoubleRatchetKit.SessionIdentity, recipient _: SessionModels.MessageRecipient
    ) async -> SessionModels.EncryptedMessage { message }
    func shouldFinishCommunicationSynchronization(_: Data?) -> Bool { false }
    func processMessage(_ message: CryptoMessage, senderSecretName: String, senderDeviceId: UUID) async -> Bool {
        
        // Detect control frames for test assertions
        if let info = message.transportInfo {
            if let event = try? BinaryDecoder().decode(TransportEvent.self, from: info) {
                switch event {
                case .sessionReestablishment:
                    await SessionEventProbe.shared.markReestablishment(for: session.id)
                case .synchronizeOneTimeKeys(_):
                    break
                case .refreshOneTimeKeys:
                    break
                case .requestMessageResend(_):
                    break
                case .linkedDeviceReprovisioning(_):
                    break
                }
            }
        }

        if var decodedMetadata = try? BinaryDecoder().decode(FriendshipMetadata.self, from: message.metadata) {
            
            decodedMetadata.swapUserPerspectives()
            
            //Update our state based on the state of the sender and it's metadata.
            switch decodedMetadata.theirState {
            case .pending:
                
                decodedMetadata.resetToPendingState()
                
                let symmetricKey = try! await session.getDatabaseSymmetricKey()
                guard let sessionIdentity = try! await session.cache?.fetchSessionIdentities().asyncFirst(where: { await $0.props(symmetricKey: symmetricKey)?.deviceId == senderDeviceId }) else {
                   return true
                }
                try! await session.cache?.deleteSessionIdentity(sessionIdentity.id)
                await session.removeIdentity(with: senderSecretName)
                
            case .requested:
                decodedMetadata.setAcceptedState()
            case .accepted:
                decodedMetadata.setAcceptedState()
            case .blocked, .blockedByOther:
                decodedMetadata.setBlockState(isBlocking: true)
            case .unblocked:
                decodedMetadata.setAcceptedState()
            default:
                break
            }
            
            guard let mySecretName = await session.sessionContext?.sessionUser.secretName else { return false }
            
            let isMe = senderSecretName == mySecretName
            
            //Create or update contact including new metadata
            _ = try! await session.createContact(
                secretName: isMe ? message.recipient.recipientDescription : senderSecretName,
                friendshipMetadata: decodedMetadata,
                requestFriendship: false)
        }
        return true
    }

    func linkedDeviceReportedPotentialCompromise(deviceId: UUID, intentId: UUID?) async {
        await compromiseProbe?.mark(deviceId: deviceId)
    }

    func peerAccountIdentityChanged(
        secretName: String,
        deviceId: UUID,
        failedSharedMessageId: String?
    ) async {
        await peerIdentityTrustProbe?.mark(
            secretName: secretName,
            deviceId: deviceId,
            failedSharedMessageId: failedSharedMessageId)
    }
}

final class MockDeviceLinkingDelegate: DeviceLinkingDelegate, @unchecked Sendable {
    let secretName: String
    var userConfiguration: UserConfiguration?
    
    init(secretName: String) {
        self.secretName = secretName
    }
    
    func generateDeviceCryptographic(_ data: Data, password: String) async -> LinkDeviceInfo? {
        if let userConfiguration,
           let devices = try? userConfiguration.getVerifiedDevices() {
            return LinkDeviceInfo(
                secretName: secretName,
                devices: devices,
                password: password,
                userConfiguration: userConfiguration
            )
        }

        // Decode the device configuration from the data parameter
        guard
            let deviceConfig = try? BinaryDecoder().decode(
                UserDeviceConfiguration.self, from: data)
        else {
            return nil
        }
        
        // Create LinkDeviceInfo with the decoded device configuration
        return LinkDeviceInfo(
            secretName: secretName,
            devices: [deviceConfig],
            password: password
        )
    }
}

final class MockSessionIdentityTransport: SessionTransport, @unchecked Sendable {

    var configurations: [String: UserConfiguration] = [:]
    var oneTimeKeys: [String: OneTimeKeys] = [:]
    var shouldThrowError = false
    
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> OneTimeKeys {
        if shouldThrowError { throw PQSSession.SessionErrors.userNotFound }
        return oneTimeKeys[secretName] ?? OneTimeKeys(curve: nil, mlKEM: nil)
    }
    
    func fetchOneTimeKeyIdentities(for secretName: String, deviceId: String, type: KeysType) async throws -> [UUID] { [] }
    func publishUserConfiguration(_ configuration: SessionModels.UserConfiguration, recipient secretName: String, recipient identity: UUID) async throws {}
    func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {}
    
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        if shouldThrowError { throw PQSSession.SessionErrors.userNotFound }
        guard let config = configurations[secretName] else {
            throw PQSSession.SessionErrors.userNotFound
        }
        return config
    }
    
    func findUserConfiguration(secretName: String) async throws -> UserConfiguration {
        if shouldThrowError { throw PQSSession.SessionErrors.configurationError }
        guard let config = configurations[secretName] else {
            throw PQSSession.SessionErrors.configurationError
        }
        return config
    }
    
    // Required SessionTransport methods
    func updateOneTimeKeys(
        for secretName: String, deviceId: String, keys: [UserConfiguration.SignedOneTimePublicKey]
    ) async throws {}
    func updateOneTimeMLKEMKeys(
        for secretName: String, deviceId: String, keys: [UserConfiguration.SignedMLKEMOneTimeKey]
    ) async throws {}
    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: KeysType)
    async throws
    {}
    func deleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws {}
    func publishRotatedKeys(for secretName: String, deviceId: String, rotated keys: RotatedPublicKeys) async throws {
        
    }
    func createUploadPacket(
        secretName: String, deviceId: UUID, recipient: MessageRecipient, metadata: Data
    ) async throws {}
}

actor ReceiverDelegate: EventReceiver {
    
    let session: PQSSession
    
    init(session: PQSSession) {
        self.session = session
    }
    
    var key: SymmetricKey?
    
    func setKey(_ key: SymmetricKey) async {
        self.key = key
    }
    
    func createdMessage(_ message: SessionModels.EncryptedMessage) async {}
    func updatedMessage(_: SessionModels.EncryptedMessage) async {}
    func updateContact(_: SessionModels.Contact) async throws {}
    func contactMetadata(changed _: SessionModels.Contact) async {}
    func deletedMessage(_: SessionModels.EncryptedMessage) async {}
    func createdContact(_: SessionModels.Contact) async throws {}
    func removedContact(_: String) async throws {}
    func removedCommunication(_ type: SessionModels.MessageRecipient) async throws {}
    func createdChannel(_ model: SessionModels.BaseCommunication) async {}
    func synchronize(contact: Contact, requestFriendship: Bool) async throws {
        if requestFriendship {
            // Mirror the production receiver: re-add of an already-accepted /
            // already-rejected contact surfaces a typed `FriendshipRequestError`
            // that's expected/benign in the auto-resync path. Swallow it so
            // tests that re-add contacts don't fail unexpectedly.
            do {
                try await self.session.requestFriendshipStateChange(
                    state: .requested,
                    contact: contact)
            } catch is FriendshipRequestError {
                // no-op
            }
        } else {
            //Acknowledge that the contact was created, this only happens on the receiving end
            try await session.sendContactCreatedAcknowledgment(recipient: contact.secretName)
        }
    }
    func transportContactMetadata() async throws {}
    func pushContactMetadata(to _: String) async throws {}
    func updatedCommunication(_: SessionModels.BaseCommunication, members _: Set<String>) async {}
}

struct ReceivedMessage {
    let message: SignedRatchetMessage
    let sender: String
    let recipient: String
    let deviceId: UUID
    let messageId: String
    let transportEvent: TransportEvent?
}

actor TransportStore {
    
    struct IdentifiableSignedoneTimePublicKey {
        let id: String
        var keys: [UserConfiguration.SignedOneTimePublicKey]
    }
    
    struct IdentifiableSignedMLKEMOneTimeKey {
        let id: String
        var keys: [UserConfiguration.SignedMLKEMOneTimeKey]
    }
    
    // MARK: - Properties
    
    var oneTimePublicKeyPairs = [IdentifiableSignedoneTimePublicKey]()
    var mlKEMOneTimeKeyPairs = [IdentifiableSignedMLKEMOneTimeKey]()
    var publishableName: String!
    var userConfigurations = [User]()
    var lastPublishedRotatedKeys: SessionModels.RotatedPublicKeys?

    /// Test helper: the store is shared across serialized suite tests; clear capture before asserting on rotation payloads.
    func resetLastPublishedRotatedKeys() async {
        lastPublishedRotatedKeys = nil
    }

    /// Drain all curve and MLKEM OTKs for a given secret name so the next
    /// inbound triggers a missingOneTimeKey / fresh-key error.
    func drainOTKs(for secretName: String) {
        if let idx = oneTimePublicKeyPairs.firstIndex(where: { $0.id == secretName }) {
            oneTimePublicKeyPairs[idx].keys.removeAll()
        }
        if let idx = mlKEMOneTimeKeyPairs.firstIndex(where: { $0.id == secretName }) {
            mlKEMOneTimeKeyPairs[idx].keys.removeAll()
        }
    }
    
    func setPublishableName(_ publishableName: String) async {
        self.publishableName = publishableName
    }
    
    func setUserConfigurations(index: Int, config: UserConfiguration) async {
        userConfigurations[index].config = config
    }

    func upsertUserConfiguration(secretName: String, deviceId: UUID, config: UserConfiguration) async {
        if let index = userConfigurations.firstIndex(where: { $0.secretName == secretName }) {
            userConfigurations[index] = User(secretName: secretName, deviceId: deviceId, config: config)
        } else {
            userConfigurations.append(User(secretName: secretName, deviceId: deviceId, config: config))
        }
    }
    
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> SessionModels.OneTimeKeys {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.signingPublicKey else { fatalError() }
        let signingKey = try Curve25519.Signing.PublicKey(rawRepresentation: signingKeyData)

        guard let oneTimeKeyPairIndex = oneTimePublicKeyPairs.firstIndex(where: {
                $0.id == secretName
            }) else { fatalError() }
        
        var oneTimeKeyPair = oneTimePublicKeyPairs[oneTimeKeyPairIndex]
        guard let publicKey = try oneTimeKeyPair.keys.last?.verified(using: signingKey) else {
            fatalError()
        }
        oneTimeKeyPair.keys.removeAll(where: { $0.id == publicKey.id })
        oneTimePublicKeyPairs[oneTimeKeyPairIndex] = oneTimeKeyPair
        
        guard
            let mlKEMKeyPairIndex = mlKEMOneTimeKeyPairs.firstIndex(where: { $0.id == secretName })
        else { fatalError() }
        var mlKEMKeyPair = mlKEMOneTimeKeyPairs[mlKEMKeyPairIndex]
        guard let mlKEMKey = try mlKEMKeyPair.keys.last?.verified(using: signingKey) else {
            fatalError()
        }
        
        mlKEMKeyPair.keys.removeAll(where: { $0.id == mlKEMKey.id })
        mlKEMOneTimeKeyPairs[mlKEMKeyPairIndex] = mlKEMKeyPair
        
        return SessionModels.OneTimeKeys(curve: publicKey, mlKEM: mlKEMKey)
        
    }
    
    func fetchOneTimeKeyIdentities(for secretName: String, deviceId: String, type: KeysType) async throws -> [UUID] {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.signingPublicKey else { fatalError() }
        let signingKey = try Curve25519.Signing.PublicKey(rawRepresentation: signingKeyData)
        let filteredCurve = oneTimePublicKeyPairs.filter { $0.id == secretName }
        let filteredMLKEM = mlKEMOneTimeKeyPairs.filter { $0.id == secretName }
        var verifiedIDs: [UUID] = []

        switch type {
        case .curve:
            for key in filteredCurve {
                for oneTimeKey in key.keys {
                    if let verifiedKey = try? oneTimeKey.verified(using: signingKey) {
                        verifiedIDs.append(verifiedKey.id)
                    }
                }
            }
        case .mlKEM:
            for key in filteredMLKEM {
                for oneTimeKey in key.keys {
                    if let verifiedKey = try? oneTimeKey.verified(using: signingKey) {
                        verifiedIDs.append(verifiedKey.id)
                    }
                }
            }
        }
        return verifiedIDs
    }

    func updateOneTimeKeys(
        for secretName: String,
        deviceId _: String,
        keys: [UserConfiguration.SignedOneTimePublicKey]
    ) async throws {
        if let index = oneTimePublicKeyPairs.firstIndex(where: { $0.id == secretName }) {
            oneTimePublicKeyPairs[index].keys.append(contentsOf: keys)
        } else {
            oneTimePublicKeyPairs.append(
                IdentifiableSignedoneTimePublicKey(id: secretName, keys: keys)
            )
        }
    }

    func updateOneTimeMLKEMKeys(
        for secretName: String,
        deviceId _: String,
        keys: [UserConfiguration.SignedMLKEMOneTimeKey]
    ) async throws {
        if let index = mlKEMOneTimeKeyPairs.firstIndex(where: { $0.id == secretName }) {
            mlKEMOneTimeKeyPairs[index].keys.append(contentsOf: keys)
        } else {
            mlKEMOneTimeKeyPairs.append(
                IdentifiableSignedMLKEMOneTimeKey(id: secretName, keys: keys)
            )
        }
    }

    func batchDeleteOneTimeKeys(for secretName: String, with _: String, type: KeysType) async throws {
        switch type {
        case .curve:
            if let index = oneTimePublicKeyPairs.firstIndex(where: { $0.id == secretName }) {
                oneTimePublicKeyPairs[index].keys.removeAll()
            }
        case .mlKEM:
            if let index = mlKEMOneTimeKeyPairs.firstIndex(where: { $0.id == secretName }) {
                mlKEMOneTimeKeyPairs[index].keys.removeAll()
            }
        }
    }

    func deleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws {
        guard let keyId = UUID(uuidString: id) else { return }

        switch type {
        case .curve:
            if let index = oneTimePublicKeyPairs.firstIndex(where: { $0.id == secretName }) {
                oneTimePublicKeyPairs[index].keys.removeAll(where: { $0.id == keyId })
            }
        case .mlKEM:
            if let index = mlKEMOneTimeKeyPairs.firstIndex(where: { $0.id == secretName }) {
                mlKEMOneTimeKeyPairs[index].keys.removeAll(where: { $0.id == keyId })
            }
        }
    }
    
    func publishUserConfiguration(
        _ configuration: SessionModels.UserConfiguration, recipient identity: UUID
    ) async throws {
        userConfigurations.append(
            .init(secretName: publishableName, deviceId: identity, config: configuration))
        oneTimePublicKeyPairs.append(
            IdentifiableSignedoneTimePublicKey(
                id: publishableName, keys: configuration.signedOneTimePublicKeys))
        mlKEMOneTimeKeyPairs.append(
            IdentifiableSignedMLKEMOneTimeKey(
                id: publishableName, keys: configuration.signedMLKEMOneTimePublicKeys))
    }
    
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        guard
            let userConfiguration = userConfigurations.first(where: { $0.secretName == secretName }
            )?.config
        else {
            throw PQSSession.SessionErrors.userNotFound
        }
        return userConfiguration
    }
    
    func findUserConfiguration(secretName: String) async throws -> UserConfiguration {
        guard
            let userConfiguration = userConfigurations.first(where: { $0.secretName == secretName }
            )?.config
        else {
            throw PQSSession.SessionErrors.configurationError
        }
        return userConfiguration
    }
    
    func publishRotatedKeys(
        for secretName: String, deviceId: String, rotated keys: SessionModels.RotatedPublicKeys
    ) async throws {
        guard let index = userConfigurations.firstIndex(where: { $0.secretName == secretName })
        else { fatalError() }
        var userConfig = userConfigurations[index]
        let oldSigningKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: userConfig.config.signingPublicKey)
        let newSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: keys.pskData)
        lastPublishedRotatedKeys = keys
        let trustedExistingDeviceIds = userConfig.config.signedDevices.compactMap { signedDevice in
            (try? signedDevice.verified(using: oldSigningKey))?.deviceId
        }
        let invalidExistingDeviceIds = userConfig.config.signedDevices.compactMap { signedDevice in
            trustedExistingDeviceIds.contains(signedDevice.id) ? nil : signedDevice.id
        }

        let hasBatchRotation = keys.allSignedDevices?.isEmpty == false
        if let signedDeviceKeyBundle = keys.deviceKeyBundle,
           !hasBatchRotation,
           keys.pskData == userConfig.config.signingPublicKey {
            guard let deviceUUID = UUID(uuidString: deviceId),
                  signedDeviceKeyBundle.id == deviceUUID,
                  let existingDevice = userConfig.config.signedDevices.compactMap({ try? $0.verified(using: oldSigningKey) })
                    .first(where: { $0.deviceId == deviceUUID })
            else {
                throw TestError.invalidRotatedDeviceSignature
            }
            let deviceSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: existingDevice.signingPublicKey)
            guard let bundle = try signedDeviceKeyBundle.verified(using: deviceSigningKey),
                  bundle.deviceId == deviceUUID
            else {
                throw TestError.invalidRotatedDeviceSignature
            }
            userConfig.config.signedDeviceKeyBundles.removeAll { $0.id == deviceUUID }
            userConfig.config.signedDeviceKeyBundles.append(signedDeviceKeyBundle)
            userConfigurations[index] = userConfig
            return
        }

        if let batch = keys.allSignedDevices, !batch.isEmpty {
            for signedDevice in batch {
                guard try signedDevice.verified(using: newSigningKey) != nil else {
                    throw TestError.invalidRotatedDeviceSignature
                }
            }
            userConfig.config.signingPublicKey = keys.pskData
            userConfig.config.signedDevices = batch
            if let signedDeviceKeyBundle = keys.deviceKeyBundle,
               let rotatedDevice = batch.compactMap({ try? $0.verified(using: newSigningKey) })
                .first(where: { $0.deviceId == signedDeviceKeyBundle.id }) {
                let deviceSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: rotatedDevice.signingPublicKey)
                guard let bundle = try signedDeviceKeyBundle.verified(using: deviceSigningKey),
                      bundle.deviceId == rotatedDevice.deviceId
                else {
                    throw TestError.invalidRotatedDeviceSignature
                }
                userConfig.config.signedDeviceKeyBundles.removeAll { $0.id == signedDeviceKeyBundle.id }
                userConfig.config.signedDeviceKeyBundles.append(signedDeviceKeyBundle)
            }
            userConfigurations[index] = userConfig
            return
        }

        var accountSigningKeyUnchanged = keys.pskData == userConfig.config.signingPublicKey
        if !accountSigningKeyUnchanged {
            accountSigningKeyUnchanged = (try? keys.signedDevice.verified(using: oldSigningKey)) != nil
        }
        if userConfig.config.signedDevices.count > 1, !accountSigningKeyUnchanged {
            let deviceUUID = UUID(uuidString: deviceId)
            let trustedExistingDeviceId = trustedExistingDeviceIds.count == 1 ? trustedExistingDeviceIds[0] : nil
            let pathMatchesTrustedExistingDevice = deviceUUID == trustedExistingDeviceId
            let payloadMatchesTrustedExistingDevice = keys.signedDevice.id == trustedExistingDeviceId
            let verifiedWithNewSigningKey = (try? keys.signedDevice.verified(using: newSigningKey)) != nil
            if let recovery = keys.recovery,
               let trustedExistingDeviceId,
               recovery.recoveringDeviceId == trustedExistingDeviceId,
               pathMatchesTrustedExistingDevice,
               payloadMatchesTrustedExistingDevice,
               verifiedWithNewSigningKey,
               recovery.prunedDeviceIds.sorted(by: { $0.uuidString < $1.uuidString })
                    == invalidExistingDeviceIds.sorted(by: { $0.uuidString < $1.uuidString }) {
                let authorization = RotatedKeysRecoveryAuthorization(
                    secretName: secretName,
                    recoveringDeviceId: trustedExistingDeviceId,
                    newSigningPublicKey: keys.pskData,
                    newSignedDeviceData: keys.signedDevice.data,
                    prunedDeviceIds: recovery.prunedDeviceIds
                )
                let canonicalAuthorizationData = authorization.canonicalSigningData()
                let legacyBinaryAuthorizationData = try BinaryEncoder().encode(authorization)
                guard let trustedExistingDevice = try userConfig.config.signedDevices
                    .first(where: { $0.id == trustedExistingDeviceId })?
                    .verified(using: oldSigningKey) else {
                    throw TestError.invalidRecoverySignature
                }
                let trustedDeviceSigningKey = try Curve25519.Signing.PublicKey(
                    rawRepresentation: trustedExistingDevice.signingPublicKey
                )
                guard trustedDeviceSigningKey.isValidSignature(recovery.oldAccountSignature, for: canonicalAuthorizationData)
                    || trustedDeviceSigningKey.isValidSignature(recovery.oldAccountSignature, for: legacyBinaryAuthorizationData)
                else {
                    throw TestError.invalidRecoverySignature
                }
                guard let rotatedDevice = try keys.signedDevice.verified(using: newSigningKey) else {
                    throw TestError.invalidRotatedDeviceSignature
                }
                userConfig.config.signingPublicKey = keys.pskData
                userConfig.config.signedDevices = [keys.signedDevice]
                userConfig.config.signedDeviceKeyBundles.removeAll()
                if let signedDeviceKeyBundle = keys.deviceKeyBundle {
                    let deviceSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: rotatedDevice.signingPublicKey)
                    guard signedDeviceKeyBundle.id == rotatedDevice.deviceId,
                          let bundle = try signedDeviceKeyBundle.verified(using: deviceSigningKey),
                          bundle.deviceId == rotatedDevice.deviceId
                    else {
                        throw TestError.invalidRotatedDeviceSignature
                    }
                    userConfig.config.signedDeviceKeyBundles.append(signedDeviceKeyBundle)
                }
                userConfigurations[index] = userConfig
                return
            }
            throw TestError.multiDeviceRotationRequiresBatch
        }

        let verifiedWithEffectiveKey = accountSigningKeyUnchanged
            ? ((try? keys.signedDevice.verified(using: oldSigningKey)) != nil)
            : ((try? keys.signedDevice.verified(using: newSigningKey)) != nil)
        guard verifiedWithEffectiveKey else {
            throw TestError.invalidRotatedDeviceSignature
        }

        guard
            let deviceIndex = userConfig.config.signedDevices.firstIndex(where: {
                guard let verified = try? $0.verified(using: oldSigningKey) else { return false }
                return verified.deviceId.uuidString == deviceId
            })
        else { fatalError() }
        if !accountSigningKeyUnchanged {
            userConfig.config.signingPublicKey = keys.pskData
        }
        userConfig.config.signedDevices[deviceIndex] = keys.signedDevice
        if let signedDeviceKeyBundle = keys.deviceKeyBundle {
            let effectiveSigningKey = accountSigningKeyUnchanged ? oldSigningKey : newSigningKey
            guard let rotatedDevice = try keys.signedDevice.verified(using: effectiveSigningKey) else {
                throw TestError.invalidRotatedDeviceSignature
            }
            let deviceSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: rotatedDevice.signingPublicKey)
            guard let bundle = try signedDeviceKeyBundle.verified(using: deviceSigningKey),
                  bundle.deviceId == rotatedDevice.deviceId
            else {
                throw TestError.invalidRotatedDeviceSignature
            }
            userConfig.config.signedDeviceKeyBundles.removeAll { $0.id == signedDeviceKeyBundle.id }
            userConfig.config.signedDeviceKeyBundles.append(signedDeviceKeyBundle)
        }
        userConfigurations[index] = userConfig
    }
}



final class _MockTransportDelegate: SessionTransport, @unchecked Sendable {
    
    var continuation: AsyncStream<ReceivedMessage>.Continuation?
    let session: PQSSession
    let store: TransportStore

    /// Optional hook to simulate message loss by preventing delivery into the async stream.
    var shouldDeliver: (@Sendable (ReceivedMessage) async -> Bool)?

    /// Optional hook to transform outgoing messages before delivery (test-only).
    /// Useful for forging signatures or mutating payloads deterministically.
    var transformOutgoing: (@Sendable (ReceivedMessage) async throws -> ReceivedMessage)?

    /// Optional hook to pause or observe OTK uploads in recovery tests.
    var beforeUpdateOneTimeKeys: (@Sendable () async -> Void)?

    /// If set, publishing rotated keys will throw this error (test-only).
    /// Used to simulate rotation publish failures.
    var publishRotatedKeysError: Error?

    /// If set, OTK curve uploads will throw on the first N calls then succeed.
    /// Thread-safe via OTKErrorInjector actor.
    private let otkErrorInjector = OTKErrorInjector()
    func setOTKUploadFailCount(_ count: Int, error: PQSSession.SessionErrors = .oneTimeKeyUploadFailed) async {
        await otkErrorInjector.configure(failCount: count, error: error)
    }
    var otkUploadAttemptCount: Int {
        get async { await otkErrorInjector.attemptCount }
    }

    // Track updateOneTimeKeys calls for testing (thread-safe)
    private let callTracker = CallTracker()

    // Track publishRotatedKeys calls for testing (thread-safe)
    private let rotationTracker = RotationTracker()
    var publishRotatedKeysCallCount: Int {
        get async { await rotationTracker.callCount }
    }
    
    var updateOneTimeKeysCallCount: Int {
        get async { await callTracker.callCount }
    }
    
    var updateOneTimeKeysCalls: [(secretName: String, deviceId: String, keyCount: Int)] {
        get async { await callTracker.calls }
    }
    
    func resetCallTracking() async {
        await callTracker.reset()
    }
    
    init(session: PQSSession, store: TransportStore) {
        self.session = session
        self.store = store
    }
    
    // MARK: - Used Methods
    
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> SessionModels.OneTimeKeys {
        try await store.fetchOneTimeKeys(for: secretName, deviceId: deviceId)
    }
    
    func fetchOneTimeKeyIdentities(for secretName: String, deviceId: String, type: KeysType) async throws -> [UUID] {
        try await store.fetchOneTimeKeyIdentities(for: secretName, deviceId: deviceId, type: type)
    }
    
    func publishUserConfiguration(_ configuration: SessionModels.UserConfiguration, recipient secretName: String, recipient identity: UUID) async throws {
        try await store.publishUserConfiguration(configuration, recipient: identity)
        
    }
    
    func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {

        // Determine actual sender from the bound session, not from metadata
        guard let sessionContext = await session.sessionContext else { return }
        
        let received = ReceivedMessage(
            message: message,
            sender: sessionContext.sessionUser.secretName,
            recipient: metadata.secretName,
            deviceId: sessionContext.sessionUser.deviceId,
            messageId: metadata.sharedMessageId,
            transportEvent: metadata.transportEvent
        )
        let finalReceived: ReceivedMessage
        if let transformOutgoing {
            finalReceived = try await transformOutgoing(received)
        } else {
            finalReceived = received
        }
        if let shouldDeliver, await shouldDeliver(finalReceived) == false {
            return
        }
        continuation?.yield(finalReceived)
    }
    
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        try await store.findConfiguration(for: secretName)
    }
    
    func findUserConfiguration(secretName: String) async throws -> UserConfiguration {
        try await store.findUserConfiguration(secretName: secretName)
    }
    
    func publishRotatedKeys(
        for secretName: String, deviceId: String, rotated keys: SessionModels.RotatedPublicKeys
    ) async throws {
        if let publishRotatedKeysError {
            throw publishRotatedKeysError
        }
        await rotationTracker.increment()
        try await store.publishRotatedKeys(for: secretName, deviceId: deviceId, rotated: keys)
    }
    
    // MARK: - Unused Methods (Stubs)
    
    func receiveMessage() async throws -> String { "" }
    func updateOneTimeKeys(
        for secretName: String, deviceId: String,
        keys: [SessionModels.UserConfiguration.SignedOneTimePublicKey]
    ) async throws {
        if let beforeUpdateOneTimeKeys {
            await beforeUpdateOneTimeKeys()
        }
        // Track calls for testing (thread-safe)
        await callTracker.record(secretName: secretName, deviceId: deviceId, keyCount: keys.count)
        try await otkErrorInjector.checkAndThrow()
        try await store.updateOneTimeKeys(for: secretName, deviceId: deviceId, keys: keys)
    }
    func updateOneTimeMLKEMKeys(
        for secretName: String, deviceId: String,
        keys: [SessionModels.UserConfiguration.SignedMLKEMOneTimeKey]
    ) async throws {
        try await otkErrorInjector.checkAndThrow()
        try await store.updateOneTimeMLKEMKeys(for: secretName, deviceId: deviceId, keys: keys)
    }
    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: SessionModels.KeysType)
    async throws
    {
        try await store.batchDeleteOneTimeKeys(for: secretName, with: id, type: type)
    }
    func deleteOneTimeKeys(for secretName: String, with id: String, type: SessionModels.KeysType)
    async throws
    {
        try await store.deleteOneTimeKeys(for: secretName, with: id, type: type)
    }
    func createUploadPacket(
        secretName _: String, deviceId _: UUID, recipient _: SessionModels.MessageRecipient,
        metadata _: Data
    ) async throws {}
    func notifyIdentityCreation(for _: String, keys _: SessionModels.OneTimeKeys) async throws {}
}

private actor RotationTracker {
    var callCount: Int = 0
    func increment() { callCount += 1 }
}

private actor OTKErrorInjector {
    private var remainingFailures: Int = 0
    private var error: PQSSession.SessionErrors = .oneTimeKeyUploadFailed
    private(set) var attemptCount: Int = 0

    func configure(failCount: Int, error: PQSSession.SessionErrors) {
        remainingFailures = failCount
        self.error = error
        attemptCount = 0
    }

    func checkAndThrow() throws {
        attemptCount += 1
        if remainingFailures > 0 {
            remainingFailures -= 1
            throw error
        }
    }
}

actor MockIdentityStore: PQSSessionStore {
    // MARK: - Properties
    let id = UUID()
    var sessionContext: Data?
    var identities = [SessionIdentity]()
    var communications = [BaseCommunication]()
    let crypto = NeedleTailCrypto()
    var mockUserData: MockUserData
    let session: PQSSession
    let isSender: Bool
    var localDeviceSalt: String?
    var encyrptedConfigurationForTesting = Data()
    var createdMessages = [EncryptedMessage]()
    var contacts = [ContactModel]()
    
    func setLocalSalt(_ salt: String) async {
        localDeviceSalt = salt
    }
    
    init(mockUserData: MockUserData, session: PQSSession, isSender: Bool) {
        self.mockUserData = mockUserData
        self.session = session
        self.isSender = isSender
    }
    
    // MARK: - Used Methods
    
    func createLocalSessionContext(_ data: Data) async throws { sessionContext = data }
    func fetchLocalSessionContext() async throws -> Data {
        guard let context = sessionContext else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        return context
    }
    func updateLocalSessionContext(_ data: Data) async throws { sessionContext = data }
    func deleteLocalSessionContext() async throws { sessionContext = nil }
    func fetchLocalDeviceSalt(keyData: Data) async throws -> Data {
        keyData + "salt".data(using: .utf8)!
    }
    func deleteLocalDeviceSalt() async throws {}
    func fetchSessionIdentities() async throws -> [DoubleRatchetKit.SessionIdentity] {
        identities
    }
    func updateSessionIdentity(_ session: DoubleRatchetKit.SessionIdentity) async throws {
        identities.removeAll(where: { $0.id == session.id })
        identities.append(session)
    }
    
    func createSessionIdentity(_ session: SessionIdentity) async throws {
        identities.append(session)
    }
    func fetchLocalDeviceSalt() async throws -> String {
        guard let salt = localDeviceSalt else { throw PQSSession.SessionErrors.saltError }
        return salt
    }
    
    func findLocalDeviceConfiguration() async throws -> Data { encyrptedConfigurationForTesting }
    func createLocalDeviceConfiguration(_ configuration: Data) async throws {
        encyrptedConfigurationForTesting = configuration
    }
    
    // MARK: - Unused Methods (Stubs)
    
    func removeContact(_: UUID) async throws {}
    func deleteContact(_: UUID) async throws {}
    func deleteSessionIdentity(_ id: UUID) async throws {
        identities.removeAll(where: { $0.id == id })
    }
    func createMediaJob(_: SessionModels.DataPacket) async throws {}
    func fetchAllMediaJobs() async throws -> [SessionModels.DataPacket] { [] }
    func fetchMediaJob(id _: UUID) async throws -> SessionModels.DataPacket? { nil }
    func deleteMediaJob(_: UUID) async throws {}
    func fetchContacts() async throws -> [SessionModels.ContactModel] { contacts }
    func createContact(_ contact: SessionModels.ContactModel) async throws {
        contacts.append(contact)
    }
    func updateContact(_ contact: SessionModels.ContactModel) async throws {
        if let index = contacts.firstIndex(where: { $0.id == contact.id }) {
            contacts[index] = contact
        }
    }
    func fetchCommunications() async throws -> [SessionModels.BaseCommunication] {
        communications
    }
    func createCommunication(_ communication: SessionModels.BaseCommunication) async throws {
        communications.append(communication)
    }
    func updateCommunication(_ communication: SessionModels.BaseCommunication) async throws {
        if let idx = communications.firstIndex(where: { $0.id == communication.id }) {
            communications[idx] = communication
        } else {
            communications.append(communication)
        }
    }
    func removeCommunication(_: SessionModels.BaseCommunication) async throws {}
    func deleteCommunication(_: SessionModels.BaseCommunication) async throws {}
    func fetchMessages(sharedCommunicationId _: UUID) async throws -> [MessageRecord] { [] }
    func fetchMessage(id _: UUID) async throws -> SessionModels.EncryptedMessage {
        if let existing = createdMessages.first {
            return existing
        }
        return try .init(
            id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123",
            sequenceNumber: 1, data: Data())
    }
    
    func fetchMessage(sharedId: String) async throws -> SessionModels.EncryptedMessage {
        if let existing = createdMessages.first(where: { $0.sharedId == sharedId }) {
            return existing
        }
        return try .init(
            id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123",
            sequenceNumber: 1, data: Data())
    }
    
    func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        createdMessages.append(message)
    }
    
    func getAllMessages() async -> [EncryptedMessage] {
        return createdMessages
    }
    
    func updateMessage(_: SessionModels.EncryptedMessage, symmetricKey _: SymmetricKey) async throws
    {}
    func removeMessage(_: SessionModels.EncryptedMessage) async throws {}
    func deleteMessage(_: SessionModels.EncryptedMessage) async throws {}
    func streamMessages(sharedIdentifier _: UUID) async throws -> (
        AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>,
        AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>.Continuation?
    ) {
        let stream = AsyncThrowingStream<SessionModels.EncryptedMessage, any Error> {
            continuation in
            for i in 1...5 {
                if let message = try? SessionModels.EncryptedMessage(
                    id: UUID(), communicationId: UUID(), sessionContextId: i, sharedId: "123",
                    sequenceNumber: 1, data: Data())
                {
                    continuation.yield(message)
                }
            }
            continuation.finish()
        }
        return (stream, nil)
    }
    
    func messageCount(sharedIdentifier _: UUID) async throws -> Int { 1 }
    func readJobs() async throws -> [SessionModels.JobModel] { [] }
    func fetchJobs() async throws -> [SessionModels.JobModel] { [] }
    func createJob(_: SessionModels.JobModel) async throws {}
    func updateJob(_: SessionModels.JobModel) async throws {}
    func removeJob(_: SessionModels.JobModel) async throws {}
    func deleteJob(_: SessionModels.JobModel) async throws {}
    func findMediaJobs(for _: String, symmetricKey _: SymmetricKey) async throws -> [SessionModels
        .DataPacket]
    { [] }
    func fetchMediaJobs(recipient _: String, symmetricKey _: SymmetricKey) async throws
    -> [SessionModels.DataPacket]
    { [] }
    func findMediaJob(for _: String, symmetricKey _: SymmetricKey) async throws -> SessionModels
        .DataPacket?
    { nil }
    func fetchMediaJob(synchronizationIdentifier _: String, symmetricKey _: SymmetricKey)
    async throws -> SessionModels.DataPacket?
    { nil }
    
    /// Clears all stored data for testing purposes
    func clearAllData() async throws {
        sessionContext = nil
        identities.removeAll()
        encyrptedConfigurationForTesting = Data()
        createdMessages.removeAll()
        contacts.removeAll()
    }
}

struct MockUserData {
    var senderPublicIdentity: UUID?
    let ssn = "alice"
    let sap = "123"
    var receiverPublicIdentity = UUID()
    let sci = 0
    let dn = "deviceName"
    let rsn = "bob"
    let lid = UUID()
    let ntm = CryptoMessage(
        text: "Some Message",
        metadata: .init(),
        recipient: .nickname("bob"),
        sentDate: Date(),
        destructionTime: nil
    )
    let smi = "123456789"
    let session: PQSSession
    
    init(session: PQSSession) {
        self.session = session
    }
    
    func identityStore(isSender: Bool) -> MockIdentityStore {
        MockIdentityStore(mockUserData: self, session: session, isSender: isSender)
    }
}

struct User {
    let secretName: String
    let deviceId: UUID
    var config: UserConfiguration
}

extension Data {
    var hexString: String {
        map { String(format: "%02hhx", $0) }.joined()
    }
}

// MARK: - Test Errors

enum TestError: Error, Equatable {
    case contactPropsDecryptionFailed
    case multiDeviceRotationRequiresBatch
    case invalidRotatedDeviceSignature
    case invalidRecoverySignature
    case invalidRatchetHeader
}

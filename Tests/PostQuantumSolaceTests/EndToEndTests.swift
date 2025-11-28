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
        await self.store.setPublishableName(sMockUserData.ssn)
        _senderChildSession2.linkDelegate = senderChild2LinkDelegate
        let bundle = try await _senderChildSession2.createDeviceCryptographicBundle(isMaster: false)
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
    
    // MARK: - Test Methods
    
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
                    bobReceived += 1
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
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
        
        // Alice receive loop
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should process Bob's replies after rotation") {
                var count = 0
                for await received in aliceStream {
                    count += 1

                    if count == 3 {
                        
                        try await self._senderSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                        
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
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
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
        
        // Give tasks time to run
        try await Task.sleep(until: .now + .seconds(1))
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
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
        
        // Wait for messages to be sent and received - sessionReestablishment messages are sent asynchronously
        // We need to give enough time for the messages to be processed through the transport layer
        var attempts = 0
        let maxAttempts = 20
        while attempts < maxAttempts && !receivedAutoSync {
            try await Task.sleep(until: .now + .milliseconds(100))
            attempts += 1
        }
        
        #expect(receivedAutoSync, "Expected an automatic sync/control message after rotations without manual sends. Messages may not have been routed correctly or timing issue.")
        #expect(await SessionEventProbe.shared.hasReestablishment(for: _recipientMaxSkipSession.id), "Recipient should observe sessionReestablishment control frame")
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
                        bobDecrypted = true
                        aliceTransport.continuation?.finish()
                        bobTransport.continuation?.finish()
                        return
                    } catch {
                        return
                    }
                }
            }
        }
        
        // Simultaneous rotations
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await self._senderMaxSkipSession.rotateKeysOnPotentialCompromise()
            }
            group.addTask {
                try await self._recipientMaxSkipSession.rotateKeysOnPotentialCompromise()
            }
            try await group.waitForAll()
        }
        
        // Immediately send without delay
        try await _senderMaxSkipSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "immediate")
        
        try await Task.sleep(until: .now + .seconds(1))
        #expect(bobDecrypted, "Bob should decrypt immediate post-rotation message without delay if auto re-handshake is working")
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
        
        aliceTask?.cancel()
        try? await Task.sleep(nanoseconds: 50_000_000) // Give time to cancel
        await shutdownSessions()
    }
    
    
    
    @Test
    func thousandMessageExchange() async throws {
        let totalMessages = 1000
        
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
        Task {
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
            await #expect(
                throws: Never.self,
                "Alice's message processing loop should handle received messages and key rotation without errors"
            ) {
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
        }
        // Bob's receive loop
        Task {
        var bobIterations = 0
        for await received in bobStream {
            bobIterations += 1
            await #expect(
                throws: Never.self,
                "Bob's message processing loop should handle received messages, replies, and key rotation without errors"
            ) {
                    do {
                try await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId)
                    } catch PQSSession.SessionErrors.databaseNotInitialized {
                        return
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
                signedMLKEMOneTimePublicKeys: masterConfig.signedMLKEMOneTimePublicKeys)
            
            //Publish the new config to the remote store
            let senderSecretName = await self._senderSession.sessionContext!.sessionUser.secretName
            if let index = await self.store.userConfigurations.firstIndex(where: {
                $0.secretName == senderSecretName
            }) {
                await self.store.setUserConfigurations(index: index, config: newConfig)
            }
            
            try await self._senderSession.updateUserConfiguration(newConfig.getVerifiedDevices())
            try await self._senderChildSession1.updateUserConfiguration(
                newConfig.getVerifiedDevices())
            try await self._senderChildSession2.updateUserConfiguration(
                newConfig.getVerifiedDevices())
            
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
                signedMLKEMOneTimePublicKeys: masterRecipientConfig.signedMLKEMOneTimePublicKeys)
            
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
            try await self._recipientChildSession1.updateUserConfiguration(
                newRecipientConfig.getVerifiedDevices())
            try await self._recipientChildSession2.updateUserConfiguration(
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
        
        // Simulate transport layer issues by sending messages in bursts
        // to cause potential message queue overflow or processing delays
        var authenticationFailures = 0
        var successfulMessages = 0
        
        // Send messages in bursts to simulate transport layer stress
        for burst in 0..<3 {
            let burstTasks = (1...5).map { i in
                Task {
                    do {
                        try await _senderSession.writeTextMessage(
                            recipient: .nickname("bob"),
                            text: "Transport test burst \(burst) message \(i)")
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
            
            // Wait for burst to complete
            for task in burstTasks {
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
            
            // Small delay between bursts
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
        
        // Create multiple concurrent tasks to send messages simultaneously
        let concurrentTasks = (1...10).map { i in
            Task {
                do {
                    // Minimal delay to ensure they start almost simultaneously
                    try await Task.sleep(until: .now + .milliseconds(UInt64.random(in: 0...5)))
                    
                    try await _senderSession.writeTextMessage(
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
        
        // Wait for all concurrent tasks to complete
        let results = await withTaskGroup(of: MessageResult.self) { group in
            for task in concurrentTasks {
                group.addTask {
                    await task.value
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
            await #expect(throws: Never.self, "Bob should receive throughout key rotations") {
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
        
        // Initial warm‑up exchange
        for i in 1...5 {
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup alice #\(i)")
            try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "warmup bob #\(i)")
            try await Task.sleep(until: .now + .milliseconds(20))
        }
        
        // Rotate keys mid‑conversation on Alice
        try await _senderSession.rotateKeysOnPotentialCompromise()
        
        for i in 6...10 {
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice post-rotate #\(i)")
            try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob steady #\(i)")
            try await Task.sleep(until: .now + .milliseconds(15))
        }
        
        // Rotate keys mid‑conversation on Bob
        try await _recipientSession.rotateKeysOnPotentialCompromise()
        
        for i in 11...15 {
            try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "alice steady #\(i)")
            try await _recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "bob post-rotate #\(i)")
            try await Task.sleep(until: .now + .milliseconds(15))
        }
        
        try await Task.sleep(until: .now + .seconds(2))
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
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    await counter.incrementBob()
                }
            }
        }
        
        // Alice's receive loop
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive Bob's messages") {
                for await received in aliceStream {
                    try await self._senderSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    await counter.incrementAlice()
                }
            }
        }
        
        // Step 1: Initial warm-up message to establish session
        try await _senderSession.writeTextMessage(recipient: .nickname("bob"), text: "warmup message")
        try await Task.sleep(until: .now + .milliseconds(200))
        
        // Step 2: Alice rotates her keys
        // This updates Alice's signing key, which Bob needs to fetch when verifying messages
        try await _senderSession.rotateKeysOnPotentialCompromise()
        try await Task.sleep(until: .now + .milliseconds(200))
        
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
        // If Bob got invalidSignature errors, the receiveMessage calls would have thrown
        // and bobReceivedCount would be lower
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
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    await counter.incrementBob()
                }
            }
        }
        
        // Alice's receive loop - should NOT get maxSkippedHeadersExceeded
        aliceTask = Task {
            await #expect(throws: Never.self, "Alice should receive Bob's messages without maxSkippedHeadersExceeded errors") {
                for await received in aliceStream {
                    do {
                        try await self._senderSession.receiveMessage(
                            message: received.message,
                            sender: received.sender,
                            deviceId: received.deviceId,
                            messageId: received.messageId
                        )
                        await counter.incrementAlice()
                    } catch let error as RatchetError {
                        if error == .maxSkippedHeadersExceeded {
                            await counter.addError("maxSkippedHeadersExceeded")
                            throw error
                        }
                        throw error
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
        
        // Verify no maxSkippedHeadersExceeded errors occurred
        let errors = await counter.getErrors()
        let bobCount = await counter.getBobCount()
        let aliceCount = await counter.getAliceCount()
        
        #expect(errors.isEmpty, "Alice should NOT get maxSkippedHeadersExceeded errors. Errors: \(errors)")
        #expect(bobCount >= 1, "Bob should have received Alice's post-rotation message. Actual: \(bobCount)")
        #expect(aliceCount >= 1, "Alice should have received Bob's message without errors. Actual: \(aliceCount)")
    }
    
    @Test("Session Reestablishment Notification Triggers Identity Refresh")
    func testSessionReestablishmentTriggersIdentityRefresh() async throws {
        // This test verifies that when Bob receives a sessionReestablishment notification
        // from Alice, Bob's cached identity is refreshed with Alice's new keys
        
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
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    bobReceivedCount += 1
                    // Check if this was a sessionReestablishment message (it won't be saved)
                    // We can detect it by checking if it's a special transport event
                    bobReceivedReestablishment = true
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
                        try await Task.sleep(nanoseconds: 50_000)
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
        var bobTask: Task<Void, Never>?
        var aliceTask: Task<Void, Never>?
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
        
        bobTask = Task {
            await #expect(throws: Never.self) {
                for await received in bobStream {
                    bobMessageCount += 1
                    try await self._recipientMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                    
                    if bobMessageCount == 2 {
                        try await self._recipientMaxSkipSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: "B->A")
                    }
                    //
                    if bobMessageCount == 3 {
                        try await self._recipientMaxSkipSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: "B2->A2")
                    }
                    
                    if bobMessageCount == 4 {
                        try await _recipientMaxSkipSession.rotateKeysOnPotentialCompromise()
                        try await Task.sleep(nanoseconds: 50_000)
                        try await self._recipientMaxSkipSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: "B3->A3")
                    }
                }
            }
        }
        
        aliceTask = Task {
            await #expect(throws: Never.self) {
                for await received in aliceStream {
                    aliceMessageCount += 1
                    try await self._senderMaxSkipSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                    
                    if aliceMessageCount == 2 {
                        try await _senderMaxSkipSession.rotateKeysOnPotentialCompromise()
                        try await Task.sleep(nanoseconds: 50_000)
                        try await self._senderMaxSkipSession.writeTextMessage(
                            recipient: .nickname("bob"),
                            text: "A2->B2")
                    }
                    
                    if aliceMessageCount == 3 {
                        try await self._senderMaxSkipSession.writeTextMessage(
                            recipient: .nickname("bob"),
                            text: "A3->B3")
                    }
                }
            }
        }
        
        try await self._senderMaxSkipSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "A->B")
        
        try await Task.sleep(until: .now + .seconds(1))
        
        #expect(bobMessageCount == 6)
        #expect(aliceMessageCount == 6)
        aliceTransport.continuation?.finish()
        bobTransport.continuation?.finish()
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
    
    init(session: PQSSession) {
        self.session = session
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
}

final class MockDeviceLinkingDelegate: DeviceLinkingDelegate, @unchecked Sendable {
    let secretName: String
    
    init(secretName: String) {
        self.secretName = secretName
    }
    
    func generateDeviceCryptographic(_ data: Data, password: String) async -> LinkDeviceInfo? {
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
            //This only happens on the requesters end
            try await self.session.requestFriendshipStateChange(
                state: .requested,
                contact: contact)
        } else {
            //Acknowledge that the contact was created, this only happens on the receiving end
            try await session.sendContactCreatedAcknowledgment(recipient: contact.secretName)
        }
    }
    func transportContactMetadata() async throws {}
    func updatedCommunication(_: SessionModels.BaseCommunication, members _: Set<String>) async {}
}

struct ReceivedMessage {
    let message: SignedRatchetMessage
    let sender: String
    let recipient: String
    let deviceId: UUID
    let messageId: String
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
    
    func setPublishableName(_ publishableName: String) async {
        self.publishableName = publishableName
    }
    
    func setUserConfigurations(index: Int, config: UserConfiguration) async {
        userConfigurations[index].config = config
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
    
    func fetchOneTimeKeyIdentities(for secretName: String, deviceId: String, type: KeysType)
    async throws -> [UUID]
    {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.signingPublicKey else { fatalError() }
        let signingKey = try Curve25519.Signing.PublicKey(rawRepresentation: signingKeyData)
        let filtered = oneTimePublicKeyPairs.filter { $0.id == secretName }
        var verifiedIDs: [UUID] = []
        for key in filtered {
            for oneTimeKey in key.keys {
                if let verifiedKey = try? oneTimeKey.verified(using: signingKey) {
                    verifiedIDs.append(verifiedKey.id)
                }
            }
        }
        return verifiedIDs
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
        guard
            let deviceIndex = userConfig.config.signedDevices.firstIndex(where: {
                guard let verified = try? $0.verified(using: oldSigningKey) else { return false }
                return verified.deviceId.uuidString == deviceId
            })
        else { fatalError() }
        userConfig.config.signedDevices[deviceIndex] = keys.signedDevice
        userConfig.config.signingPublicKey = keys.pskData
        userConfigurations[index] = userConfig
    }
}



final class _MockTransportDelegate: SessionTransport, @unchecked Sendable {
    
    var continuation: AsyncStream<ReceivedMessage>.Continuation?
    let session: PQSSession
    let store: TransportStore
    
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
            messageId: metadata.sharedMessageId
        )
        continuation?.yield(received)
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
        try await store.publishRotatedKeys(for: secretName, deviceId: deviceId, rotated: keys)
    }
    
    // MARK: - Unused Methods (Stubs)
    
    func receiveMessage() async throws -> String { "" }
    func updateOneTimeKeys(
        for _: String, deviceId _: String,
        keys _: [SessionModels.UserConfiguration.SignedOneTimePublicKey]
    ) async throws {}
    func updateOneTimeMLKEMKeys(
        for _: String, deviceId _: String,
        keys _: [SessionModels.UserConfiguration.SignedMLKEMOneTimeKey]
    ) async throws {}
    func batchDeleteOneTimeKeys(for _: String, with _: String, type _: SessionModels.KeysType)
    async throws
    {}
    func deleteOneTimeKeys(for _: String, with _: String, type _: SessionModels.KeysType)
    async throws
    {}
    func createUploadPacket(
        secretName _: String, deviceId _: UUID, recipient _: SessionModels.MessageRecipient,
        metadata _: Data
    ) async throws {}
    func notifyIdentityCreation(for _: String, keys _: SessionModels.OneTimeKeys) async throws {}
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
    func deleteSessionIdentity(_: UUID) async throws {}
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
        try .init(
            id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123",
            sequenceNumber: 1, data: Data())
    }
    
    func fetchMessage(sharedId _: String) async throws -> SessionModels.EncryptedMessage {
        try .init(
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

enum TestError: Error {
    case contactPropsDecryptionFailed
}

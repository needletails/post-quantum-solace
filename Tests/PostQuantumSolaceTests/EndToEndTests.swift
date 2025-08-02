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
import BSON
import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailAsyncSequence
import NeedleTailCrypto
import Testing

@testable import PQSSession
@testable import SessionEvents
@testable import SessionModels

@Suite(.serialized)
actor EndToEndTests {
    let crypto = NeedleTailCrypto()
    var _senderSession = PQSSession()
    var _senderChildSession1 = PQSSession()
    var _senderChildSession2 = PQSSession()
    var _recipientSession = PQSSession()
    var _recipientChildSession1 = PQSSession()
    var _recipientChildSession2 = PQSSession()
    let sMockUserData: MockUserData
    let sMockUserChildData1: MockUserData
    let sMockUserChildData2: MockUserData
    let rMockUserData: MockUserData
    let rMockUserChildData1: MockUserData
    let rMockUserChildData2: MockUserData
    let transport = _MockTransportDelegate()
    var senderReceiver = ReceiverDelegate()
    var senderChildReceiver1 = ReceiverDelegate()
    var senderChildReceiver2 = ReceiverDelegate()
    var recipientReceiver = ReceiverDelegate()
    var recipientChildReceiver1 = ReceiverDelegate()
    var recipientChildReceiver2 = ReceiverDelegate()
    let bobProcessedRotated = ContinuationSignal()
    let aliceProcessedRotated = ContinuationSignal()
    let aliceProcessedBobRotation = ContinuationSignal()  // NEW SIGNAL
    let senderChild1LinkDelegate = MockDeviceLinkingDelegate(secretName: "alice")
    let senderChild2LinkDelegate = MockDeviceLinkingDelegate(secretName: "alice")
    let recipientChild1LinkDelegate = MockDeviceLinkingDelegate(secretName: "bob")
    let recipientChild2LinkDelegate = MockDeviceLinkingDelegate(secretName: "bob")
    
    var aliceStreamContinuation: AsyncStream<ReceivedMessage>.Continuation? {
        didSet { transport.aliceStreamContinuation = aliceStreamContinuation }
    }
    
    var bobStreamContinuation: AsyncStream<ReceivedMessage>.Continuation? {
        didSet { transport.bobStreamContinuation = bobStreamContinuation }
    }
    private let bobProcessedThree = ContinuationSignal()
    private let aliceProcessedSix = ContinuationSignal()
    
    init() {
        sMockUserData = MockUserData(session: _senderSession)
        sMockUserChildData1 = MockUserData(session: _senderChildSession1)
        sMockUserChildData2 = MockUserData(session: _senderChildSession2)
        rMockUserData = MockUserData(session: _recipientSession)
        rMockUserChildData1 = MockUserData(session: _recipientChildSession1)
        rMockUserChildData2 = MockUserData(session: _recipientChildSession2)
    }
    
    func shutdownSessions() async {
        await _senderSession.shutdown()
        await _senderChildSession1.shutdown()
        await _senderChildSession2.shutdown()
        await _recipientSession.shutdown()
        await _recipientChildSession1.shutdown()
        await _recipientChildSession2.shutdown()
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
    
    
    
    func createSenderSession(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testSalt1"
        await _senderSession.setLogLevel(.trace)
        await _senderSession.setDatabaseDelegate(conformer: store)
        await _senderSession.setTransportDelegate(conformer: transport)
        await _senderSession.setPQSSessionDelegate(conformer: SessionDelegate())
        await _senderSession.setReceiverDelegate(conformer: senderReceiver)
        
        _senderSession.isViable = true
        transport.publishableName = sMockUserData.ssn
        _senderSession = try await _senderSession.createSession(
            secretName: sMockUserData.ssn, appPassword: sMockUserData.sap
        ) {}
        await _senderSession.setAppPassword(sMockUserData.sap)
        _senderSession = try await _senderSession.startSession(appPassword: sMockUserData.sap)
        try await senderReceiver.setKey(_senderSession.getDatabaseSymmetricKey())
    }
    
    func linkSenderChildSession1(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testChildSalt1"
        _senderChildSession1.isViable = true
        transport.publishableName = sMockUserData.ssn
        _senderChildSession1.linkDelegate = senderChild1LinkDelegate
        
        let bundle = try await _senderChildSession1.createDeviceCryptographicBundle(isMaster: false)
        await conformSessionDelegate(
            session: _senderChildSession1, pqsDelegate: SessionDelegate(), store: store,
            receiver: senderChildReceiver1)
        _senderChildSession1 = try await _senderChildSession1.linkDevice(
            bundle: bundle, password: "123")
        try await senderChildReceiver1.setKey(_senderChildSession1.getDatabaseSymmetricKey())
        _ = try await _senderChildSession1.refreshIdentities(
            secretName: sMockUserData.ssn, forceRefresh: true)
    }
    
    func linkSenderChildSession2(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testChildSalt2"
        await _senderChildSession2.setLogLevel(.trace)
        _senderChildSession2.isViable = true
        transport.publishableName = sMockUserData.ssn
        _senderChildSession2.linkDelegate = senderChild2LinkDelegate
        let bundle = try await _senderChildSession2.createDeviceCryptographicBundle(isMaster: false)
        await conformSessionDelegate(
            session: _senderChildSession2, pqsDelegate: SessionDelegate(), store: store,
            receiver: senderChildReceiver2)
        _senderChildSession2 = try await _senderChildSession2.linkDevice(
            bundle: bundle, password: "123")
        try await senderChildReceiver2.setKey(_senderChildSession2.getDatabaseSymmetricKey())
        _ = try await _senderChildSession2.refreshIdentities(
            secretName: sMockUserData.ssn, forceRefresh: true)
    }
    
    func createRecipientSession(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testSalt2"
        await _recipientSession.setLogLevel(.trace)
        await _recipientSession.setDatabaseDelegate(conformer: store)
        await _recipientSession.setTransportDelegate(conformer: transport)
        await _recipientSession.setPQSSessionDelegate(conformer: SessionDelegate())
        
        _recipientSession.isViable = true
        await _recipientSession.setReceiverDelegate(conformer: recipientReceiver)
        transport.publishableName = rMockUserData.rsn
        _recipientSession = try await _recipientSession.createSession(
            secretName: rMockUserData.rsn, appPassword: rMockUserData.sap
        ) {}
        await _recipientSession.setAppPassword(rMockUserData.sap)
        _recipientSession = try await _recipientSession.startSession(appPassword: rMockUserData.sap)
        try await recipientReceiver.setKey(_recipientSession.getDatabaseSymmetricKey())
    }
    
    func linkRecipientChildSession1(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testChildSalt1"
        _recipientChildSession1.isViable = true
        transport.publishableName = rMockUserData.rsn
        _recipientChildSession1.linkDelegate = recipientChild1LinkDelegate
        let bundle = try await _recipientChildSession1.createDeviceCryptographicBundle(
            isMaster: false)
        await conformSessionDelegate(
            session: _recipientChildSession1, pqsDelegate: SessionDelegate(), store: store,
            receiver: recipientChildReceiver1)
        _recipientChildSession1 = try await _recipientChildSession1.linkDevice(
            bundle: bundle, password: "123")
        try await recipientChildReceiver1.setKey(_recipientChildSession1.getDatabaseSymmetricKey())
        _ = try await _recipientChildSession1.refreshIdentities(
            secretName: rMockUserData.rsn, forceRefresh: true)
    }
    
    func linkRecipientChildSession2(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testChildSalt2"
        _recipientChildSession2.isViable = true
        transport.publishableName = rMockUserData.rsn
        _recipientChildSession2.linkDelegate = recipientChild2LinkDelegate
        let bundle = try await _recipientChildSession2.createDeviceCryptographicBundle(
            isMaster: false)
        await conformSessionDelegate(
            session: _recipientChildSession2, pqsDelegate: SessionDelegate(), store: store,
            receiver: recipientChildReceiver2)
        _recipientChildSession2 = try await _recipientChildSession2.linkDevice(
            bundle: bundle, password: "123")
        try await recipientChildReceiver2.setKey(_recipientChildSession2.getDatabaseSymmetricKey())
        _ = try await _recipientChildSession2.refreshIdentities(
            secretName: rMockUserData.rsn, forceRefresh: true)
    }
    
    // MARK: - Test Methods
    
    @Test
    func ratchetManagerReCreation() async throws {
        var aliceTask: Task<Void, Never>?
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            self.aliceStreamContinuation = continuation
        }
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            self.bobStreamContinuation = continuation
        }
        
        await #expect(
            throws: Never.self,
            "Session initialization and first message should complete without errors"
        ) {
            let senderStore = self.createSenderStore()
            let recipientStore = self.createRecipientStore()
            
            try await self.createSenderSession(store: senderStore)
            try await self.createRecipientSession(store: recipientStore)
            
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"), text: "Message One", metadata: [:])
        }
        
        aliceTask = Task {
            await #expect(
                throws: Never.self,
                "Alice's message processing loop should handle received messages without errors"
            ) {
                var aliceIterations = 0
                for await received in aliceStream {
                    aliceIterations += 1
                    try await _senderSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    
                    if aliceIterations == 2 {
                        try await _senderSession.writeTextMessage(
                            recipient: .nickname("bob"), text: "Message Four", metadata: [:])
                        try await _senderSession.writeTextMessage(
                            recipient: .nickname("bob"), text: "Message Five", metadata: [:])
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
                        recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                    try await _recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Three", metadata: [:])
                }
                
                if bobIterations == 3 {
                    self.aliceStreamContinuation?.finish()
                    self.bobStreamContinuation?.finish()
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
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            self.aliceStreamContinuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            self.bobStreamContinuation = continuation
        }
        await #expect(
            throws: Never.self,
            "Sessions should initialize and Alice should send the first message without errors"
        ) {
            // 2) Initialize sessions (PQXDH handshake)
            try await self.createSenderSession(store: senderStore)
            try await self.createRecipientSession(store: recipientStore)
            
            // 3) Kick off the very first message from Alice → Bob
            try await self._senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "1",
                metadata: [:]
            )
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
                            text: "\(next)",
                            metadata: [:]
                        )
                    } else {
                        // Bob got all his 1 000; close his stream
                        self.bobStreamContinuation?.finish()
                        self.aliceStreamContinuation?.finish()
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
                        text: "\(next)",
                        metadata: [:]
                    )
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
            let stream = AsyncStream<ReceivedMessage> { continuation in
                self.bobStreamContinuation = continuation
            }
            
            // 2) Do the PQXDH handshake before sending any data
            try await self.createSenderSession(store: senderStore)
            try await self.createRecipientSession(store: recipientStore)
            
            // 3) Prepare 79 distinct messages
            let messages = (0..<79).map { "Out‑of‑order Message \($0)" }
            
            // 4) Send them all (in-order) from Alice → Bob
            for text in messages {
                try await self._senderSession.writeTextMessage(
                    recipient: .nickname("bob"),
                    text: text,
                    metadata: [:]
                )
            }
            
            // 5) Collect exactly 79 ReceivedMessage frames from the stream …
            var collected: [ReceivedMessage] = []
            for await received in stream {
                collected.append(received)
                if collected.count == messages.count {
                    // Once we have all 79, stop listening
                    self.bobStreamContinuation?.finish()
                    break
                }
            }
            
            // 6) Now actually feed them into Bob's ratchet out‑of‑order:
            //    first the very first message he should ever see…
            let first = collected.removeFirst()
            try await self._recipientSession.receiveMessage(
                message: first.message,
                sender: first.sender,
                deviceId: first.deviceId,
                messageId: first.messageId
            )
            
            //    …then the rest in a random order:
            for msg in collected.shuffled() {
                try await self._recipientSession.receiveMessage(
                    message: msg.message,
                    sender: msg.sender,
                    deviceId: msg.deviceId,
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
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            self.aliceStreamContinuation = continuation
        }
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            self.bobStreamContinuation = continuation
        }
        await #expect(
            throws: Never.self,
            "Session initialization and first message should complete without errors (rekey test)"
        ) {
            try await self.createSenderSession(store: senderStore)
            try await self.createRecipientSession(store: recipientStore)
            try await self._senderSession.writeTextMessage(
                recipient: .nickname("bob"), text: "Message One", metadata: [:])
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
                    try await self._senderSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                    // First user message (after protocol message)
                    if aliceIterations == 1 {
                        try await self._senderSession.rotateKeysOnPotentialCompromise()
                        try await self._senderSession.writeTextMessage(
                            recipient: .nickname("bob"), text: "Message Three", metadata: [:])
                        await self.bobProcessedRotated.wait()
                    }
                    // After Bob's post-rotation message
                    if aliceIterations == 2 {
                        await self.aliceProcessedBobRotation.signal()
                        self.aliceStreamContinuation?.finish()
                        self.bobStreamContinuation?.finish()
                    }
                }
                await self._senderSession.shutdown()
            }
        }
        // Bob's receive loop
        var bobIterations = 0
        for await received in bobStream {
            bobIterations += 1
            await #expect(
                throws: Never.self,
                "Bob's message processing loop should handle received messages, replies, and key rotation without errors"
            ) {
                try await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId)
                // First user message (after protocol message)
                if bobIterations == 1 {
                    await self.bobProcessedRotated.signal()
                    try await self._recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                }
                // After Alice's post-rotation message
                if bobIterations == 2 {
                    try await self._recipientSession.rotateKeysOnPotentialCompromise()
                    try await self._recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Four", metadata: [:])
                    await self.aliceProcessedBobRotation.wait()
                    self.bobStreamContinuation?.finish()
                    self.aliceStreamContinuation?.finish()
                }
            }
        }
        await shutdownSessions()
    }
    
    @Test
    func testCreateContactEndToEnd() async throws {
        // 1) Create stores & streams
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            self.aliceStreamContinuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            self.bobStreamContinuation = continuation
        }
        
        await #expect(throws: Never.self, "Sessions should initialize without errors") {
            // 2) Initialize sessions
            try await self.createSenderSession(store: senderStore)
            try await self.createRecipientSession(store: recipientStore)
        }
        
        await #expect(
            throws: Never.self,
            "Alice should be able to create a contact for Bob and request friendship"
        ) {
            // 3) Alice creates a contact for Bob with friendship request
            var aliceFriendship = FriendshipMetadata()
            aliceFriendship.setRequestedState()  // Alice is requesting friendship
            
            let contactMetadata: Document = [
                "nickname": "Bob",
                "trustLevel": "high",
                "createdAt": Date(),
                "friendshipMetadata": try BSONEncoder().encode(aliceFriendship),
            ]
            
            let createdContact = try await self._senderSession.createContact(
                secretName: "bob",
                metadata: contactMetadata,
                requestFriendship: true
            )
            
            // Verify the contact was created with correct properties
            #expect(createdContact.id != UUID())
            
            if let props = try await createdContact.props(
                symmetricKey: self._senderSession.getDatabaseSymmetricKey())
            {
                #expect(props.secretName == "bob")
                #expect(props.metadata["nickname"] as? String == "Bob")
                #expect(props.metadata["trustLevel"] as? String == "high")
                #expect(props.metadata["createdAt"] != nil)
                
                // Verify friendship metadata was created
                #expect(props.metadata["friendshipMetadata"] != nil)
            } else {
                throw TestError.contactPropsDecryptionFailed
            }
        }
        
        // 4) Verify Alice's contact was created and stored
        let aliceContacts = try await senderStore.fetchContacts()
        #expect(aliceContacts.count == 1, "Alice should have one contact")
        
        if let aliceContact = aliceContacts.first,
           let props = try await aliceContact.props(
            symmetricKey: self._senderSession.getDatabaseSymmetricKey())
        {
            #expect(props.secretName == "bob")
            
            // Verify friendship metadata exists
            if let friendshipData = props.metadata["friendshipMetadata"] as? Document,
               let friendship = try? BSONDecoder().decode(
                FriendshipMetadata.self, from: friendshipData)
            {
                #expect(friendship.myState == .requested, "Alice should have requested friendship")
                #expect(friendship.theirState == .pending, "Bob's state should be pending")
            } else {
                throw TestError.contactPropsDecryptionFailed
            }
        }
        
        await #expect(
            throws: Never.self,
            "Bob should be able to create a contact for Alice and accept friendship"
        ) {
            // 5) Bob creates a contact for Alice and accepts the friendship
            var bobFriendship = FriendshipMetadata()
            bobFriendship.theirState = .requested  // Bob sees Alice's request
            bobFriendship.myState = .pending  // Bob hasn't responded yet
            
            let bobContactMetadata: Document = [
                "nickname": "Alice",
                "trustLevel": "high",
                "createdAt": Date(),
                "friendshipMetadata": try BSONEncoder().encode(bobFriendship),
            ]
            
            let bobCreatedContact = try await self._recipientSession.createContact(
                secretName: "alice",
                metadata: bobContactMetadata,
                requestFriendship: false
            )
            
            // Verify Bob's contact was created
            #expect(bobCreatedContact.id != UUID())
            
            if let props = try await bobCreatedContact.props(
                symmetricKey: self._recipientSession.getDatabaseSymmetricKey())
            {
                #expect(props.secretName == "alice")
                #expect(props.metadata["nickname"] as? String == "Alice")
            } else {
                throw TestError.contactPropsDecryptionFailed
            }
        }
        
        // 6) Bob accepts Alice's friendship request
        await #expect(throws: Never.self, "Bob should be able to accept Alice's friendship request")
        {
            let bobContacts = try await recipientStore.fetchContacts()
            #expect(bobContacts.count == 1, "Bob should have one contact")
            
            if let bobContact = bobContacts.first,
               let props = try await bobContact.props(
                symmetricKey: self._recipientSession.getDatabaseSymmetricKey())
            {
                #expect(props.secretName == "alice")
                
                // Create a Contact object for the friendship state change
                let contact = Contact(
                    id: bobContact.id,
                    secretName: props.secretName,
                    configuration: props.configuration,
                    metadata: props.metadata
                )
                
                // Bob accepts the friendship request
                try await self._recipientSession.requestFriendshipStateChange(
                    state: .accepted,
                    contact: contact
                )
            }
        }
        
        // 7) Verify Bob's friendship state was updated
        let updatedBobContacts = try await recipientStore.fetchContacts()
        if let updatedBobContact = updatedBobContacts.first,
           let props = try await updatedBobContact.props(
            symmetricKey: self._recipientSession.getDatabaseSymmetricKey())
        {
            
            if let friendshipData = props.metadata["friendshipMetadata"] as? Document,
               let friendship = try? BSONDecoder().decode(
                FriendshipMetadata.self, from: friendshipData)
            {
                #expect(friendship.myState == .accepted, "Bob should have accepted the friendship")
                #expect(friendship.theirState == .accepted, "Bob should see both users as accepted")
                #expect(friendship.ourState == .accepted, "The combined state should be accepted")
            }
        }
        
        await #expect(
            throws: Never.self,
            "Alice should be able to send a message to Bob after friendship is established"
        ) {
            // 8) Test that Alice can send a message to Bob
            try await self._senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "Hello Bob! I just added you as a contact.",
                metadata: [:]
            )
        }
        
        // 9) Bob processes Alice's message
        Task {
            await #expect(throws: Never.self, "Bob should process Alice's message without errors") {
                var bobIterations = 0
                for await received in bobStream {
                    bobIterations += 1
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    
                    if bobIterations == 1 {
                        // Bob responds to Alice
                        try await self._recipientSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: "Hello Alice! Nice to meet you.",
                            metadata: [:]
                        )
                        self.aliceStreamContinuation?.finish()
                        self.bobStreamContinuation?.finish()
                    }
                }
            }
        }
        
        // 10) Alice processes Bob's response
        await #expect(throws: Never.self, "Alice should process Bob's response without errors") {
            var aliceIterations = 0
            for await received in aliceStream {
                aliceIterations += 1
                try await self._senderSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                )
            }
        }
        
        // 11) Verify final state - both contacts should exist and be properly configured
        let finalAliceContacts = try await senderStore.fetchContacts()
        let finalBobContacts = try await recipientStore.fetchContacts()
        
        #expect(finalAliceContacts.count == 1, "Alice should have one contact")
        #expect(finalBobContacts.count == 1, "Bob should have one contact")
        
        await shutdownSessions()
    }
    
    private func conformSessionDelegate(
        session: PQSSession, pqsDelegate: PQSSessionDelegate, store: PQSSessionStore,
        receiver: EventReceiver
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
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            self.aliceStreamContinuation = continuation
        }
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            self.bobStreamContinuation = continuation
        }
        
        await #expect(throws: Never.self, "Real linkDevice test should complete without errors") {
            let senderStore = self.createSenderStore()
            let senderChildStore1 = self.createSenderChildStore1()
            let senderChildStore2 = self.createSenderChildStore2()
            let recipientStore = self.createRecipientStore()
            let recipientChildStore1 = self.createRecipientChildStore1()
            let recipientChildStore2 = self.createRecipientChildStore2()
            
            try await self.createSenderSession(store: senderStore)
            let masterConfig = await self._senderSession.sessionContext!.activeUserConfiguration
            try await self.linkSenderChildSession1(store: senderChildStore1)
            let childConfig1 = await _senderChildSession1.sessionContext!.activeUserConfiguration
            let childDevice1 = try childConfig1.signedDevices.last!.verified(
                using: Curve25519.Signing.PublicKey(
                    rawRepresentation: childConfig1.signingPublicKey))!
            let newSigned = try UserConfiguration.SignedDeviceConfiguration(
                device: childDevice1,
                signingKey: Curve25519.Signing.PrivateKey(
                    rawRepresentation: await _senderSession.sessionContext!.sessionUser.deviceKeys.signingPrivateKey))
            
            try await self.linkSenderChildSession2(store: senderChildStore2)
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
                signedPQKemOneTimePublicKeys: masterConfig.signedPQKemOneTimePublicKeys)
            
            //Publish the new config to the remote store
            let senderSecretName = await self._senderSession.sessionContext!.sessionUser.secretName
            if let index = transport.userConfigurations.firstIndex(where: {
                $0.secretName == senderSecretName
            }) {
                transport.userConfigurations[index].config = newConfig
            }
            
            try await self._senderSession.updateUserConfiguration(newConfig.getVerifiedDevices())
            try await self._senderChildSession1.updateUserConfiguration(
                newConfig.getVerifiedDevices())
            try await self._senderChildSession2.updateUserConfiguration(
                newConfig.getVerifiedDevices())
            
            try await self.createRecipientSession(store: recipientStore)
            let masterRecipientConfig = await self._recipientSession.sessionContext!
                .activeUserConfiguration
            try await self.linkRecipientChildSession1(store: recipientChildStore1)
            
            let childRecipientConfig1 = await _recipientChildSession1.sessionContext!
                .activeUserConfiguration
            
            let childRecipientDevice1 = try childRecipientConfig1.signedDevices.last!.verified(
                using: Curve25519.Signing.PublicKey(
                    rawRepresentation: childRecipientConfig1.signingPublicKey))!
            
            let newSignedRecipient = try UserConfiguration.SignedDeviceConfiguration(
                device: childRecipientDevice1,
                signingKey: Curve25519.Signing.PrivateKey(
                    rawRepresentation: await _recipientSession.sessionContext!.sessionUser.deviceKeys.signingPrivateKey))
            
            try await self.linkRecipientChildSession2(store: recipientChildStore2)
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
                signedPQKemOneTimePublicKeys: masterRecipientConfig.signedPQKemOneTimePublicKeys)
            
            //Publish the new config to the remote store
            let recipientSecretName = await self._recipientSession.sessionContext!.sessionUser
                .secretName
            if let index = transport.userConfigurations.firstIndex(where: {
                $0.secretName == recipientSecretName
            }) {
                transport.userConfigurations[index].config = newRecipientConfig
            }
            
            try await self._recipientSession.updateUserConfiguration(
                newRecipientConfig.getVerifiedDevices())
            try await self._recipientChildSession1.updateUserConfiguration(
                newRecipientConfig.getVerifiedDevices())
            try await self._recipientChildSession2.updateUserConfiguration(
                newRecipientConfig.getVerifiedDevices())
            
            _ = try await self._senderSession.createContact(
                secretName: "bob",
                metadata: [:],
                requestFriendship: true)
            
            try await self._senderSession.writeTextMessage(
                recipient: .nickname("bob"), text: "Message One", metadata: [:])
            
        }
        
        aliceTask = Task {
            await #expect(
                throws: Never.self,
                "Alice's message processing loop should handle received messages without errors"
            ) {
                var aliceIterations = 0
                for await received in aliceStream {
                    aliceIterations += 1
                    try await self._senderSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    
                    // Note: Child devices should not receive master device messages
                    // This would cause ratchet state mismatches
                    print("Alice master device processed message \(aliceIterations)")
                    
                    if aliceIterations == 2 {
                        try await self._senderSession.writeTextMessage(
                            recipient: .nickname("bob"), text: "Message Four", metadata: [:])
                        try await self._senderSession.writeTextMessage(
                            recipient: .nickname("bob"), text: "Message Five", metadata: [:])
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
                try await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                )
                
                if bobIterations == 1 {
                    try await self._recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                    try await self._recipientSession.writeTextMessage(
                        recipient: .nickname("alice"), text: "Message Three", metadata: [:])
                }
                
                if bobIterations == 3 {
                    self.aliceStreamContinuation?.finish()
                    self.bobStreamContinuation?.finish()
                }
            }
            await shutdownSessions()
        }
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
    
    func synchronizeCommunication(
        recipient _: SessionModels.MessageRecipient, sharedIdentifier _: String
    ) async throws {}
    func requestFriendshipStateChange(
        recipient: SessionModels.MessageRecipient, blockData: Data?, metadata: BSON.Document,
        currentState: SessionModels.FriendshipMetadata.State
    ) async throws {}
    func deliveryStateChanged(
        recipient _: SessionModels.MessageRecipient, metadata _: BSON.Document
    ) async throws {}
    func contactCreated(recipient _: SessionModels.MessageRecipient) async throws {}
    func requestMetadata(recipient _: SessionModels.MessageRecipient) async throws {}
    func editMessage(recipient _: SessionModels.MessageRecipient, metadata _: BSON.Document)
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
    func processUnpersistedMessage(
        _: SessionModels.CryptoMessage, senderSecretName _: String, senderDeviceId _: UUID
    ) async -> Bool { true }
}

final class MockDeviceLinkingDelegate: DeviceLinkingDelegate, @unchecked Sendable {
    let secretName: String
    
    init(secretName: String) {
        self.secretName = secretName
    }
    
    func generateDeviceCryptographic(_ data: Data, password: String) async -> LinkDeviceInfo? {
        // Decode the device configuration from the data parameter
        guard
            let deviceConfig = try? BSONDecoder().decodeData(
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

// Mock classes from SessionIdentityTests
final class MockSessionIdentityStore: PQSSessionStore, @unchecked Sendable {
    var sessionContext: Data?
    var identities = [SessionIdentity]()
    
    // Core session context methods
    func createLocalSessionContext(_ data: Data) async throws { sessionContext = data }
    func fetchLocalSessionContext() async throws -> Data {
        guard let context = sessionContext else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        return context
    }
    func updateLocalSessionContext(_ data: Data) async throws { sessionContext = data }
    func deleteLocalSessionContext() async throws { sessionContext = nil }
    
    // Device salt methods
    func fetchLocalDeviceSalt(keyData: Data) async throws -> Data {
        keyData + "salt".data(using: .utf8)!
    }
    func deleteLocalDeviceSalt() async throws {}
    func fetchLocalDeviceSalt() async throws -> String { "test-salt" }
    
    // Device configuration methods
    func findLocalDeviceConfiguration() async throws -> Data { Data() }
    func createLocalDeviceConfiguration(_ configuration: Data) async throws {}
    
    // Session identity methods
    func fetchSessionIdentities() async throws -> [SessionIdentity] { identities }
    func updateSessionIdentity(_ session: SessionIdentity) async throws {
        identities.removeAll(where: { $0.id == session.id })
        identities.append(session)
    }
    func createSessionIdentity(_ session: SessionIdentity) async throws {
        identities.append(session)
    }
    func deleteSessionIdentity(_ id: UUID) async throws {
        identities.removeAll(where: { $0.id == id })
    }
    
    // Stub implementations for unused methods
    func removeContact(_: UUID) async throws {}
    func deleteContact(_: UUID) async throws {}
    func createMediaJob(_: DataPacket) async throws {}
    func fetchAllMediaJobs() async throws -> [DataPacket] { [] }
    func fetchMediaJob(id _: UUID) async throws -> DataPacket? { nil }
    func deleteMediaJob(_: UUID) async throws {}
    func fetchContacts() async throws -> [ContactModel] { [] }
    func createContact(_: ContactModel) async throws {}
    func updateContact(_: ContactModel) async throws {}
    func fetchCommunications() async throws -> [BaseCommunication] { [] }
    func createCommunication(_: BaseCommunication) async throws {}
    func updateCommunication(_: BaseCommunication) async throws {}
    func removeCommunication(_: BaseCommunication) async throws {}
    func deleteCommunication(_: BaseCommunication) async throws {}
    func fetchMessages(sharedCommunicationId _: UUID) async throws -> [MessageRecord] { [] }
    func fetchMessage(id _: UUID) async throws -> EncryptedMessage {
        try .init(
            id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123",
            sequenceNumber: 1, data: Data())
    }
    func fetchMessage(sharedId _: String) async throws -> EncryptedMessage {
        try .init(
            id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123",
            sequenceNumber: 1, data: Data())
    }
    func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {}
    func updateMessage(_: EncryptedMessage, symmetricKey: SymmetricKey) async throws {}
    func removeMessage(_: EncryptedMessage) async throws {}
    func deleteMessage(_: EncryptedMessage) async throws {}
    func streamMessages(sharedIdentifier _: UUID) async throws -> (
        AsyncThrowingStream<EncryptedMessage, any Error>,
        AsyncThrowingStream<EncryptedMessage, any Error>.Continuation?
    ) {
        let stream = AsyncThrowingStream<EncryptedMessage, any Error> { _ in }
        return (stream, nil)
    }
    func messageCount(sharedIdentifier _: UUID) async throws -> Int { 0 }
    func readJobs() async throws -> [JobModel] { [] }
    func fetchJobs() async throws -> [JobModel] { [] }
    func createJob(_: JobModel) async throws {}
    func updateJob(_: JobModel) async throws {}
    func removeJob(_: JobModel) async throws {}
    func deleteJob(_: JobModel) async throws {}
    func findMediaJobs(for _: String, symmetricKey: SymmetricKey) async throws -> [DataPacket] {
        []
    }
    func fetchMediaJobs(recipient _: String, symmetricKey: SymmetricKey) async throws
    -> [DataPacket]
    { [] }
    func findMediaJob(for _: String, symmetricKey: SymmetricKey) async throws -> DataPacket? { nil }
    func fetchMediaJob(synchronizationIdentifier _: String, symmetricKey: SymmetricKey) async throws
    -> DataPacket?
    { nil }
}

final class MockSessionIdentityTransport: SessionTransport, @unchecked Sendable {
    var configurations: [String: UserConfiguration] = [:]
    var oneTimeKeys: [String: OneTimeKeys] = [:]
    var shouldThrowError = false
    
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> OneTimeKeys {
        if shouldThrowError { throw PQSSession.SessionErrors.userNotFound }
        return oneTimeKeys[secretName] ?? OneTimeKeys(curve: nil, kyber: nil)
    }
    
    func fetchOneTimeKeyIdentities(for secretName: String, deviceId: String, type: KeysType)
    async throws -> [UUID]
    { [] }
    func publishUserConfiguration(_ configuration: UserConfiguration, recipient identity: UUID)
    async throws
    {}
    func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata)
    async throws
    {}
    
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
    func updateOneTimePQKemKeys(
        for secretName: String, deviceId: String, keys: [UserConfiguration.SignedPQKemOneTimeKey]
    ) async throws {}
    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: KeysType)
    async throws
    {}
    func deleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws {}
    func publishRotatedKeys(
        for secretName: String, deviceId: String, rotated keys: RotatedPublicKeys
    ) async throws {}
    func createUploadPacket(
        secretName: String, deviceId: UUID, recipient: MessageRecipient, metadata: Document
    ) async throws {}
}

actor ReceiverDelegate: EventReceiver {
    
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
    func synchronize(contact _: SessionModels.Contact, requestFriendship _: Bool) async throws {}
    func transportContactMetadata() async throws {}
    func updatedCommunication(_: SessionModels.BaseCommunication, members _: Set<String>) async {}
}

struct ReceivedMessage {
    let message: SignedRatchetMessage
    let sender: String
    let deviceId: UUID
    let messageId: String
}

final class _MockTransportDelegate: SessionTransport, @unchecked Sendable {
    struct IdentifiableSignedoneTimePublicKey {
        let id: String
        var keys: [UserConfiguration.SignedOneTimePublicKey]
    }
    
    struct IdentifiableSignedKyberOneTimeKey {
        let id: String
        var keys: [UserConfiguration.SignedPQKemOneTimeKey]
    }
    
    // MARK: - Properties
    
    var oneTimePublicKeyPairs = [IdentifiableSignedoneTimePublicKey]()
    var kyberOneTimeKeyPairs = [IdentifiableSignedKyberOneTimeKey]()
    var publishableName: String!
    var userConfigurations = [User]()
    var aliceStreamContinuation: AsyncStream<ReceivedMessage>.Continuation?
    var bobStreamContinuation: AsyncStream<ReceivedMessage>.Continuation?
    
    // MARK: - Used Methods
    
    func fetchOneTimeKeys(for secretName: String, deviceId _: String) async throws
    -> SessionModels.OneTimeKeys
    {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.signingPublicKey else { fatalError() }
        let signingKey = try Curve25519SigningPublicKey(rawRepresentation: signingKeyData)
        
        guard
            let oneTimeKeyPairIndex = oneTimePublicKeyPairs.firstIndex(where: {
                $0.id == secretName
            })
        else { fatalError() }
        let oneTimeKeyPair = oneTimePublicKeyPairs[oneTimeKeyPairIndex]
        guard let publicKey = try oneTimeKeyPair.keys.last?.verified(using: signingKey) else {
            fatalError()
        }
        oneTimePublicKeyPairs.remove(at: oneTimeKeyPairIndex)
        
        guard
            let kyberKeyPairIndex = kyberOneTimeKeyPairs.firstIndex(where: { $0.id == secretName })
        else { fatalError() }
        let kyberKeyPair = kyberOneTimeKeyPairs[kyberKeyPairIndex]
        guard let kyberKey = try kyberKeyPair.keys.last?.verified(using: signingKey) else {
            fatalError()
        }
        kyberOneTimeKeyPairs.remove(at: kyberKeyPairIndex)
        
        return SessionModels.OneTimeKeys(curve: publicKey, kyber: kyberKey)
    }
    
    func fetchOneTimeKeyIdentities(for secretName: String, deviceId _: String, type _: KeysType)
    async throws -> [UUID]
    {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.signingPublicKey else { fatalError() }
        let signingKey = try Curve25519SigningPublicKey(rawRepresentation: signingKeyData)
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
        kyberOneTimeKeyPairs.append(
            IdentifiableSignedKyberOneTimeKey(
                id: publishableName, keys: configuration.signedPQKemOneTimePublicKeys))
    }
    
    func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata)
    async throws
    {
        guard let sender = userConfigurations.first(where: { $0.secretName != metadata.secretName })
        else { return }
        guard
            let recipient = userConfigurations.first(where: { $0.secretName == metadata.secretName }
            )
        else { return }
        let received = ReceivedMessage(
            message: message,
            sender: sender.secretName,
            deviceId: sender.deviceId,
            messageId: metadata.sharedMessageId
        )
        if recipient.secretName == "alice" {
            aliceStreamContinuation?.yield(received)
        } else if recipient.secretName == "bob" {
            bobStreamContinuation?.yield(received)
        }
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
        let oldSigningKey = try Curve25519SigningPublicKey(
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
    
    // MARK: - Unused Methods (Stubs)
    
    func receiveMessage() async throws -> String { "" }
    func updateOneTimeKeys(
        for _: String, deviceId _: String,
        keys _: [SessionModels.UserConfiguration.SignedOneTimePublicKey]
    ) async throws {}
    func updateOneTimePQKemKeys(
        for _: String, deviceId _: String,
        keys _: [SessionModels.UserConfiguration.SignedPQKemOneTimeKey]
    ) async throws {}
    func batchDeleteOneTimeKeys(for _: String, with _: String, type _: SessionModels.KeysType)
    async throws
    {}
    func deleteOneTimeKeys(for _: String, with _: String, type _: SessionModels.KeysType)
    async throws
    {}
    func createUploadPacket(
        secretName _: String, deviceId _: UUID, recipient _: SessionModels.MessageRecipient,
        metadata _: BSON.Document
    ) async throws {}
    func notifyIdentityCreation(for _: String, keys _: SessionModels.OneTimeKeys) async throws {}
}

final class MockIdentityStore: PQSSessionStore, @unchecked Sendable {
    // MARK: - Properties
    
    var sessionContext: Data?
    var identities = [SessionIdentity]()
    let crypto = NeedleTailCrypto()
    var mockUserData: MockUserData
    let session: PQSSession
    let isSender: Bool
    var localDeviceSalt: String?
    var encyrptedConfigurationForTesting = Data()
    var createdMessages = [EncryptedMessage]()
    var contacts = [ContactModel]()
    
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
    func fetchSessionIdentities() async throws -> [DoubleRatchetKit.SessionIdentity] { identities }
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
    func fetchCommunications() async throws -> [SessionModels.BaseCommunication] { [] }
    func createCommunication(_: SessionModels.BaseCommunication) async throws {}
    func updateCommunication(_: SessionModels.BaseCommunication) async throws {}
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
        metadata: [:],
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

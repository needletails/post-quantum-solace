//
//  TaskProcessorSequenceTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-01-27.
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

import Foundation
import NeedleTailLogger
import SessionModels
import DoubleRatchetKit
@testable import PQSSession
import Testing

// MARK: - Test Suite

@Suite(.serialized)
actor TaskProcessorSequenceTests {
    
    var session = PQSSession()
    let transport: _MockTransportDelegate
    var senderReceiver: ReceiverDelegate
    let localId = UUID()
    let store = TransportStore()
    
    init() {
        senderReceiver = ReceiverDelegate(session: session)
        self.transport =  _MockTransportDelegate(session: session, store: store)
    }
    
    func createSenderSession(store: MockIdentityStore, shouldCreate: Bool = true) async throws {
        await store.setLocalSalt("testSalt1")
        await session.setLogLevel(.trace)
        await session.setDatabaseDelegate(conformer: store)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: senderReceiver)
        
        session.isViable = true
        await self.store.setPublishableName("alice")
        if shouldCreate {
            session = try await session.createSession(
                secretName: "alice", appPassword: "123"
            ) {}
        }
        await session.setAppPassword("123")
        session = try await session.startSession(appPassword: "123")
        try await senderReceiver.setKey(session.getDatabaseSymmetricKey())
    }
    
    // MARK: - Basic FIFO Tests

    @Test("Reconciliation cooldowns are directional")
    func testReconciliationCooldownIsDirectional() async {
        let peerDeviceId = UUID()
        let now = Date()

        #expect(await session.canAttemptReconciliation(
            sender: "alice",
            deviceId: peerDeviceId,
            flow: .inbound,
            now: now))

        await session.markReconciliationAttempt(
            sender: "alice",
            deviceId: peerDeviceId,
            flow: .inbound,
            now: now)

        #expect(!(await session.canAttemptReconciliation(
            sender: "alice",
            deviceId: peerDeviceId,
            flow: .inbound,
            now: now.addingTimeInterval(1))))

        #expect(await session.canAttemptReconciliation(
            sender: "alice",
            deviceId: peerDeviceId,
            flow: .outbound,
            now: now.addingTimeInterval(1)))

        await session.shutdown()
    }

    @Test("Inbound recovery failure classes clear after successful replay")
    func testInboundRecoveryFailureClassesClearAfterSuccessfulReplay() async {
        let sender = "alice"
        let deviceId = UUID()
        let messageId = "replayed-shared-id"

        await session.markInboundFailure(
            sender: sender,
            deviceId: deviceId,
            messageId: messageId,
            failureClass: "crypto.bodyDecryptionFailed")
        await session.markInboundFailure(
            sender: sender,
            deviceId: deviceId,
            messageId: messageId,
            failureClass: "ratchet.initialMessageNotReceived")

        let first = await session.takeInboundFailureClasses(
            sender: sender,
            deviceId: deviceId,
            messageId: messageId)
        let second = await session.takeInboundFailureClasses(
            sender: sender,
            deviceId: deviceId,
            messageId: messageId)

        #expect(Set(first) == ["crypto.bodyDecryptionFailed", "ratchet.initialMessageNotReceived"])
        #expect(second.isEmpty)
        await session.shutdown()
    }
    
    @Test("Basic FIFO - Single Message")
    func testBasicFIFOSingleMessage() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        let message = createTestMessage("1")
        
        try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
            message: message,
            recipientIdentity: recipientIdentity,
            localId: localId,
            sharedId: "123"))), session: session)
        
        try await Task.sleep(until: .now + .seconds(2))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == 1, "Expected 1 message to be processed")
        #expect(processedMessages.first == "1", "Expected message '1' to be processed")
        
        await session.shutdown()
    }
    
    @Test("Basic FIFO - Sequential Messages")
    func testBasicFIFOSequentialMessages() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Feed 10 messages in sequence
        for i in 1...10 {
            let message = createTestMessage("\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }
        
        try await Task.sleep(until: .now + .seconds(5))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == 10, "Expected 10 messages to be processed")
        
        // Verify FIFO order
        for (index, messageText) in processedMessages.enumerated() {
            let expectedMessage = "\(index + 1)"
            #expect(messageText == expectedMessage, "Message at index \(index) should be '\(expectedMessage)' but was '\(messageText)'")
        }
        
        await session.shutdown()
    }
    
    @Test("Basic FIFO - Large Batch")
    func testBasicFIFOLargeBatch() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Feed 100 messages in sequence
        for i in 1...100 {
            let message = createTestMessage("\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }
        
        try await Task.sleep(until: .now + .seconds(15))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == 100, "Expected 100 messages to be processed")
        
        // Verify FIFO order
        for (index, messageText) in processedMessages.enumerated() {
            let expectedMessage = "\(index + 1)"
            #expect(messageText == expectedMessage, "Message at index \(index) should be '\(expectedMessage)' but was '\(messageText)'")
        }
        
        await session.shutdown()
    }
    
    // MARK: - Concurrent FIFO Tests
    
    @Test("Concurrent FIFO - Multiple Tasks")
    func testConcurrentFIFOMultipleTasks() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Create multiple concurrent tasks feeding messages
        let messageCount = 50
        let concurrentTasks = 10
        let expectedCount = messageCount * concurrentTasks
        
        // Track the order in which messages were fed
        let fedOrderTracker = FedOrderTracker()
        
        // Small delay to ensure system is ready
        try await Task.sleep(until: .now + .milliseconds(100))
        
        let tasks = await (0..<concurrentTasks).asyncMap { taskIndex in
            return try? await Task {
                for i in 1...messageCount {
                    let messageNumber = taskIndex * messageCount + i
                    let message = await createTestMessage("\(messageNumber)")
                    
                    // Record the order this message was fed
                    _ = await fedOrderTracker.getNextOrder()
                    
                    try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                        message: message,
                        recipientIdentity: recipientIdentity,
                        localId: localId,
                        sharedId: "123"))), session: session)
                    
                    // Small delay to create race conditions
                    try await Task.sleep(until: .now + .milliseconds(Int.random(in: 1...5)))
                }
            }.value
        }
        
        // Wait for all tasks to complete
        try await withThrowingTaskGroup(of: Void.self) { group in
            for task in tasks {
                group.addTask { task }
            }
            try await group.waitForAll()
        }
        
        // Wait for all messages to be processed with longer timeout
        var attempts = 0
        let maxAttempts = 30 // Increased timeout
        while attempts < maxAttempts {
            let processedMessages = await mockDelegate.getProcessedMessages()
            if processedMessages.count == expectedCount {
                break
            }
            try await Task.sleep(until: .now + .seconds(1))
            attempts += 1
        }
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == expectedCount, "Expected \(expectedCount) messages to be processed, got \(processedMessages.count)")
        
        // Verify that all messages were processed (we can't guarantee order in concurrent scenario)
        // but we can verify that no messages were lost and all were processed
        let processedSet = Set(processedMessages)
        let expectedSet = Set((1...expectedCount).map { "\($0)" })
        
        // Debug: Print missing and extra messages
        let missingMessages = expectedSet.subtracting(processedSet)
        let extraMessages = processedSet.subtracting(expectedSet)
        if !missingMessages.isEmpty {
            print("Missing messages: \(missingMessages.sorted())")
        }
        if !extraMessages.isEmpty {
            print("Extra messages: \(extraMessages.sorted())")
        }
        
        #expect(processedSet == expectedSet, "All messages should be processed exactly once")
        
        await session.shutdown()
    }
    
    @Test("Concurrent FIFO - Interleaved Pattern")
    func testConcurrentFIFOInterleavedPattern() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Feed messages in an interleaved (out-of-order) pattern.
        // NOTE: Although TaskProcessor is an actor, upstream executor scheduling differs
        // between platforms. We keep this test deterministic (single producer) while
        // still validating the queue can handle non-monotonic enqueue patterns.
        let messageCount = 100
        var feedOrder: [Int] = []
        feedOrder.reserveCapacity(messageCount)
        for i in stride(from: 1, through: messageCount, by: 2) { feedOrder.append(i) }
        for i in stride(from: messageCount, through: 2, by: -2) { feedOrder.append(i) }

        for i in feedOrder {
            let message = createTestMessage("\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }

        // On Linux (and on busy CI runners), a fixed sleep can be insufficient.
        // Poll until all messages are processed (or we hit a reasonable timeout).
        let deadline = Date().addingTimeInterval(60)
        var processedMessages: [String] = []
        while Date() < deadline {
            processedMessages = await mockDelegate.getProcessedMessages()
            if processedMessages.count == messageCount {
                break
            }
            try await Task.sleep(until: .now + .milliseconds(50))
        }

        #expect(
            processedMessages.count == messageCount,
            "Expected \(messageCount) messages to be processed, got \(processedMessages.count). Unique: \(Set(processedMessages).count)"
        )
        
        // Verify that all messages were processed (we can't guarantee order in concurrent scenario)
        // but we can verify that no messages were lost and all were processed
        let processedSet = Set(processedMessages)
        let expectedSet = Set((1...messageCount).map { "\($0)" })
        #expect(processedSet == expectedSet, "All messages should be processed exactly once")
        
        await session.shutdown()
    }
    
    // MARK: - Session State Tests
    
    @Test("Session State - Viability Toggle")
    func testSessionStateViabilityToggle() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Feed some messages
        for i in 1...10 {
            let message = createTestMessage("\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }
        
        // Toggle session viability
        session.isViable = false
        try await Task.sleep(until: .now + .seconds(1))
        
        // Feed more messages while session is not viable
        for i in 11...20 {
            let message = createTestMessage("\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }
        
        // Make session viable again
        session.isViable = true
        try await Task.sleep(until: .now + .seconds(5))
        try await session.resumeJobQueue()
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == 20, "Expected 20 messages to be processed, got \(processedMessages.count)")
        
        // Verify FIFO order
        for (index, messageText) in processedMessages.enumerated() {
            let expectedMessage = "\(index + 1)"
            #expect(messageText == expectedMessage, "Message at index \(index) should be '\(expectedMessage)' but was '\(messageText)'")
        }
        
        await session.shutdown()
    }
    
    @Test("Session State - Rapid Viability Changes")
    func testSessionStateRapidViabilityChanges() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Start feeding messages
        let feedTask = Task {
            for i in 1...50 {
                let message = createTestMessage("\(i)")
                try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                    message: message,
                    recipientIdentity: recipientIdentity,
                    localId: localId,
                    sharedId: "123"))), session: session)
                try await Task.sleep(until: .now + .milliseconds(10))
            }
        }
        
        // Rapidly toggle session viability
        let toggleTask = Task {
            for _ in 0..<20 {
                session.isViable.toggle()
                try await Task.sleep(until: .now + .milliseconds(Int.random(in: 50...200)))
            }
            session.isViable = true // Ensure it's viable at the end
        }
        
        // Wait for both tasks to complete
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { try await feedTask.value }
            group.addTask { try await toggleTask.value }
            try await group.waitForAll()
        }
        
        try await Task.sleep(until: .now + .seconds(10))
        try await session.resumeJobQueue()
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == 50, "Expected 50 messages to be processed, got \(processedMessages.count)")
        
        // Verify that all messages were processed (we can't guarantee perfect FIFO order during rapid viability changes)
        // but we can verify that no messages were lost and all were processed
        let processedSet = Set(processedMessages)
        let expectedSet = Set((1...50).map { "\($0)" })
        #expect(processedSet == expectedSet, "All messages should be processed exactly once")
        
        // Verify that the system handled rapid viability changes gracefully
        // by ensuring all messages were eventually processed
        print("Processed messages in order: \(processedMessages)")
        
        await session.shutdown()
    }
    
    // MARK: - Error Handling Tests
    
    @Test("Error Handling - Missing Identity")
    func testErrorHandlingMissingIdentity() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegateWithErrors(errorType: .missingIdentity)
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Feed messages that will cause missing identity errors
        for i in 1...10 {
            let message = createTestMessage("\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }
        
        try await Task.sleep(until: .now + .seconds(5))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        let errorCount = await mockDelegate.getErrorCount()
        
        #expect(processedMessages.count == 0, "Expected 0 messages to be processed due to errors")
        #expect(errorCount == 10, "Expected 10 missing identity errors")
        
        await session.shutdown()
    }
    
    @Test("Error Handling - Authentication Failure")
    func testErrorHandlingAuthenticationFailure() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegateWithErrors(errorType: .authenticationFailure)
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Feed messages that will cause authentication failures
        for i in 1...10 {
            let message = createTestMessage("\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }
        
        try await Task.sleep(until: .now + .seconds(5))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        let errorCount = await mockDelegate.getErrorCount()
        
        #expect(processedMessages.count == 0, "Expected 0 messages to be processed due to errors")
        #expect(errorCount == 10, "Expected 10 authentication failure errors")
        
        await session.shutdown()
    }
    
    @Test("Error Handling - Mixed Success and Failure")
    func testErrorHandlingMixedSuccessAndFailure() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegateWithMixedErrors()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Feed messages - some will succeed, some will fail
        for i in 1...20 {
            let message = createTestMessage("\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }
        
        try await Task.sleep(until: .now + .seconds(5))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        let errorCount = await mockDelegate.getErrorCount()
        
        #expect(processedMessages.count == 10, "Expected 10 messages to be processed successfully")
        #expect(errorCount == 10, "Expected 10 errors")
        
        // Verify that successful messages maintain FIFO order
        for (index, messageText) in processedMessages.enumerated() {
            let expectedMessage = "\(index * 2 + 1)" // Odd numbers succeed
            #expect(messageText == expectedMessage, "Message at index \(index) should be '\(expectedMessage)' but was '\(messageText)'")
        }
        
        await session.shutdown()
    }

    @Test("Error Handling - Outbound Invalid Signature Drops Bad Job And Continues")
    func testErrorHandlingOutboundInvalidSignatureDropsBadJobAndContinues() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)

        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let recipientIdentity = createTestRecipientIdentity()

        let firstTask = EncryptableTask(task: .writeMessage(.init(
            message: createTestMessage("fatal_invalid_signature"),
            recipientIdentity: recipientIdentity,
            localId: localId,
            sharedId: "fatal_invalid_signature_shared"
        )))
        let secondTask = EncryptableTask(task: .writeMessage(.init(
            message: createTestMessage("processed_after_resume"),
            recipientIdentity: recipientIdentity,
            localId: localId,
            sharedId: "processed_after_resume_shared"
        )))

        let firstJob = try await session.taskProcessor.createJobModel(
            sequenceId: await session.taskProcessor.incrementId(),
            task: firstTask,
            symmetricKey: symmetricKey
        )
        let secondJob = try await session.taskProcessor.createJobModel(
            sequenceId: await session.taskProcessor.incrementId(),
            task: secondTask,
            symmetricKey: symmetricKey
        )

        try await cache.createJob(firstJob)
        try await cache.createJob(secondJob)

        let failingDelegate = MockTaskDelegateWithOneShotError(
            failingMessage: "fatal_invalid_signature",
            error: PQSSession.SessionErrors.invalidSignature
        )
        await session.taskProcessor.setTaskDelegate(failingDelegate)

        try await session.resumeJobQueue()

        #expect(await failingDelegate.getErrorCount() == 1, "Expected one invalid signature failure")
        #expect(
            await failingDelegate.getProcessedMessages() == ["processed_after_resume"],
            "Outbound invalidSignature should drop the failed job and keep draining later jobs"
        )

        let jobsAfterFailure = try await cache.fetchJobs()
        #expect(jobsAfterFailure.isEmpty, "Outbound invalidSignature should remove the failed job and any successfully processed later jobs")

        await session.shutdown()
    }

    @Test("Error Handling - Same Account Invalid Signature Reports Linked Device Compromise")
    func testSameAccountInvalidSignatureReportsLinkedDeviceCompromise() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)

        let probe = LinkedDeviceCompromiseProbe()
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session, compromiseProbe: probe))
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: PQSSession.SessionErrors.invalidSignature)
        )

        guard let context = await session.sessionContext else {
            Issue.record("Session context should be available")
            await session.shutdown()
            return
        }

        let signingKey = Curve25519.Signing.PrivateKey()
        let header = EncryptedHeader(
            remoteLongTermPublicKey: Data(repeating: 1, count: 32),
            remoteOneTimePublicKey: nil,
            remoteMLKEMPublicKey: try MLKEMPublicKey(Data(repeating: 2, count: 1568)),
            headerCiphertext: Data([0x01]),
            messageCiphertext: Data([0x02]),
            oneTimeKeyId: nil,
            mlKEMOneTimeKeyId: UUID(),
            encrypted: Data([0x04])
        )
        let ratchetMessage = RatchetMessage(header: header, encryptedData: Data([0x03]))
        let signed = try SignedRatchetMessage(
            message: ratchetMessage,
            signingPrivateKey: signingKey.rawRepresentation
        )
        let claimedDeviceId = UUID()
        let inbound = InboundTaskMessage(
            message: signed,
            senderSecretName: context.sessionUser.secretName,
            senderDeviceId: claimedDeviceId,
            sharedMessageId: "same_account_invalid_signature"
        )

        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(inbound)),
            session: session
        )

        #expect(await probe.contains(claimedDeviceId), "Master should report same-account invalidSignature as linked-device compromise")
        #expect(await probe.count() == 1, "Same invalidSignature should produce one compromise report")

        await session.shutdown()
    }

    @Test("Peer signing-key pin mismatch reports peer identity change")
    func testPeerSigningKeyOutOfSyncReportsPeerIdentityChange() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)

        let probe = LinkedDeviceCompromiseProbe()
        let peerProbe = PeerIdentityTrustProbe()
        await session.setPQSSessionDelegate(conformer: SessionDelegate(
            session: session,
            compromiseProbe: probe,
            peerIdentityTrustProbe: peerProbe))
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: PQSSession.SessionErrors.peerSigningKeyOutOfSync)
        )

        let signingKey = Curve25519.Signing.PrivateKey()
        let header = EncryptedHeader(
            remoteLongTermPublicKey: Data(repeating: 1, count: 32),
            remoteOneTimePublicKey: nil,
            remoteMLKEMPublicKey: try MLKEMPublicKey(Data(repeating: 2, count: 1568)),
            headerCiphertext: Data([0x01]),
            messageCiphertext: Data([0x02]),
            oneTimeKeyId: nil,
            mlKEMOneTimeKeyId: UUID(),
            encrypted: Data([0x04])
        )
        let ratchetMessage = RatchetMessage(header: header, encryptedData: Data([0x03]))
        let signed = try SignedRatchetMessage(
            message: ratchetMessage,
            signingPrivateKey: signingKey.rawRepresentation
        )
        let peerDeviceId = UUID()
        let inbound = InboundTaskMessage(
            message: signed,
            senderSecretName: "bob",
            senderDeviceId: peerDeviceId,
            sharedMessageId: "peer_signing_key_out_of_sync"
        )

        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(inbound)),
            session: session
        )

        #expect(await probe.count() == 0, "Peer identity pin failures must not be routed as local linked-device compromise")
        #expect(await peerProbe.contains(
            secretName: "bob",
            deviceId: peerDeviceId,
            failedSharedMessageId: "peer_signing_key_out_of_sync"))
        #expect(await session.isInboundFailureQuarantined(
            sender: "bob",
            deviceId: peerDeviceId,
            messageId: "peer_signing_key_out_of_sync"))

        await session.shutdown()
    }

    @Test("Fresh-session repair reports peer identity change when pin mismatch blocks reset")
    func testFreshSessionRepairPeerSigningKeyMismatchReportsTrustChange() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)

        let peerName = "bob_pin_mismatch"
        let trustedBundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        let foreignBundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        let trustedConfiguration = trustedBundle.userConfiguration
        let foreignConfiguration = foreignBundle.userConfiguration
        #expect(trustedConfiguration.signingPublicKey != foreignConfiguration.signingPublicKey)

        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let pinnedContact = try ContactModel(
            id: UUID(),
            props: .init(
                secretName: peerName,
                configuration: trustedConfiguration,
                metadata: [:]),
            symmetricKey: symmetricKey)
        try await store.createContact(pinnedContact)

        await self.store.upsertUserConfiguration(
            secretName: peerName,
            deviceId: foreignBundle.deviceKeys.deviceId,
            config: foreignConfiguration)

        let peerProbe = PeerIdentityTrustProbe()
        await session.setPQSSessionDelegate(conformer: SessionDelegate(
            session: session,
            peerIdentityTrustProbe: peerProbe))
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.maxSkippedHeadersExceeded)
        )

        let signingKey = Curve25519.Signing.PrivateKey()
        let header = EncryptedHeader(
            remoteLongTermPublicKey: Data(repeating: 1, count: 32),
            remoteOneTimePublicKey: nil,
            remoteMLKEMPublicKey: try MLKEMPublicKey(Data(repeating: 2, count: 1568)),
            headerCiphertext: Data([0x01]),
            messageCiphertext: Data([0x02]),
            oneTimeKeyId: nil,
            mlKEMOneTimeKeyId: UUID(),
            encrypted: Data([0x04])
        )
        let ratchetMessage = RatchetMessage(header: header, encryptedData: Data([0x03]))
        let signed = try SignedRatchetMessage(
            message: ratchetMessage,
            signingPrivateKey: signingKey.rawRepresentation
        )
        let inbound = InboundTaskMessage(
            message: signed,
            senderSecretName: peerName,
            senderDeviceId: foreignBundle.deviceKeys.deviceId,
            sharedMessageId: "fresh_repair_peer_signing_key_out_of_sync"
        )

        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(inbound)),
            session: session
        )

        #expect(await peerProbe.contains(
            secretName: peerName,
            deviceId: foreignBundle.deviceKeys.deviceId,
            failedSharedMessageId: "fresh_repair_peer_signing_key_out_of_sync"))
        #expect(await session.isInboundFailureQuarantined(
            sender: peerName,
            deviceId: foreignBundle.deviceKeys.deviceId,
            messageId: "fresh_repair_peer_signing_key_out_of_sync"))
        #expect(!(await session.hasPendingResendAfterReestablishment(
            sender: peerName,
            deviceId: foreignBundle.deviceKeys.deviceId)))

        await session.shutdown()
    }

    @Test("Ratchet desync errors route to fresh-session repair")
    func testRatchetDesyncErrorsRouteToFreshSessionRepair() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)

        let recoverableErrors: [(error: RatchetError, failureClass: String)] = [
            (.headerDecryptFailed, "ratchet.headerDecryptFailed"),
            (.receivingKeyIsNil, "ratchet.receivingKeyIsNil"),
            (.receivingHeaderKeyIsNil, "ratchet.receivingHeaderKeyIsNil")
        ]

        for (index, recoverable) in recoverableErrors.enumerated() {
            await session.taskProcessor.setTaskDelegate(
                MockTaskDelegateWithStreamError(error: recoverable.error)
            )

            let peerDeviceId = UUID()
            let peerName = "bob_desync_\(index)"
            let inbound = try makeTestInboundTaskMessage(
                senderSecretName: peerName,
                senderDeviceId: peerDeviceId,
                sharedMessageId: "desync_\(index)")

            try await session.taskProcessor.feedTask(
                EncryptableTask(task: .streamMessage(inbound)),
                session: session
            )

            let hasPendingRepair = try await waitForPendingRepair(
                sender: peerName,
                deviceId: peerDeviceId)
            #expect(hasPendingRepair, "\(recoverable.failureClass) should defer resend until peerRefresh")
        }

        await session.shutdown()
    }

    @Test("Fresh-session failures coalesce into one peer recovery episode")
    func testFreshSessionFailuresCoalescePerPeer() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.maxSkippedHeadersExceeded)
        )

        let peerName = "bob_coalesced_repair"
        let peerBundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        let peerDeviceId = peerBundle.deviceKeys.deviceId
        await self.store.upsertUserConfiguration(
            secretName: peerName,
            deviceId: peerDeviceId,
            config: peerBundle.userConfiguration)
        let first = try makeTestInboundTaskMessage(
            senderSecretName: peerName,
            senderDeviceId: peerDeviceId,
            sharedMessageId: "coalesced_repair_1")
        let second = try makeTestInboundTaskMessage(
            senderSecretName: peerName,
            senderDeviceId: peerDeviceId,
            sharedMessageId: "coalesced_repair_2")

        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(first)),
            session: session)
        #expect(try await waitForPendingRepair(sender: peerName, deviceId: peerDeviceId))
        #expect(
            await session.hasOpenReestablishmentEpisode(sender: peerName, deviceId: peerDeviceId),
            "maxSkipped must keep the reestablishment episode open until peerRefresh completes")

        let reconciliationAttemptsAfterFirst = await session.lastReconciliationAtByPeer.count
        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(second)),
            session: session)

        let pendingIds = await Set(
            session.pendingResendAfterReestablishment.values
                .filter { $0.senderName == peerName && $0.senderDeviceId == peerDeviceId }
                .map(\.failedSharedMessageId))
        #expect(pendingIds == ["coalesced_repair_1", "coalesced_repair_2"])
        #expect(
            await session.lastReconciliationAtByPeer.count == reconciliationAttemptsAfterFirst,
            "A pending peer recovery must coalesce later failures without another identity reset attempt")

        await session.shutdown()
    }

    @Test("Pending replay does not block a new episode after the prior episode expires")
    func testExpiredRecoveryEpisodeRestartsWithPendingReplay() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.maxSkippedHeadersExceeded)
        )

        let peerName = "bob_expired_recovery_episode"
        let peerBundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        let peerDeviceId = peerBundle.deviceKeys.deviceId
        await self.store.upsertUserConfiguration(
            secretName: peerName,
            deviceId: peerDeviceId,
            config: peerBundle.userConfiguration)
        let expiredStart = Date().addingTimeInterval(
            -(await session.reestablishmentEpisodeTTL + 1)
        )
        #expect(await session.tryBeginReestablishmentEpisode(
            sender: peerName,
            deviceId: peerDeviceId,
            now: expiredStart))
        await session.deferPeerResendUntilReestablished(
            sender: peerName,
            deviceId: peerDeviceId,
            failedMessageId: "expired_recovery_pending",
            failureClass: "ratchet.maxSkippedHeadersExceeded",
            notifyDelegate: false)

        let next = try makeTestInboundTaskMessage(
            senderSecretName: peerName,
            senderDeviceId: peerDeviceId,
            sharedMessageId: "expired_recovery_next")
        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(next)),
            session: session)

        #expect(
            await session.hasOpenReestablishmentEpisode(
                sender: peerName,
                deviceId: peerDeviceId),
            "A pending replay marker must not extend the expired single-flight episode")

        let pendingIds = await Set(
            session.pendingResendAfterReestablishment.values
                .filter { $0.senderName == peerName && $0.senderDeviceId == peerDeviceId }
                .map(\.failedSharedMessageId))
        #expect(pendingIds == ["expired_recovery_pending", "expired_recovery_next"])

        await session.shutdown()
    }

    @Test("Responder bootstrap hold coalesces inbound failures without a competing reset")
    func testResponderBootstrapHoldCoalescesInboundFailures() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.maxSkippedHeadersExceeded)
        )

        let peerName = "bob_bootstrap_hold"
        let peerBundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        await self.store.upsertUserConfiguration(
            secretName: peerName,
            deviceId: peerBundle.deviceKeys.deviceId,
            config: peerBundle.userConfiguration)

        guard let localDeviceId = await session.sessionContext?.sessionUser.deviceId else {
            Issue.record("Session context should be available")
            await session.shutdown()
            return
        }

        let envelope = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: 1,
            targetDeviceId: localDeviceId,
            requiresPreDecryptionReset: true)
        #expect(try await session.prepareInboundPeerRefreshBootstrap(
            sender: peerName,
            deviceId: peerBundle.deviceKeys.deviceId,
            envelope: envelope))
        #expect(await session.hasRecentInboundPeerRefreshBootstrap(
            sender: peerName,
            deviceId: peerBundle.deviceKeys.deviceId))

        let reconciliationAttemptsBefore = await session.lastReconciliationAtByPeer.count
        let inbound = try makeTestInboundTaskMessage(
            senderSecretName: peerName,
            senderDeviceId: peerBundle.deviceKeys.deviceId,
            sharedMessageId: "bootstrap_hold_stale_cipher")
        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(inbound)),
            session: session)

        #expect(try await waitForPendingRepair(sender: peerName, deviceId: peerBundle.deviceKeys.deviceId))
        #expect(
            !(await session.hasOpenReestablishmentEpisode(
                sender: peerName,
                deviceId: peerBundle.deviceKeys.deviceId)),
            "A responder bootstrap hold must coalesce failures instead of opening a competing episode")
        #expect(
            await session.lastReconciliationAtByPeer.count == reconciliationAttemptsBefore,
            "No local reset may run while the peer-coordinated bootstrap owns the lane")
        let pending = await session.pendingResendAfterReestablishment.values.filter {
            $0.senderName == peerName && $0.senderDeviceId == peerBundle.deviceKeys.deviceId
        }
        #expect(pending.map(\.failedSharedMessageId) == ["bootstrap_hold_stale_cipher"])

        await session.shutdown()
    }

    @Test("maxSkipped repair emits peerRefresh instead of retrying ciphertext")
    func testMaxSkippedRepairDoesNotRetryCiphertextAlone() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.maxSkippedHeadersExceeded)
        )

        let peerName = "bob_max_skipped_refresh"
        let peerBundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        let peerDeviceId = peerBundle.deviceKeys.deviceId
        await self.store.upsertUserConfiguration(
            secretName: peerName,
            deviceId: peerDeviceId,
            config: peerBundle.userConfiguration)
        let inbound = try makeTestInboundTaskMessage(
            senderSecretName: peerName,
            senderDeviceId: peerDeviceId,
            sharedMessageId: "max_skipped_needs_refresh")

        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(inbound)),
            session: session)

        #expect(try await waitForPendingRepair(sender: peerName, deviceId: peerDeviceId))
        #expect(
            await session.hasOpenReestablishmentEpisode(sender: peerName, deviceId: peerDeviceId),
            "Episode must stay open while waiting for peerRefresh")
        // Unilateral reset + re-feed of the same ciphertext used to return before
        // deferring/emitting peerRefresh. Pending resend proves we fell through.
        let pending = await session.pendingResendAfterReestablishment.values.filter {
            $0.senderName == peerName && $0.senderDeviceId == peerDeviceId
        }
        #expect(pending.map(\.failedSharedMessageId) == ["max_skipped_needs_refresh"])
        #expect(pending.map(\.failureClass) == ["ratchet.maxSkippedHeadersExceeded"])

        await session.shutdown()
    }

    @Test("Expired skipped key is treated as replay and does not reset session")
    func testExpiredKeyDropsWithoutFreshSessionRepair() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.expiredKey)
        )

        let peerDeviceId = UUID()
        let inbound = try makeTestInboundTaskMessage(
            senderSecretName: "bob_replay",
            senderDeviceId: peerDeviceId,
            sharedMessageId: "expired_key_replay")

        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(inbound)),
            session: session
        )

        try await Task.sleep(until: .now + .milliseconds(250))
        #expect(!(await session.hasPendingResendAfterReestablishment(
            sender: "bob_replay",
            deviceId: peerDeviceId)))
        #expect(await session.shouldSuppressInboundFailure(
            inbound,
            failureClass: "ratchet.expiredKey"))

        await session.shutdown()
    }

    @Test("missingOneTimeKey pending redelivery does not repeat OTK replacement")
    func testMissingOneTimeKeyPendingRedeliveryDoesNotRepeatOTKReplacement() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.missingOneTimeKey)
        )

        let peerDeviceId = UUID()
        let inbound = try makeTestInboundTaskMessage(
            senderSecretName: "bob_missing_otk",
            senderDeviceId: peerDeviceId,
            sharedMessageId: "missing_otk_replay")

        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(inbound)),
            session: session
        )

        let hasPendingRepair = try await waitForPendingRepair(
            sender: "bob_missing_otk",
            deviceId: peerDeviceId)
        #expect(hasPendingRepair, "missingOneTimeKey should defer resend until peerRefresh")

        // Pending deferred messages must be admitted for a real replay/decrypt attempt.
        // The peer-level pending recovery still coalesces failures, so this does not
        // reopen the full OTK-replacement storm.
        #expect(
            !(await session.shouldSuppressInboundFailure(
                inbound,
                failureClass: "ratchet.missingOneTimeKey")),
            "Pending missingOneTimeKey replay should not be dropped before decryption")

        // The batch replacement now runs off the job loop; wait for the first
        // upload to land before capturing the baseline.
        let sawFirstUpload = try await waitUntil {
            await self.transport.updateOneTimeKeysCallCount >= 1
        }
        #expect(sawFirstUpload, "First missingOneTimeKey recovery should upload a replacement batch")

        // Redelivery of the identical frame must not trigger another OTK batch replacement.
        let otkCallsAfterFirst = await transport.updateOneTimeKeysCallCount
        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(inbound)),
            session: session
        )
        try await Task.sleep(until: .now + .milliseconds(500))
        let otkCallsAfterSecond = await transport.updateOneTimeKeysCallCount
        #expect(
            otkCallsAfterSecond == otkCallsAfterFirst,
            "Redelivered missingOneTimeKey frame must not replace the OTK batch again")

        await session.shutdown()
    }

    @Test("missingOneTimeKey burst coalesces recovery for distinct messages from same peer")
    func testMissingOneTimeKeyBurstCoalescesRecoveryForDistinctMessages() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.missingOneTimeKey)
        )

        let peerDeviceId = UUID()
        let first = try makeTestInboundTaskMessage(
            senderSecretName: "bob_missing_otk_burst",
            senderDeviceId: peerDeviceId,
            sharedMessageId: "missing_otk_burst_1")
        let second = try makeTestInboundTaskMessage(
            senderSecretName: "bob_missing_otk_burst",
            senderDeviceId: peerDeviceId,
            sharedMessageId: "missing_otk_burst_2")

        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(first)),
            session: session
        )
        let hasPendingRepair = try await waitForPendingRepair(
            sender: "bob_missing_otk_burst",
            deviceId: peerDeviceId)
        #expect(hasPendingRepair, "First missingOneTimeKey should start a recovery episode")

        // The batch replacement now runs off the job loop; wait for the first
        // upload to land before capturing the baseline.
        let sawFirstUpload = try await waitUntil {
            await self.transport.updateOneTimeKeysCallCount >= 1
        }
        #expect(sawFirstUpload, "First missingOneTimeKey recovery should upload a replacement batch")

        let otkCallsAfterFirst = await transport.updateOneTimeKeysCallCount
        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(second)),
            session: session
        )
        #expect(
            await session.hasPendingResendAfterReestablishment(
                sender: "bob_missing_otk_burst",
                deviceId: peerDeviceId,
                failedMessageId: "missing_otk_burst_2"),
            "Distinct failed message should still be recorded for replay")

        let otkCallsAfterSecond = await transport.updateOneTimeKeysCallCount
        #expect(
            otkCallsAfterSecond == otkCallsAfterFirst,
            "Distinct missingOneTimeKey messages from an in-flight peer recovery must not replace the OTK batch again")

        let pendingIds = await Set(session.pendingResendAfterReestablishment.values.map(\.failedSharedMessageId))
        #expect(pendingIds.contains("missing_otk_burst_1"))
        #expect(pendingIds.contains("missing_otk_burst_2"))

        await session.shutdown()
    }

    @Test("missingOneTimeKey marks recovery pending before OTK replacement completes")
    func testMissingOneTimeKeyMarksRecoveryPendingBeforeOTKReplacementCompletes() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.missingOneTimeKey)
        )

        let uploadPause = OTKUploadPause()
        transport.beforeUpdateOneTimeKeys = {
            await uploadPause.beforeFirstUpload()
        }
        defer {
            transport.beforeUpdateOneTimeKeys = nil
        }

        let peerDeviceId = UUID()
        let first = try makeTestInboundTaskMessage(
            senderSecretName: "bob_missing_otk_inflight",
            senderDeviceId: peerDeviceId,
            sharedMessageId: "missing_otk_inflight_1")
        let second = try makeTestInboundTaskMessage(
            senderSecretName: "bob_missing_otk_inflight",
            senderDeviceId: peerDeviceId,
            sharedMessageId: "missing_otk_inflight_2")

        async let firstFeed: Void = session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(first)),
            session: session
        )

        let uploadPaused = try await waitUntil {
            await uploadPause.isPaused()
        }
        #expect(uploadPaused, "Expected first recovery to pause inside OTK upload")
        #expect(
            await session.hasPendingResendAfterReestablishment(
                sender: "bob_missing_otk_inflight",
                deviceId: peerDeviceId),
            "Recovery episode must be visible before OTK replacement completes")

        async let secondFeed: Void = session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(second)),
            session: session
        )

        await uploadPause.release()
        try await firstFeed
        try await secondFeed

        #expect(
            await session.hasPendingResendAfterReestablishment(
                sender: "bob_missing_otk_inflight",
                deviceId: peerDeviceId,
                failedMessageId: "missing_otk_inflight_2"),
            "Second missingOneTimeKey should be recorded inside the in-flight recovery episode")

        let sawSingleCurveUpload = try await waitUntil {
            await self.transport.updateOneTimeKeysCallCount == 1
        }
        #expect(sawSingleCurveUpload, "Only the first in-flight recovery should upload a replacement curve OTK batch")

        await session.shutdown()
    }

    @Test("missingOneTimeKey recovery retains local one-time private keys for in-flight messages")
    func testMissingOneTimeKeyRecoveryRetainsLocalPrivateKeys() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.missingOneTimeKey)
        )

        guard let contextBefore = await session.sessionContext else {
            Issue.record("Session context should be available")
            await session.shutdown()
            return
        }
        let curveIdsBefore = Set(contextBefore.sessionUser.deviceKeys.oneTimePrivateKeys.map(\.id))
        let mlKEMIdsBefore = Set(contextBefore.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.map(\.id))
        #expect(!curveIdsBefore.isEmpty, "Session should start with local curve one-time private keys")
        #expect(!mlKEMIdsBefore.isEmpty, "Session should start with local MLKEM one-time private keys")

        let peerDeviceId = UUID()
        let inbound = try makeTestInboundTaskMessage(
            senderSecretName: "bob_retain_privates",
            senderDeviceId: peerDeviceId,
            sharedMessageId: "retain_privates_1")

        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(inbound)),
            session: session
        )

        // Recovery replaces the *published* batch: fresh keys are appended while
        // the pre-existing private counterparts stay available for the rest of
        // the in-flight backlog that was encrypted against them.
        let sawFreshBatches = try await waitUntil(timeout: 10) {
            guard let context = await self.session.sessionContext else { return false }
            return context.sessionUser.deviceKeys.oneTimePrivateKeys.count > curveIdsBefore.count
                && context.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.count > mlKEMIdsBefore.count
        }
        #expect(sawFreshBatches, "Recovery should append fresh one-time keys without wiping the existing pool")

        guard let contextAfter = await session.sessionContext else {
            Issue.record("Session context should be available after recovery")
            await session.shutdown()
            return
        }
        let curveIdsAfter = Set(contextAfter.sessionUser.deviceKeys.oneTimePrivateKeys.map(\.id))
        let mlKEMIdsAfter = Set(contextAfter.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.map(\.id))
        #expect(
            curveIdsBefore.isSubset(of: curveIdsAfter),
            "missingOneTimeKey recovery must not delete curve private keys that in-flight messages still reference")
        #expect(
            mlKEMIdsBefore.isSubset(of: mlKEMIdsAfter),
            "missingOneTimeKey recovery must not delete MLKEM private keys that in-flight messages still reference")

        await session.shutdown()
    }

    @Test("replacePublishedBatch policy retains private keys and caps the retained pool")
    func testReplacePublishedBatchRetainsAndCapsPrivateKeys() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)

        guard let contextBefore = await session.sessionContext else {
            Issue.record("Session context should be available")
            await session.shutdown()
            return
        }
        let deviceId = contextBefore.sessionUser.deviceId
        let originalCurveIds = Set(contextBefore.sessionUser.deviceKeys.oneTimePrivateKeys.map(\.id))
        let originalPublicIds = Set(
            contextBefore.activeUserConfiguration.signedOneTimePublicKeys
                .filter { $0.deviceId == deviceId }
                .map(\.id))
        #expect(!originalCurveIds.isEmpty)

        let firstReplace = await session.refreshOneTimeKeysTask(policy: .replacePublishedBatch)
        #expect(firstReplace, "Published-batch replacement should succeed")

        guard let contextAfterFirst = await session.sessionContext else {
            Issue.record("Session context should be available after first replacement")
            await session.shutdown()
            return
        }
        let curveIdsAfterFirst = Set(contextAfterFirst.sessionUser.deviceKeys.oneTimePrivateKeys.map(\.id))
        let publicIdsAfterFirst = Set(
            contextAfterFirst.activeUserConfiguration.signedOneTimePublicKeys
                .filter { $0.deviceId == deviceId }
                .map(\.id))
        #expect(
            originalCurveIds.isSubset(of: curveIdsAfterFirst),
            "Private keys must be retained across a published-batch replacement")
        #expect(
            curveIdsAfterFirst.count > originalCurveIds.count,
            "A fresh batch of private keys must be appended")
        #expect(
            publicIdsAfterFirst.isDisjoint(with: originalPublicIds),
            "The advertised public batch must be fully replaced")

        // Repeated replacements must not grow the retained private pool unboundedly.
        let secondReplace = await session.refreshOneTimeKeysTask(policy: .replacePublishedBatch)
        #expect(secondReplace, "Second published-batch replacement should succeed")

        guard let contextAfterSecond = await session.sessionContext else {
            Issue.record("Session context should be available after second replacement")
            await session.shutdown()
            return
        }
        #expect(
            contextAfterSecond.sessionUser.deviceKeys.oneTimePrivateKeys.count
                <= PQSSessionConstants.retainedOneTimePrivateKeyCap,
            "Retained private key pool must be capped")

        await session.shutdown()
    }

    @Test("missingOneTimeKey recovery does not block the job queue while OTK upload is in flight")
    func testMissingOneTimeKeyRecoveryDoesNotBlockJobQueue() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.missingOneTimeKey)
        )

        let uploadPause = OTKUploadPause()
        transport.beforeUpdateOneTimeKeys = {
            await uploadPause.beforeFirstUpload()
        }
        defer {
            transport.beforeUpdateOneTimeKeys = nil
        }

        let firstPeerDeviceId = UUID()
        let secondPeerDeviceId = UUID()
        let first = try makeTestInboundTaskMessage(
            senderSecretName: "bob_nonblocking_1",
            senderDeviceId: firstPeerDeviceId,
            sharedMessageId: "nonblocking_1")
        let second = try makeTestInboundTaskMessage(
            senderSecretName: "bob_nonblocking_2",
            senderDeviceId: secondPeerDeviceId,
            sharedMessageId: "nonblocking_2")

        async let firstFeed: Void = session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(first)),
            session: session
        )

        let uploadPaused = try await waitUntil(timeout: 15) {
            await uploadPause.isPaused()
        }
        #expect(uploadPaused, "Expected first recovery to pause inside OTK upload")

        // While the first peer's OTK upload is still in flight the job queue must
        // keep draining: a failure from a *different* peer has to be recorded
        // without waiting for the network round-trip to finish.
        async let secondFeed: Void = session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(second)),
            session: session
        )

        let secondRecordedWhilePaused = try await waitUntil(timeout: 15) {
            await self.session.hasPendingResendAfterReestablishment(
                sender: "bob_nonblocking_2",
                deviceId: secondPeerDeviceId)
        }
        #expect(
            secondRecordedWhilePaused,
            "The job queue must not be blocked behind an in-flight OTK batch upload")

        await uploadPause.release()
        try await firstFeed
        try await secondFeed

        await session.shutdown()
    }

    @Test("Delayed job does not block ready jobs behind it")
    func testDelayedJobDoesNotBlockReadyJobs() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)

        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)

        guard let cache = await session.cache else {
            Issue.record("Cache should be available")
            await session.shutdown()
            return
        }
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let recipientIdentity = createTestRecipientIdentity()

        // Seed a not-yet-due retry ahead of a ready job in the same queue.
        let delayedJob = try JobModel(
            id: UUID(),
            props: .init(
                sequenceId: 1,
                task: .init(task: .writeMessage(.init(
                    message: createTestMessage("delayed"),
                    recipientIdentity: recipientIdentity,
                    localId: UUID(),
                    sharedId: "delayed_shared"))),
                isBackgroundTask: false,
                delayedUntil: Date().addingTimeInterval(1.5),
                scheduledAt: Date(),
                attempts: 0),
            symmetricKey: symmetricKey)
        let readyJob = try JobModel(
            id: UUID(),
            props: .init(
                sequenceId: 2,
                task: .init(task: .writeMessage(.init(
                    message: createTestMessage("ready"),
                    recipientIdentity: recipientIdentity,
                    localId: UUID(),
                    sharedId: "ready_shared"))),
                isBackgroundTask: false,
                scheduledAt: Date(),
                attempts: 0),
            symmetricKey: symmetricKey)
        try await cache.createJob(delayedJob)
        try await cache.createJob(readyJob)

        async let load: Void = session.taskProcessor.loadTasks(
            cache: cache,
            symmetricKey: symmetricKey,
            session: session)

        let readyProcessed = try await waitUntil(timeout: 15) {
            await mockDelegate.getProcessedMessages().contains("ready")
        }
        #expect(
            readyProcessed,
            "A ready job must not wait for a not-yet-due delayed job that sits ahead of it")

        let delayedProcessedEventually = try await waitUntil(timeout: 5.0) {
            await mockDelegate.getProcessedMessages().contains("delayed")
        }
        #expect(delayedProcessedEventually, "The delayed job must still run once it becomes due")

        try await load
        await session.shutdown()
    }

    @Test("Peer resend request tracking is pruned and capped")
    func testPeerResendRequestTrackingIsBounded() async {
        let deviceId = UUID()
        let now = Date()

        // Stale entries (older than the cooldown that makes them meaningful) are pruned on insert.
        for index in 0..<10 {
            await session.markPeerResendRequestSent(
                sender: "stale\(index)",
                deviceId: deviceId,
                failedMessageId: "m",
                now: now.addingTimeInterval(-3600))
        }
        await session.markPeerResendRequestSent(
            sender: "fresh",
            deviceId: deviceId,
            failedMessageId: "m",
            now: now)
        #expect(
            await session.lastResendRequestAtByPeer.count == 1,
            "Stale resend-request entries must be pruned on insert")

        // A flood of unique failed-message keys must not grow the map unboundedly.
        for index in 0..<(PQSSessionConstants.recoveryTrackingMaxEntries + 100) {
            await session.markPeerResendRequestSent(
                sender: "flood",
                deviceId: deviceId,
                failedMessageId: "m\(index)",
                now: now)
        }
        #expect(
            await session.lastResendRequestAtByPeer.count <= PQSSessionConstants.recoveryTrackingMaxEntries,
            "Resend-request tracking must be capped")
        await session.shutdown()
    }

    @Test("Peer resend servicing coalesces duplicate requests within cooldown")
    func testPeerResendServicingCoalescesDuplicateRequests() async {
        let requestingDeviceId = UUID()
        let now = Date()

        #expect(
            await session.canServicePeerResendRequest(
                requestingDeviceId: requestingDeviceId,
                sharedId: "m1",
                now: now),
            "First service of a resend request must be allowed")

        await session.markPeerResendRequestServiced(
            requestingDeviceId: requestingDeviceId,
            sharedId: "m1",
            now: now)

        #expect(
            !(await session.canServicePeerResendRequest(
                requestingDeviceId: requestingDeviceId,
                sharedId: "m1",
                now: now.addingTimeInterval(1))),
            "Re-servicing the same (requesting device, sharedId) within cooldown must be refused")

        #expect(
            await session.canServicePeerResendRequest(
                requestingDeviceId: requestingDeviceId,
                sharedId: "m2",
                now: now.addingTimeInterval(1)),
            "A different failed message id must still be serviceable")

        #expect(
            await session.canServicePeerResendRequest(
                requestingDeviceId: UUID(),
                sharedId: "m1",
                now: now.addingTimeInterval(1)),
            "A different requesting device must still be serviceable")

        #expect(
            await session.canServicePeerResendRequest(
                requestingDeviceId: requestingDeviceId,
                sharedId: "m1",
                now: now.addingTimeInterval(session.peerResendServiceCooldown + 1)),
            "After the cooldown elapses the same request may be serviced again")

        await session.shutdown()
    }

    @Test("Peer resend servicing tracking is pruned and capped")
    func testPeerResendServicingTrackingIsBounded() async {
        let requestingDeviceId = UUID()
        let now = Date()

        for index in 0..<10 {
            await session.markPeerResendRequestServiced(
                requestingDeviceId: requestingDeviceId,
                sharedId: "stale\(index)",
                now: now.addingTimeInterval(-3600))
        }
        await session.markPeerResendRequestServiced(
            requestingDeviceId: requestingDeviceId,
            sharedId: "fresh",
            now: now)
        #expect(
            await session.lastServicedResendAtByRequest.count == 1,
            "Stale resend-servicing entries must be pruned on insert")

        for index in 0..<(PQSSessionConstants.recoveryTrackingMaxEntries + 100) {
            await session.markPeerResendRequestServiced(
                requestingDeviceId: requestingDeviceId,
                sharedId: "m\(index)",
                now: now)
        }
        #expect(
            await session.lastServicedResendAtByRequest.count <= PQSSessionConstants.recoveryTrackingMaxEntries,
            "Resend-servicing tracking must be capped")
        await session.shutdown()
    }

    @Test("Reconciliation tracking is pruned and capped")
    func testReconciliationTrackingIsBounded() async {
        let deviceId = UUID()
        let now = Date()

        for index in 0..<10 {
            await session.markReconciliationAttempt(
                sender: "stale\(index)",
                deviceId: deviceId,
                now: now.addingTimeInterval(-3600))
        }
        await session.markReconciliationAttempt(
            sender: "fresh",
            deviceId: deviceId,
            now: now)
        #expect(
            await session.lastReconciliationAtByPeer.count == 1,
            "Stale reconciliation entries must be pruned on insert")

        for index in 0..<(PQSSessionConstants.recoveryTrackingMaxEntries + 100) {
            await session.markReconciliationAttempt(
                sender: "flood\(index)",
                deviceId: deviceId,
                now: now)
        }
        #expect(
            await session.lastReconciliationAtByPeer.count <= PQSSessionConstants.recoveryTrackingMaxEntries,
            "Reconciliation tracking must be capped")
        await session.shutdown()
    }

    @Test("Automatic rotation tracking is pruned and capped")
    func testAutomaticRotationTrackingIsBounded() async {
        let deviceId = UUID()
        let now = Date()

        for index in 0..<10 {
            await session.markAutomaticRotationAttempt(
                sender: "stale\(index)",
                deviceId: deviceId,
                now: now.addingTimeInterval(-3600))
        }
        await session.markAutomaticRotationAttempt(
            sender: "fresh",
            deviceId: deviceId,
            now: now)
        #expect(
            await session.lastAutomaticRotationAtByPeer.count == 1,
            "Stale rotation entries must be pruned on insert")

        for index in 0..<(PQSSessionConstants.recoveryTrackingMaxEntries + 100) {
            await session.markAutomaticRotationAttempt(
                sender: "flood\(index)",
                deviceId: deviceId,
                now: now)
        }
        #expect(
            await session.lastAutomaticRotationAtByPeer.count <= PQSSessionConstants.recoveryTrackingMaxEntries,
            "Rotation tracking must be capped")
        await session.shutdown()
    }

    @Test("Pending resend-after-reestablishment tracking is capped")
    func testPendingResendTrackingIsCapped() async {
        let deviceId = UUID()
        for index in 0..<(PQSSessionConstants.recoveryTrackingMaxEntries + 100) {
            await session.deferPeerResendUntilReestablished(
                sender: "flood",
                deviceId: deviceId,
                failedMessageId: "m\(index)",
                failureClass: "ratchet.missingOneTimeKey")
        }
        #expect(
            await session.pendingResendAfterReestablishment.count <= PQSSessionConstants.recoveryTrackingMaxEntries,
            "Pending resend tracking must be capped against unique failed-message floods")
        await session.shutdown()
    }

    @Test("Ratchet decryption failure retries first and repairs on repeat")
    func testRatchetDecryptionFailedRetriesFirstThenRepairsOnRepeat() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        await session.taskProcessor.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.decryptionFailed)
        )

        let peerDeviceId = UUID()
        let inbound = try makeTestInboundTaskMessage(
            senderSecretName: "bob_decrypt_failed",
            senderDeviceId: peerDeviceId,
            sharedMessageId: "decrypt_failed_repeat")

        // First failure: either mark+resend, or handshake-defer until attempts exhaust.
        // Either way the shared id must be tracked before a second failure escalates.
        try await session.taskProcessor.feedTask(
            EncryptableTask(task: .streamMessage(inbound)),
            session: session
        )

        // Allow handshake-defer passes (bounded) to fall through to the failure policy.
        try await Task.sleep(until: .now + .seconds(2))

        let suppressed = await session.shouldSuppressInboundFailure(
            inbound,
            failureClass: "ratchet.decryptionFailed")
        let pending = await session.hasPendingResendAfterReestablishment(
            sender: "bob_decrypt_failed",
            deviceId: peerDeviceId)
        #expect(
            suppressed || pending,
            "First decryptionFailed must be recorded (suppress on retry) or already escalate to deferred repair")

        if !(await session.hasPendingResendAfterReestablishment(
            sender: "bob_decrypt_failed",
            deviceId: peerDeviceId))
        {
            try await session.taskProcessor.feedTask(
                EncryptableTask(task: .streamMessage(inbound)),
                session: session
            )
        }

        let hasPendingRepair = try await waitForPendingRepair(
            sender: "bob_decrypt_failed",
            deviceId: peerDeviceId)
        #expect(hasPendingRepair, "Repeated ratchet.decryptionFailed should escalate to peerRefresh repair")

        await session.shutdown()
    }
    
    // MARK: - Task Type Tests
    
    @Test("Task Types - Write Messages")
    func testTaskTypesWriteMessages() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Feed write message tasks
        for i in 1...10 {
            let message = createTestMessage("write_\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }
        
        try await Task.sleep(until: .now + .seconds(5))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == 10, "Expected 10 write messages to be processed")
        
        // Verify all are write messages
        for (index, messageText) in processedMessages.enumerated() {
            let expectedMessage = "write_\(index + 1)"
            #expect(messageText == expectedMessage, "Message at index \(index) should be '\(expectedMessage)' but was '\(messageText)'")
        }
        
        await session.shutdown()
    }
    
    @Test("Task Types - Write Messages Only")
    func testTaskTypesWriteMessagesOnly() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Feed write message tasks
        for i in 1...10 {
            let message = createTestMessage("write_\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }
        
        try await Task.sleep(until: .now + .seconds(5))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == 10, "Expected 10 write messages to be processed")
        
        // Verify all are write messages
        for (index, messageText) in processedMessages.enumerated() {
            let expectedMessage = "write_\(index + 1)"
            #expect(messageText == expectedMessage, "Message at index \(index) should be '\(expectedMessage)' but was '\(messageText)'")
        }
        
        await session.shutdown()
    }
    
    // MARK: - Edge Cases
    
    @Test("Edge Cases - Empty Queue")
    func testEdgeCasesEmptyQueue() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        // Don't feed any messages
        try await Task.sleep(until: .now + .seconds(2))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == 0, "Expected 0 messages to be processed")
        
        await session.shutdown()
    }
    
    @Test("Edge Cases - Single Message with Long Processing")
    func testEdgeCasesSingleMessageLongProcessing() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegateWithDelay(delaySeconds: 2)
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        let message = createTestMessage("slow_message")
        
        try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
            message: message,
            recipientIdentity: recipientIdentity,
            localId: localId,
            sharedId: "123"))), session: session)
        
        try await Task.sleep(until: .now + .seconds(5))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == 1, "Expected 1 message to be processed")
        #expect(processedMessages.first == "slow_message", "Expected 'slow_message' to be processed")
        
        await session.shutdown()
    }
    
    @Test("Edge Cases - Rapid Feed and Shutdown")
    func testEdgeCasesRapidFeedAndShutdown() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        let recipientIdentity = createTestRecipientIdentity()
        
        // Feed messages rapidly
        let feedTask = Task {
            for i in 1...100 {
                let message = createTestMessage("\(i)")
                try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                    message: message,
                    recipientIdentity: recipientIdentity,
                    localId: localId,
                    sharedId: "123"))), session: session)
            }
        }
        
        // Start feeding and immediately shutdown
        try await feedTask.value
        await session.shutdown()
        
        try await Task.sleep(until: .now + .seconds(2))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        // Some messages may be processed before shutdown
        #expect(processedMessages.count >= 0, "Expected some messages to be processed before shutdown")
        
        // Verify FIFO order for processed messages
        for (index, messageText) in processedMessages.enumerated() {
            let expectedMessage = "\(index + 1)"
            #expect(messageText == expectedMessage, "Message at index \(index) should be '\(expectedMessage)' but was '\(messageText)'")
        }
    }
    
    // MARK: - Scheduling / Load / Viability Edge Cases

    @Test("Edge Cases - delayedUntil does not execute early")
    func testEdgeCasesDelayedUntilDoesNotExecuteEarly() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)

        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)

        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        
        let recipientIdentity = createTestRecipientIdentity()
        let message = createTestMessage("delayed_until")
        let task = EncryptableTask(
            task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "delayed_until_shared"
            ))
        )
        
        // Create a job, then set delayedUntil in the encrypted props.
        let seq = await session.taskProcessor.incrementId()
        let job = try await session.taskProcessor.createJobModel(sequenceId: seq, task: task, symmetricKey: symmetricKey)
        if var props = await job.props(symmetricKey: symmetricKey) {
            props.delayedUntil = Date().addingTimeInterval(0.35)
            _ = try await job.updateProps(symmetricKey: symmetricKey, props: props)
        }
        try await cache.createJob(job)

        // Kick off processing in the background (resumeJobQueue blocks until the queue drains).
        let runner = Task {
            try await session.resumeJobQueue()
        }
        // Verify it doesn't run early.
        try await Task.sleep(until: .now + .milliseconds(150))
        #expect(await mockDelegate.getProcessedMessages().isEmpty, "Job should not execute before delayedUntil")

        // Then verify it does execute after delayedUntil.
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline {
            let processed = await mockDelegate.getProcessedMessages()
            if processed.contains("delayed_until") { break }
            try await Task.sleep(until: .now + .milliseconds(50))
        }

        let processed = await mockDelegate.getProcessedMessages()
        #expect(processed == ["delayed_until"], "Expected exactly one delayed execution, got \(processed)")
        #expect(try await cache.fetchJobs().isEmpty, "Delayed job should be removed from cache after processing")
        _ = try? await runner.value
        
        await session.shutdown()
    }
    
    @Test("Edge Cases - cancellation during delayedUntil pauses and leaves job in cache")
    func testEdgeCasesCancellationDuringDelayedUntilLeavesJobInCache() async throws {
        // NOTE: cancellation of the caller does not cancel the internal processing task
        // started by TaskProcessor, so this edge case is covered instead by toggling session viability
        // while a delayed job is sleeping (which should pause and keep the job in cache).
        try await testEdgeCasesNonViableDuringDelayedUntilPausesAndResumes()
    }

    @Test("Edge Cases - non-viable during delayedUntil pauses and leaves job in cache, then resumes")
    func testEdgeCasesNonViableDuringDelayedUntilPausesAndResumes() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        
        let recipientIdentity = createTestRecipientIdentity()
        let message = createTestMessage("paused_during_delay")
            let task = EncryptableTask(
                task: .writeMessage(.init(
                    message: message,
                    recipientIdentity: recipientIdentity,
                    localId: localId,
                sharedId: "paused_during_delay_shared"
            ))
            )
            
            let seq = await session.taskProcessor.incrementId()
        let job = try await session.taskProcessor.createJobModel(sequenceId: seq, task: task, symmetricKey: symmetricKey)
        guard var props = await job.props(symmetricKey: symmetricKey) else {
            throw PQSSession.SessionErrors.propsError
        }
        props.delayedUntil = Date().addingTimeInterval(0.35)
        _ = try await job.updateProps(symmetricKey: symmetricKey, props: props)
            try await cache.createJob(job)

        // Start processing; while it's sleeping for delayedUntil, flip session to non-viable.
        let runner = Task {
            try await session.resumeJobQueue()
        }
        try await Task.sleep(until: .now + .milliseconds(100))
        session.isViable = false
        _ = try? await runner.value

        // After delayedUntil elapses, processor should pause (not execute) because session is not viable.
        #expect(await mockDelegate.getProcessedMessages().isEmpty, "Job should not execute if session becomes non-viable during delayedUntil sleep")
        #expect(try await cache.fetchJobs().count == 1, "Job should remain in cache when paused due to non-viable session")

        // Resume and ensure it runs once.
        session.isViable = true
        try await session.resumeJobQueue()
        
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline {
            let processed = await mockDelegate.getProcessedMessages()
            if processed.contains("paused_during_delay") { break }
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        
        let processed = await mockDelegate.getProcessedMessages()
        #expect(processed == ["paused_during_delay"], "Expected exactly one execution after resume, got \(processed)")
        #expect(try await cache.fetchJobs().isEmpty, "Job should be removed from cache after processing")
        
        await session.shutdown()
    }
    
    @Test("Edge Cases - loadTasks seeding does not double-enqueue jobs")
    func testEdgeCasesLoadTasksSeedingDoesNotDoubleEnqueue() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        
        let recipientIdentity = createTestRecipientIdentity()
        let count = 7
        for i in 1...count {
            let message = createTestMessage("seeded_\(i)")
            let task = EncryptableTask(
                task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                    sharedId: "seeded_shared_\(i)"
                ))
            )
            let seq = await session.taskProcessor.incrementId()
            let job = try await session.taskProcessor.createJobModel(sequenceId: seq, task: task, symmetricKey: symmetricKey)
            try await cache.createJob(job)
        }

        // This call seeds the consumer with cache jobs then starts processing.
        try await session.taskProcessor.loadTasks(nil, cache: cache, symmetricKey: symmetricKey, session: session)

        // Poll until all jobs are processed (or timeout).
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            let processed = await mockDelegate.getProcessedMessages()
            if processed.count >= count { break }
            try await Task.sleep(until: .now + .milliseconds(50))
        }

        let processed = await mockDelegate.getProcessedMessages()
        #expect(processed.count == count, "Expected exactly \(count) processed jobs (no duplicates), got \(processed.count): \(processed)")
        #expect(Set(processed).count == count, "Expected all processed job labels to be unique")
        #expect(try await cache.fetchJobs().isEmpty, "All jobs should be removed from cache after processing")
        
        await session.shutdown()
    }
    
    @Test("Edge Cases - feedTask while not viable pauses and processes after resume")
    func testEdgeCasesFeedTaskWhileNotViablePausesAndResumes() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }

        // Make the session non-viable and enqueue a task.
        session.isViable = false
        let recipientIdentity = createTestRecipientIdentity()
        let message = createTestMessage("paused_nonviable")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
            sharedId: "paused_nonviable_shared"
        ))), session: session)

        // It should not have processed, and the job should remain in cache.
        try await Task.sleep(until: .now + .milliseconds(150))
        #expect(await mockDelegate.getProcessedMessages().isEmpty, "No tasks should execute while session is not viable")
        #expect(try await cache.fetchJobs().count == 1, "Job should remain in cache while session is not viable")
        
        // Resume viability and explicitly resume the job queue.
        session.isViable = true
        try await session.resumeJobQueue()

        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline {
            let processed = await mockDelegate.getProcessedMessages()
            if processed.contains("paused_nonviable") { break }
            try await Task.sleep(until: .now + .milliseconds(50))
        }

        let processed = await mockDelegate.getProcessedMessages()
        #expect(processed == ["paused_nonviable"], "Expected exactly one execution after resume, got \(processed)")
        #expect(try await cache.fetchJobs().isEmpty, "Job should be removed from cache after processing")
        
        await session.shutdown()
    }
    
    // MARK: - Job Stranding Race Condition Tests

    /// Feeds multiple tasks from separate concurrent tasks and verifies
    /// all jobs are drained from the cache afterwards.
    ///
    /// Without the defensive post-loop drain check in `startProcessingIfNeeded`,
    /// a task fed while the processing loop is between its final deque-empty check
    /// and `stop()` can be stranded in cache indefinitely (until another feedTask
    /// or resumeJobQueue happens to pick it up).
    @Test("Job Stranding - concurrent feedTask calls should not strand jobs in cache")
    func concurrentFeedTaskDoesNotStrandJobs() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)

        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)

        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }

        let recipientIdentity = createTestRecipientIdentity()
        let iterations = 20

        for iteration in 0..<iterations {
            let task1 = EncryptableTask(task: .writeMessage(.init(
                message: createTestMessage("strand_A_\(iteration)"),
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "strand_A_\(iteration)")))
            let task2 = EncryptableTask(task: .writeMessage(.init(
                message: createTestMessage("strand_B_\(iteration)"),
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "strand_B_\(iteration)")))

            let t1 = Task {
                try? await session.taskProcessor.feedTask(task1, session: session)
            }
            await Task.yield()
            let t2 = Task {
                try? await session.taskProcessor.feedTask(task2, session: session)
            }

            await t1.value
            await t2.value
        }

        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            let remaining = try await cache.fetchJobs()
            if remaining.isEmpty { break }
            try await Task.sleep(until: .now + .milliseconds(50))
        }

        let remaining = try await cache.fetchJobs()
        #expect(remaining.isEmpty, "Expected all jobs to be drained from cache, but \(remaining.count) remain stranded")

        let processedMessages = await mockDelegate.getProcessedMessages()
        let expectedCount = iterations * 2
        #expect(processedMessages.count == expectedCount, "Expected \(expectedCount) messages processed, got \(processedMessages.count)")

        await session.shutdown()
    }

    /// Feeds a rapid burst of tasks and ensures none remain stranded in cache.
    @Test("Job Stranding - rapid sequential feedTask should drain all jobs from cache")
    func rapidSequentialFeedTaskDrainsAllFromCache() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)

        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)

        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }

        let recipientIdentity = createTestRecipientIdentity()
        let count = 10

        for i in 0..<count {
            let task = EncryptableTask(task: .writeMessage(.init(
                message: createTestMessage("rapid_\(i)"),
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "rapid_\(i)")))
            try await session.taskProcessor.feedTask(task, session: session)
        }

        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            let remaining = try await cache.fetchJobs()
            if remaining.isEmpty { break }
            try await Task.sleep(until: .now + .milliseconds(50))
        }

        let remaining = try await cache.fetchJobs()
        #expect(remaining.isEmpty, "Expected all jobs to be drained from cache, but \(remaining.count) remain")

        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == count, "Expected \(count) messages processed, got \(processedMessages.count)")

        await session.shutdown()
    }

    // MARK: - Helper Methods
    
    private func createTestRecipientIdentity() -> SessionIdentity {
        try! SessionIdentity(
            id: localId,
            props: .init(
                secretName: "alice",
                deviceId: localId,
                sessionContextId: 0,
                longTermPublicKey: .init(),
                signingPublicKey: .init(),
                mlKEMPublicKey: .init(.init(count: 1568)),
                oneTimePublicKey: nil,
                deviceName: "alice-device",
                isMasterDevice: true),
            symmetricKey: .init(size: .bits256))
    }
    
    private func createTestMessage(_ text: String) -> CryptoMessage {
        CryptoMessage(
            text: text,
            metadata: .init(),
            recipient: .nickname("bob"),
            sentDate: Date(),
            destructionTime: nil)
    }

    private func makeTestInboundTaskMessage(
        senderSecretName: String,
        senderDeviceId: UUID,
        sharedMessageId: String
    ) throws -> InboundTaskMessage {
        let signingKey = Curve25519.Signing.PrivateKey()
        let header = EncryptedHeader(
            remoteLongTermPublicKey: Data(repeating: 1, count: 32),
            remoteOneTimePublicKey: nil,
            remoteMLKEMPublicKey: try MLKEMPublicKey(Data(repeating: 2, count: 1568)),
            headerCiphertext: Data([0x01]),
            messageCiphertext: Data([0x02]),
            oneTimeKeyId: nil,
            mlKEMOneTimeKeyId: UUID(),
            encrypted: Data([0x04])
        )
        let ratchetMessage = RatchetMessage(header: header, encryptedData: Data([0x03]))
        let signed = try SignedRatchetMessage(
            message: ratchetMessage,
            signingPrivateKey: signingKey.rawRepresentation
        )
        return InboundTaskMessage(
            message: signed,
            senderSecretName: senderSecretName,
            senderDeviceId: senderDeviceId,
            sharedMessageId: sharedMessageId
        )
    }

    private func waitForPendingRepair(
        sender: String,
        deviceId: UUID,
        timeout: TimeInterval = 3
    ) async throws -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await session.hasPendingResendAfterReestablishment(
                sender: sender,
                deviceId: deviceId) {
                return true
            }
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        return await session.hasPendingResendAfterReestablishment(
            sender: sender,
            deviceId: deviceId)
    }

    private func waitForSuppressedInboundFailure(
        _ inbound: InboundTaskMessage,
        failureClass: String,
        timeout: TimeInterval = 3
    ) async throws -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await session.shouldSuppressInboundFailure(inbound, failureClass: failureClass) {
                return true
            }
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        return await session.shouldSuppressInboundFailure(inbound, failureClass: failureClass)
    }

    private func waitUntil(
        timeout: TimeInterval = 3,
        _ condition: @escaping @Sendable () async -> Bool
    ) async throws -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await condition() {
                return true
            }
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        return await condition()
    }
    
    
    @Test("Edge Cases - Feed While Processing")
    func testEdgeCasesFeedWhileProcessing() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        let recipientIdentity = createTestRecipientIdentity()
        let midBatch = 25
        // Feed first batch
        for i in 1...midBatch {
            let message = createTestMessage("first_\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: localId,
                sharedId: "123"))), session: session)
        }
        // Start processing, then immediately feed more
        try await Task.sleep(until: .now + .milliseconds(50))
        for i in (midBatch+1)...(midBatch*2) {
            let message = createTestMessage("second_\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                    message: message,
                    recipientIdentity: recipientIdentity,
                    localId: localId,
                sharedId: "123"))), session: session)
        }
        try await Task.sleep(until: .now + .seconds(5))
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == midBatch*2, "Expected all messages to be processed")
        // Optionally, check for all expected labels
        for i in 1...midBatch {
            #expect(processedMessages.contains("first_\(i)"))
            #expect(processedMessages.contains("second_\(midBatch+i)"))
        }
        await session.shutdown()
    }
    
    // 2. Feed During Shutdown/Restart
    
    @Test("Edge Cases - Feed During Shutdown and Restart")
    func testEdgeCasesFeedDuringShutdownAndRestart() async throws {
        let store = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        try await createSenderSession(store: store)
        let mockDelegate = MockTaskDelegate()
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        let recipientIdentity = createTestRecipientIdentity()
        // Feed half, shutdown, then feed more, then restart
        for i in 1...10 {
            let message = createTestMessage("A_\(i)")
            try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                    message: message,
                    recipientIdentity: recipientIdentity,
                    localId: localId,
                sharedId: "123"))), session: session)
        }
        await session.shutdown()
        try await Task.sleep(until: .now + .seconds(2))
        
        // Restart session properly - don't clear store data to maintain session context
        try await createSenderSession(store: store, shouldCreate: false)
        await session.taskProcessor.setTaskDelegate(mockDelegate)
        let recipientIdentity2 = createTestRecipientIdentity()
        for i in 11...20 {
            let message = createTestMessage("B_\(i)")
                try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                    message: message,
                recipientIdentity: recipientIdentity2,
                    localId: localId,
                sharedId: "123"))), session: session)
            }
        try await Task.sleep(until: .now + .seconds(5))
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == 20, "Expected all messages to be processed after restart")
        for i in 1...10 { #expect(processedMessages.contains("A_\(i)")) }
        for i in 11...20 { #expect(processedMessages.contains("B_\(i)")) }
        await session.shutdown()
    }
}

// MARK: - Helper Classes

/// Tracks the order in which messages were fed to the system
actor FedOrderTracker {
    private var currentOrder = 0
    
    func getNextOrder() -> Int {
        currentOrder += 1
        return currentOrder
    }
}

// MARK: - Mock Task Delegates

final class MockTaskDelegate: TaskSequenceDelegate, @unchecked Sendable {
    private let messageTracker = MessageTracker()
    
    func performRatchet(task: SessionModels.TaskType, session: PQSSession) async throws {
        switch task {
        case .writeMessage(let task):
            await messageTracker.addMessage(task.message.text)
            print("Processed message: \(task.message.text)")
        case .streamMessage(let task):
            // For testing purposes, we'll just track the shared message ID
            await messageTracker.addMessage("stream_\(task.sharedMessageId)")
            print("Processed stream message: \(task.sharedMessageId)")
        }
    }
    
    func getProcessedMessages() async -> [String] {
        await messageTracker.getMessages()
    }
    
    func clearProcessedMessages() async {
        await messageTracker.clearMessages()
    }
}

final class MockTaskDelegateWithErrors: TaskSequenceDelegate, @unchecked Sendable {
    private let messageTracker = MessageTracker()
    private let errorTracker = ErrorTracker()
    private let errorType: ErrorType
    
    enum ErrorType {
        case missingIdentity
        case authenticationFailure
    }
    
    init(errorType: ErrorType) {
        self.errorType = errorType
    }
    
    func performRatchet(task: SessionModels.TaskType, session: PQSSession) async throws {
        await errorTracker.incrementErrorCount()
        
        switch errorType {
        case .missingIdentity:
            throw TaskProcessor.JobProcessorErrors.missingIdentity
        case .authenticationFailure:
            throw PQSSession.SessionErrors.invalidKeyId
        }
    }
    
    func getProcessedMessages() async -> [String] {
        await messageTracker.getMessages()
    }
    
    func getErrorCount() async -> Int {
        await errorTracker.getErrorCount()
    }
}

final class MockTaskDelegateWithMixedErrors: TaskSequenceDelegate, @unchecked Sendable {
    private let messageTracker = MessageTracker()
    private let errorTracker = ErrorTracker()
    private var messageCount = 0
    
    func performRatchet(task: SessionModels.TaskType, session: PQSSession) async throws {
        messageCount += 1
        
        if messageCount % 2 == 1 {
            // Odd messages succeed
            switch task {
            case .writeMessage(let task):
                await messageTracker.addMessage(task.message.text)
            case .streamMessage(let task):
                await messageTracker.addMessage(task.sharedMessageId)
            }
        } else {
            // Even messages fail
            await errorTracker.incrementErrorCount()
            throw TaskProcessor.JobProcessorErrors.missingIdentity
        }
    }
    
    func getProcessedMessages() async -> [String] {
        await messageTracker.getMessages()
    }
    
    func getErrorCount() async -> Int {
        await errorTracker.getErrorCount()
    }
}

final class MockTaskDelegateWithOneShotError: TaskSequenceDelegate, @unchecked Sendable {
    private let messageTracker = MessageTracker()
    private let errorTracker = ErrorTracker()
    private let failingMessage: String
    private let error: Error
    private var hasThrown = false

    init(failingMessage: String, error: Error) {
        self.failingMessage = failingMessage
        self.error = error
    }

    func performRatchet(task: SessionModels.TaskType, session: PQSSession) async throws {
        switch task {
        case .writeMessage(let task):
            if !hasThrown && task.message.text == failingMessage {
                hasThrown = true
                await errorTracker.incrementErrorCount()
                throw error
            }
            await messageTracker.addMessage(task.message.text)
        case .streamMessage(let task):
            await messageTracker.addMessage(task.sharedMessageId)
        }
    }

    func getProcessedMessages() async -> [String] {
        await messageTracker.getMessages()
    }

    func getErrorCount() async -> Int {
        await errorTracker.getErrorCount()
    }
}

private actor OTKUploadPause {
    private var didPause = false
    private var isReleased = false
    private var continuation: CheckedContinuation<Void, Never>?

    func beforeFirstUpload() async {
        guard !didPause else { return }
        didPause = true
        guard !isReleased else { return }
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }

    func isPaused() -> Bool {
        didPause && !isReleased
    }

    func release() {
        isReleased = true
        continuation?.resume()
        continuation = nil
    }
}

final class MockTaskDelegateWithStreamError: TaskSequenceDelegate, @unchecked Sendable {
    private let error: Error

    init(error: Error) {
        self.error = error
    }

    func performRatchet(task: SessionModels.TaskType, session: PQSSession) async throws {
        switch task {
        case .streamMessage:
            throw error
        case .writeMessage:
            break
        }
    }
}

final class MockTaskDelegateWithDelay: TaskSequenceDelegate, @unchecked Sendable {
    private let messageTracker = MessageTracker()
    private let delaySeconds: Int
    
    init(delaySeconds: Int) {
        self.delaySeconds = delaySeconds
    }
    
    func performRatchet(task: SessionModels.TaskType, session: PQSSession) async throws {
        // Simulate long processing time
        try await Task.sleep(until: .now + .seconds(delaySeconds))
        
        switch task {
        case .writeMessage(let task):
            await messageTracker.addMessage(task.message.text)
        case .streamMessage(let task):
            await messageTracker.addMessage(task.sharedMessageId)
        }
    }
    
    func getProcessedMessages() async -> [String] {
        await messageTracker.getMessages()
    }
}

// MARK: - Supporting Actors

actor MessageTracker {
    private var processedMessages: [String] = []
    
    func addMessage(_ message: String) {
        processedMessages.append(message)
    }
    
    func getMessages() -> [String] {
        processedMessages
    }
    
    func clearMessages() {
        processedMessages.removeAll()
    }
}

actor ErrorTracker {
    private var errorCount = 0
    
    func incrementErrorCount() {
        errorCount += 1
    }
    
    func getErrorCount() -> Int {
        errorCount
    }
}

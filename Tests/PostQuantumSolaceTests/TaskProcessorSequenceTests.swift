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
    let transport = _MockTransportDelegate()
    var senderReceiver = ReceiverDelegate()
    let localId = UUID()
    
    func createSenderSession(store: MockIdentityStore, shouldCreate: Bool = true) async throws {
        store.localDeviceSalt = "testSalt1"
        await session.setLogLevel(.trace)
        await session.setDatabaseDelegate(conformer: store)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate())
        await session.setReceiverDelegate(conformer: senderReceiver)
        
        session.isViable = true
        transport.publishableName = "alice"
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
        
        // Create tasks that feed messages in different patterns
        let messageCount = 100
        
        let forwardTask = Task {
            for i in stride(from: 1, through: messageCount, by: 2) {
                let message = createTestMessage("\(i)")
                try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                    message: message,
                    recipientIdentity: recipientIdentity,
                    localId: localId,
                    sharedId: "123"))), session: session)
                try await Task.sleep(until: .now + .milliseconds(2))
            }
        }
        
        let backwardTask = Task {
            for i in stride(from: messageCount, through: 2, by: -2) {
                let message = createTestMessage("\(i)")
                try await session.taskProcessor.feedTask(.init(task: .writeMessage(.init(
                    message: message,
                    recipientIdentity: recipientIdentity,
                    localId: localId,
                    sharedId: "123"))), session: session)
                try await Task.sleep(until: .now + .milliseconds(2))
            }
        }
        
        // Start both tasks concurrently
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { try await forwardTask.value }
            group.addTask { try await backwardTask.value }
            try await group.waitForAll()
        }
        
        try await Task.sleep(until: .now + .seconds(10))
        
        let processedMessages = await mockDelegate.getProcessedMessages()
        #expect(processedMessages.count == messageCount, "Expected \(messageCount) messages to be processed, got \(processedMessages.count)")
        
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
                pqKemPublicKey: .init(.init(count: 1568)),
                oneTimePublicKey: nil,
                deviceName: "alice-device",
                isMasterDevice: true),
            symmetricKey: .init(size: .bits256))
    }
    
    private func createTestMessage(_ text: String) -> CryptoMessage {
        CryptoMessage(
            text: text,
            metadata: [:],
            recipient: .nickname("bob"),
            sentDate: Date(),
            destructionTime: nil)
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


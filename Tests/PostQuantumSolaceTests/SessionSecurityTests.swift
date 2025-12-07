//
//  SessionSecurityTests.swift
//  post-quantum-solace
//
//  Created by AI Assistant on 2025-12-07.
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
import NeedleTailCrypto
@testable import PQSSession
import SessionEvents
import SessionModels
import Testing

@Suite(.serialized)
actor SessionSecurityTests {

    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    // MARK: - Helpers

    private func setupSession(secretName: String = "alice", password: String = "123") async throws {
        let mockUserData = MockUserData(session: session)
        let cacheStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)

        await cacheStore.setLocalSalt("securitySalt")
        await session.setLogLevel(.trace)
        await session.setDatabaseDelegate(conformer: cacheStore)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: ReceiverDelegate(session: session))

        session.isViable = true
        await store.setPublishableName(secretName)

        session = try await session.createSession(
            secretName: secretName,
            appPassword: password
        ) {}

        await session.setAppPassword(password)
        session = try await session.startSession(appPassword: password)
    }

    // MARK: - Tests

    @Test("verifyAppPassword should return true only for correct password")
    func testVerifyAppPassword() async throws {
        try await setupSession()

        let correct = await session.verifyAppPassword("123")
        let incorrect = await session.verifyAppPassword("wrong-password")

        #expect(correct == true)
        #expect(incorrect == false)

        await session.shutdown()
    }

    @Test("changeAppPassword should re-encrypt context and accept only new password")
    func testChangeAppPasswordPreservesContextAndUpdatesPassword() async throws {
        try await setupSession(password: "old-password")

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized before password change")
            return
        }

        try await session.changeAppPassword("new-password")

        // Old password should fail, new password should succeed
        let oldOk = await session.verifyAppPassword("old-password")
        let newOk = await session.verifyAppPassword("new-password")

        #expect(oldOk == false)
        #expect(newOk == true)

        // Starting a new session with the new password should yield an equivalent context
        let restarted = try await session.startSession(appPassword: "new-password")
        guard let restartedContext = await restarted.sessionContext else {
            Issue.record("Restarted session context should not be nil")
            return
        }

        #expect(restartedContext.sessionUser.deviceId == originalContext.sessionUser.deviceId)
        #expect(restartedContext.activeUserConfiguration.signingPublicKey == originalContext.activeUserConfiguration.signingPublicKey)

        await session.shutdown()
    }
}


//
//  KeyRotationTests.swift
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
import Crypto

@Suite(.serialized)
actor KeyRotationTests {

    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    // MARK: - Helpers

    /// Sets up a basic session with a single device and cached context.
    private func setupRotatableSession() async throws -> (_MockTransportDelegate, MockIdentityStore) {
        let mockUserData = MockUserData(session: session)
        let cacheStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)

        await cacheStore.setLocalSalt("rotationSalt")
        await session.setLogLevel(.trace)
        await session.setDatabaseDelegate(conformer: cacheStore)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: ReceiverDelegate(session: session))

        session.isViable = true
        await store.setPublishableName(mockUserData.ssn)

        session = try await session.createSession(
            secretName: mockUserData.ssn,
            appPassword: mockUserData.sap
        ) {}

        await session.setAppPassword(mockUserData.sap)
        session = try await session.startSession(appPassword: mockUserData.sap)

        return (transport, cacheStore)
    }

    // MARK: - Tests

    @Test("rotateKeysOnPotentialCompromise should update signing, curve and MLKEM keys and publish rotation")
    func testRotateKeysOnPotentialCompromise() async throws {
        _ = try await setupRotatableSession()

        // Capture original key material
        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let originalSigningKey = originalContext.sessionUser.deviceKeys.signingPrivateKey
        let originalCurveKey = originalContext.sessionUser.deviceKeys.longTermPrivateKey

        // Act
        try await session.rotateKeysOnPotentialCompromise()

        // Assert session context has new keys
        guard let rotatedContext = await session.sessionContext else {
            Issue.record("Rotated session context should not be nil")
            return
        }

        #expect(rotatedContext.sessionUser.deviceKeys.signingPrivateKey != originalSigningKey)
        #expect(rotatedContext.sessionUser.deviceKeys.longTermPrivateKey != originalCurveKey)

        // Assert that publishRotatedKeys was called by checking store user configuration was updated
        let userConfigs = await store.userConfigurations
        #expect(userConfigs.count == 1, "Expected a single user configuration in TransportStore after rotation")

        await session.shutdown()
    }

    @Test("rotateMLKEMKeysIfNeeded should not rotate when within interval")
    func testRotateMLKEMKeysIfNeeded_noRotationWhenFresh() async throws {
        _ = try await setupRotatableSession()

        // Ensure rotateKeysDate is now so rotation is not needed
        guard await session.sessionContext != nil else {
            Issue.record("Session context should be initialized")
            return
        }

        if var context = await session.sessionContext {
            context.sessionUser.deviceKeys.rotateKeysDate = Date()
            await session.setSessionContext(context)
        }

        let rotated = try await session.rotateMLKEMKeysIfNeeded()
        #expect(rotated == false)

        await session.shutdown()
    }

    @Test("rotateMLKEMKeysIfNeeded should rotate when past interval and update rotateKeysDate")
    func testRotateMLKEMKeysIfNeeded_rotatesWhenDue() async throws {
        _ = try await setupRotatableSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let pastDate = Calendar.current.date(byAdding: .day, value: -(PQSSessionConstants.keyRotationIntervalDays + 1), to: Date())!

        if var context = await session.sessionContext {
            context.sessionUser.deviceKeys.rotateKeysDate = pastDate
            await session.setSessionContext(context)
        }

        let rotated = try await session.rotateMLKEMKeysIfNeeded()
        #expect(rotated == true)

        guard let newContext = await session.sessionContext else {
            Issue.record("New session context should not be nil")
            return
        }

        let rotatedDate = newContext.sessionUser.deviceKeys.rotateKeysDate
        #expect(rotatedDate != nil)
        if let rotatedDate {
            #expect(rotatedDate > pastDate)
        }

        await session.shutdown()
    }

    @Test("refreshOneTimeKeys with MLKEM type should replace MLKEM one-time key batch")
    func testRefreshOneTimeKeysMLKEMReplacesKeyBatch() async throws {
        _ = try await setupRotatableSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let originalIds = Set(
            originalContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.map(\.id)
        )
        #expect(!originalIds.isEmpty)

        try await session.refreshOneTimeKeys(refreshType: .mlKEM)

        guard let updatedContext = await session.sessionContext else {
            Issue.record("Updated session context should not be nil")
            return
        }

        let updatedIds = Set(
            updatedContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.map(\.id)
        )

        #expect(updatedIds.count == PQSSessionConstants.oneTimeKeyBatchSize)
        #expect(updatedIds != originalIds)

        await session.shutdown()
    }
}


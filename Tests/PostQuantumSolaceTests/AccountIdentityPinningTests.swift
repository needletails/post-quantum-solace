//
//  AccountIdentityPinningTests.swift
//  post-quantum-solace
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//

import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
@testable import PQSSession
import SessionEvents
import SessionModels
import Testing

@Suite(.serialized)
actor AccountIdentityPinningTests {

    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    private func setupSession(secretName: String = "alice", password: String = "123") async throws {
        let mockUserData = MockUserData(session: session)
        let cacheStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)

        await cacheStore.setLocalSalt("pinningSalt")
        await session.setLogLevel(.error)
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

    /// Build a structurally-valid but cryptographically-foreign `UserConfiguration`:
    /// signed by a brand new, unrelated account-level signing key.
    private func foreignConfiguration() -> UserConfiguration {
        let foreignKey = Curve25519.Signing.PrivateKey()
        return UserConfiguration(
            signingPublicKey: foreignKey.publicKey.rawRepresentation,
            signedDevices: [],
            signedOneTimePublicKeys: [],
            signedMLKEMOneTimePublicKeys: []
        )
    }

    @Test("adoptVerifiedUserConfiguration accepts the existing pinned key")
    func adoptIdempotentForSameKey() async throws {
        try await setupSession()

        guard let context = await session.sessionContext else {
            Issue.record("Expected an initialized session context")
            return
        }
        let pinnedConfig = context.activeUserConfiguration

        // Re-adopting the same configuration is a no-op for the pin and must succeed.
        try await session.adoptVerifiedUserConfiguration(pinnedConfig)

        let after = await session.sessionContext?.activeUserConfiguration.signingPublicKey
        #expect(after == pinnedConfig.signingPublicKey)

        await session.shutdown()
    }

    @Test("adoptVerifiedUserConfiguration rejects a foreign signing key (TOFU pin)")
    func adoptRejectsForeignSigningKey() async throws {
        try await setupSession()

        let intruder = foreignConfiguration()

        await #expect(throws: PQSSession.SessionErrors.signingKeyOutOfSync) {
            try await session.adoptVerifiedUserConfiguration(intruder)
        }

        // Pin must remain unchanged after a rejected adoption attempt.
        guard let context = await session.sessionContext else {
            Issue.record("Expected session context to remain initialized")
            return
        }
        #expect(context.activeUserConfiguration.signingPublicKey != intruder.signingPublicKey)

        await session.shutdown()
    }

    @Test("updateUserConfiguration succeeds on master (account key matches device key)")
    func updateUserConfigurationOnMasterIsAllowed() async throws {
        try await setupSession()

        // Empty device list keeps the operation purely structural; the call must
        // not throw `signingKeyOutOfSync` on a master session.
        try await session.updateUserConfiguration([])

        await session.shutdown()
    }
}

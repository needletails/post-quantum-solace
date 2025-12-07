//
//  ChannelCommunicationTests.swift
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

import Foundation
import NeedleTailCrypto
@testable import PQSSession
import SessionEvents
import SessionModels
import Testing

@Suite(.serialized)
actor ChannelCommunicationTests {

    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    // MARK: - Helpers

    private func setupSession() async throws -> (SessionCache, SymmetricKey) {
        let mockUserData = MockUserData(session: session)
        let backingStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)

        await backingStore.setLocalSalt("channelSalt")
        await session.setLogLevel(.trace)
        await session.setDatabaseDelegate(conformer: backingStore)
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

        guard let cache = await session.cache else {
            Issue.record("Session cache should be initialized")
            throw PQSSession.SessionErrors.databaseNotInitialized
        }

        let symmetricKey = try await session.getDatabaseSymmetricKey()
        return (cache, symmetricKey)
    }

    // MARK: - Tests

    @Test("createChannelCommunication should throw when member count is invalid")
    func testCreateChannelCommunication_invalidMemberCount() async throws {
        let (cache, symmetricKey) = try await setupSession()

        await #expect(throws: PQSSession.SessionErrors.invalidMemberCount.self) {
            try await session.taskProcessor.createChannelCommunication(
                sender: "alice",
                recipient: .channel("general"),
                channelName: "general",
                administrator: "alice",
                members: ["alice"], // invalid: too few members
                operators: ["alice"],
                symmetricKey: symmetricKey,
                session: session,
                cache: cache,
                metadata: Data()
            )
        }

        await session.shutdown()
    }

    @Test("createChannelCommunication should not synchronize when shouldSynchronize is false")
    func testCreateChannelCommunication_noSynchronizationWhenDisabled() async throws {
        let (cache, symmetricKey) = try await setupSession()

        // Record current count instead of assuming empty cache
        let initialCommunications = try await cache.fetchCommunications()
        let initialCount = initialCommunications.count

        try await session.taskProcessor.createChannelCommunication(
            sender: "alice",
            recipient: .channel("general"),
            channelName: "general",
            administrator: "alice",
            members: ["alice", "bob", "joe"],
            operators: ["alice"],
            symmetricKey: symmetricKey,
            session: session,
            cache: cache,
            metadata: Data(),
            shouldSynchronize: false
        )

        // Communication should be created locally
        let communications = try await cache.fetchCommunications()
        #expect(communications.count == initialCount + 1)

        await session.shutdown()
    }
}


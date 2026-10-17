//
//  SelfConfigurationPinTests.swift
//  post-quantum-solace
//
//  The account signing key is pinned on first use. A self-refresh that is not
//  forced used to mint sibling lanes straight from whatever configuration the
//  directory returned, so a malicious directory could attach a device under
//  its own key and receive every personal fan-out copy. The pin must hold on
//  every self refresh, forced or not.
//

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
@testable import PQSSession
import SessionEvents
import SessionModels
import Testing

@Suite(.serialized)
actor SelfConfigurationPinTests {
    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    private func setupSession() async throws -> (MockUserData, MockIdentityStore) {
        let mockUserData = MockUserData(session: session)
        let cacheStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)

        await cacheStore.setLocalSalt("selfConfigPinSalt")
        await session.setDatabaseDelegate(conformer: cacheStore)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: ReceiverDelegate(session: session))
        await session.setConnectivity(true)
        await store.setPublishableName(mockUserData.ssn)

        session = try await session.createAccount(
            secretName: mockUserData.ssn,
            appPassword: mockUserData.sap
        ) {}
        await session.setAppPassword(mockUserData.sap)
        session = try await session.unlock(appPassword: mockUserData.sap)
        return (mockUserData, cacheStore)
    }

    /// A self-consistent account configuration under a key this device never saw,
    /// carrying one device the attacker controls.
    private func foreignConfiguration() async throws -> (UserConfiguration, UUID) {
        let attacker = PQSSession()
        defer { Task { await attacker.shutdown() } }
        let bundle = try await attacker.createDeviceCryptographicBundle(isMaster: true)
        return (bundle.userConfiguration, bundle.deviceKeys.deviceId)
    }

    private func deviceIds(in cacheStore: MockIdentityStore) async throws -> Set<UUID> {
        let key = try await session.getDatabaseSymmetricKey()
        var ids = Set<UUID>()
        for identity in await cacheStore.identities {
            if let props = await identity.props(symmetricKey: key) {
                ids.insert(props.deviceId)
            }
        }
        return ids
    }

    @Test("a non-forced self refresh refuses a configuration under a foreign account key")
    func nonForcedSelfRefreshRejectsForeignAccountKey() async throws {
        let (mockUserData, cacheStore) = try await setupSession()
        defer { Task { await session.shutdown() } }

        let (foreign, attackerDevice) = try await foreignConfiguration()
        await store.upsertUserConfiguration(
            secretName: mockUserData.ssn,
            deviceId: attackerDevice,
            config: foreign)
        // Cold memo, as after a process restart.
        await session.removeIdentity(with: mockUserData.ssn)

        await #expect(throws: PQSError.signingKeyOutOfSync) {
            _ = try await session.refreshIdentities(secretName: mockUserData.ssn)
        }

        let minted = try await deviceIds(in: cacheStore)
        #expect(!minted.contains(attackerDevice), "no lane may be minted for a device signed by a foreign account key")
        #expect(await session.accountIdentityRequiresAcknowledgement)

        // The pinned configuration in the live context is untouched.
        let pinned = try #require(await session.sessionContext?.activeUserConfiguration.signingPublicKey)
        #expect(pinned != foreign.signingPublicKey)
    }

    @Test("a matching self refresh still succeeds and clears the mismatch gate")
    func matchingSelfRefreshClearsGate() async throws {
        let (mockUserData, cacheStore) = try await setupSession()
        defer { Task { await session.shutdown() } }

        let (foreign, attackerDevice) = try await foreignConfiguration()
        await store.upsertUserConfiguration(
            secretName: mockUserData.ssn,
            deviceId: attackerDevice,
            config: foreign)
        await session.removeIdentity(with: mockUserData.ssn)
        await #expect(throws: PQSError.signingKeyOutOfSync) {
            _ = try await session.refreshIdentities(secretName: mockUserData.ssn)
        }
        #expect(await session.accountIdentityRequiresAcknowledgement)

        // The directory serves the real configuration again.
        let real = try #require(await session.sessionContext?.activeUserConfiguration)
        let ownDevice = try #require(await session.sessionContext?.sessionUser.deviceId)
        await store.upsertUserConfiguration(
            secretName: mockUserData.ssn,
            deviceId: ownDevice,
            config: real)
        await session.removeIdentity(with: mockUserData.ssn)

        _ = try await session.refreshIdentities(secretName: mockUserData.ssn)
        #expect(!(await session.accountIdentityRequiresAcknowledgement))
        let minted = try await deviceIds(in: cacheStore)
        #expect(!minted.contains(attackerDevice))
    }
}

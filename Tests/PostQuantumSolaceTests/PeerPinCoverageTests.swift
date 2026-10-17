//
//  PeerPinCoverageTests.swift
//  post-quantum-solace
//
//  The account-key pin used to live only on Contact rows. Channel members and
//  pre-friendship senders have lanes but no Contact, so a directory could swap
//  their whole account key and the next refresh would silently re-lane to it.
//  The first lane minted for a peer now pins its account key in the session
//  context, and the pin survives restarts without changing legacy blobs.
//

import BinaryCodable
import Foundation
import NeedleTailCrypto
@testable import PQSSession
import SessionModels
import Testing

@Suite(.serialized)
actor PeerPinCoverageTests {
    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    private func setupSession() async throws -> MockIdentityStore {
        let mockUserData = MockUserData(session: session)
        let cacheStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)
        await cacheStore.setLocalSalt("peerPinSalt")
        await session.setDatabaseDelegate(conformer: cacheStore)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: ReceiverDelegate(session: session))
        await session.setConnectivity(true)
        await store.setPublishableName(mockUserData.ssn)
        session = try await session.createAccount(secretName: mockUserData.ssn, appPassword: mockUserData.sap) {}
        await session.setAppPassword(mockUserData.sap)
        session = try await session.unlock(appPassword: mockUserData.sap)
        return cacheStore
    }

    private func publishedPeer(_ name: String) async throws -> (UserConfiguration, UUID) {
        let peer = PQSSession()
        defer { Task { await peer.shutdown() } }
        let bundle = try await peer.createDeviceCryptographicBundle(isMaster: true)
        await store.upsertUserConfiguration(
            secretName: name,
            deviceId: bundle.deviceKeys.deviceId,
            config: bundle.userConfiguration)
        return (bundle.userConfiguration, bundle.deviceKeys.deviceId)
    }

    @Test("the first lane to a non-contact pins its account key")
    func firstLaneToNonContactPinsAccountKey() async throws {
        let cacheStore = try await setupSession()
        defer { Task { await session.shutdown() } }

        let (original, originalDevice) = try await publishedPeer("carol")
        let lanes = try await session.refreshIdentities(secretName: "carol")
        #expect(!lanes.isEmpty)

        // The directory now serves carol under a different account key.
        let (_, foreignDevice) = try await publishedPeer("carol")
        await session.removeIdentity(with: "carol")

        await #expect(throws: PQSError.peerSigningKeyOutOfSync) {
            _ = try await session.refreshIdentities(secretName: "carol", forceRefresh: true)
        }

        let key = try await session.getDatabaseSymmetricKey()
        var laneDevices = Set<UUID>()
        for identity in await cacheStore.identities {
            if let props = await identity.props(symmetricKey: key), props.secretName == "carol" {
                laneDevices.insert(props.deviceId)
            }
        }
        #expect(laneDevices.contains(originalDevice))
        #expect(!laneDevices.contains(foreignDevice), "no lane may be minted under the swapped key")
        _ = original
    }

    @Test("legacy session contexts decode with no peer pins and encode byte-identically")
    func legacyContextsHaveNoPins() async throws {
        _ = try await setupSession()
        defer { Task { await session.shutdown() } }
        var context = try #require(await session.sessionContext)
        context.peerAccountSigningKeyPins = nil
        let encoded = try BinaryEncoder().encode(context)
        let decoded = try BinaryDecoder().decode(SessionContext.self, from: encoded)
        #expect(decoded.peerAccountSigningKeyPins == nil)
        #expect(try BinaryEncoder().encode(decoded) == encoded)
    }
}

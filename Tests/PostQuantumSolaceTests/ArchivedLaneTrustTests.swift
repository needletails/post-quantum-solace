//
//  ArchivedLaneTrustTests.swift
//  post-quantum-solace
//
//  An archived lane left behind by a peer's key rotation carries retired
//  identity keys. It may still decrypt a delayed frame, but it must never be
//  promoted back to the outbound lane: that would route our sends to keys the
//  rotation exists to abandon.
//

import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
@testable import PQSSession
import SessionModels
import Testing

@Suite(.serialized)
actor ArchivedLaneTrustTests {
    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    private func setupSession() async throws -> MockIdentityStore {
        let mockUserData = MockUserData(session: session)
        let cacheStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)
        await cacheStore.setLocalSalt("archivedLaneSalt")
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

    private func peerDevice(deviceId: UUID, signingKey: Curve25519.Signing.PrivateKey) throws -> UserDeviceConfiguration {
        let mlkem = try crypto.generateMLKem1024PrivateKey()
        return UserDeviceConfiguration(
            deviceId: deviceId,
            signingPublicKey: signingKey.publicKey.rawRepresentation,
            longTermPublicKey: Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation,
            finalMLKEMPublicKey: try MLKEMPublicKey(id: UUID(), mlkem.publicKey.rawRepresentation),
            deviceName: "bob-phone",
            hmacData: Data(),
            isMasterDevice: true)
    }

    private func mintLane(for device: UserDeviceConfiguration) async throws -> SessionIdentity {
        try await session.createEncryptableSessionIdentityModel(
            with: device,
            oneTimePublicKey: nil,
            mlKEMPublicKey: device.finalMLKEMPublicKey,
            for: "bob",
            associatedWith: device.deviceId,
            new: Int.random(in: 1 ..< .max))
    }

    private func isActive(_ identity: SessionIdentity, in store: MockIdentityStore) async throws -> Bool {
        let key = try await session.getDatabaseSymmetricKey()
        guard let row = await store.identities.first(where: { $0.id == identity.id }),
              let props = await row.props(symmetricKey: key) else { return false }
        return !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
    }

    @Test("an archive with retired identity keys is not promoted over the current lane")
    func retiredKeyArchiveIsNotPromoted() async throws {
        let cacheStore = try await setupSession()
        defer { Task { await session.shutdown() } }
        let deviceId = UUID()

        // Pre-rotation lane, then the peer rotates: a new lane under new keys.
        let archived = try await mintLane(for: try peerDevice(deviceId: deviceId, signingKey: .init()))
        _ = try await session.demoteActiveSessionIdentityToInactive(archived)
        let current = try await mintLane(for: try peerDevice(deviceId: deviceId, signingKey: .init()))

        // A delayed (or attacker-held) frame decrypted on the archive.
        _ = try await session.activateSessionIdentityAfterInboundDecrypt(archived)

        #expect(try await isActive(current, in: cacheStore), "the current lane must stay active")
        #expect(!(try await isActive(archived, in: cacheStore)), "the retired-key archive must stay decrypt-only")
    }

    @Test("an archive that still carries the current identity keys is promoted")
    func sameKeyArchiveIsPromoted() async throws {
        let cacheStore = try await setupSession()
        defer { Task { await session.shutdown() } }
        let deviceId = UUID()
        let signingKey = Curve25519.Signing.PrivateKey()
        let device = try peerDevice(deviceId: deviceId, signingKey: signingKey)

        let archived = try await mintLane(for: device)
        _ = try await session.demoteActiveSessionIdentityToInactive(archived)
        let current = try await mintLane(for: device)

        _ = try await session.activateSessionIdentityAfterInboundDecrypt(archived)

        #expect(try await isActive(archived, in: cacheStore), "a ratchet-reset archive may be promoted")
        #expect(!(try await isActive(current, in: cacheStore)))
    }
}

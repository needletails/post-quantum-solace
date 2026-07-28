//
//  NackEpisodeLaneReuseTests.swift
//  post-quantum-solace
//
//  Legacy surgical NACK episode-lane reuse is superseded by strict §4.1
//  OOB retry. These tests now assert that requestMessageResend does not mint
//  DR control lanes.
//

import Foundation
import Crypto
import DoubleRatchetKit
import SessionModels
@testable import PQSSession
import Testing

@Suite(.serialized)
actor NackEpisodeLaneReuseTests {

    var session = PQSSession()
    let transport: _MockTransportDelegate
    var senderReceiver: ReceiverDelegate
    let store = TransportStore()

    init() {
        senderReceiver = ReceiverDelegate(session: session)
        transport = _MockTransportDelegate(session: session, store: store)
    }

    private func createSenderSession(store: MockIdentityStore) async throws {
        await store.setLocalSalt("testSaltEpisodeLane")
        await session.setLogLevel(.trace)
        await session.setDatabaseDelegate(conformer: store)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: senderReceiver)
        await session.setViability(true)
        await self.store.setPublishableName("alice")
        session = try await session.createSession(secretName: "alice", appPassword: "123") {}
        await session.setAppPassword("123")
        session = try await session.startSession(appPassword: "123")
        try await senderReceiver.setKey(session.getDatabaseSymmetricKey())
    }

    private func installLinkedSiblingDevice() async throws -> UUID {
        let childBundle = try await session.createDeviceCryptographicBundle(isMaster: false)
        guard let masterContext = await session.sessionContext else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        guard let childDevice = try childBundle.userConfiguration.getVerifiedDevices().first(where: {
            $0.deviceId == childBundle.deviceKeys.deviceId
        }) else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }
        let masterSigningKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: masterContext.sessionUser.deviceKeys.signingPrivateKey)

        var configuration = masterContext.activeUserConfiguration
        configuration.signedDevices.removeAll { $0.id == childDevice.deviceId }
        configuration.signedDevices.append(try UserConfiguration.SignedDeviceConfiguration(
            device: childDevice,
            signingKey: masterSigningKey))
        for key in childBundle.userConfiguration.signedOneTimePublicKeys {
            configuration.signedOneTimePublicKeys.removeAll { $0.id == key.id }
            configuration.signedOneTimePublicKeys.append(key)
        }
        for key in childBundle.userConfiguration.signedMLKEMOneTimePublicKeys {
            configuration.signedMLKEMOneTimePublicKeys.removeAll { $0.id == key.id }
            configuration.signedMLKEMOneTimePublicKeys.append(key)
        }
        for bundle in childBundle.userConfiguration.signedDeviceKeyBundles {
            configuration.signedDeviceKeyBundles.removeAll { $0.id == bundle.id }
            configuration.signedDeviceKeyBundles.append(bundle)
        }

        await store.upsertUserConfiguration(
            secretName: "alice",
            deviceId: childBundle.deviceKeys.deviceId,
            config: configuration)
        try await session.adoptVerifiedUserConfiguration(configuration)
        return childBundle.deviceKeys.deviceId
    }

    private func activeIdentityIds(
        secretName: String,
        deviceId: UUID
    ) async throws -> [UUID] {
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let identities = try await session.cache?.fetchSessionIdentities() ?? []
        var ids: [UUID] = []
        for identity in identities {
            guard let props = await identity.props(symmetricKey: symmetricKey),
                  props.secretName == secretName,
                  props.deviceId == deviceId,
                  !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            else { continue }
            ids.append(identity.id)
        }
        return ids
    }

    @Test("Same-account continuous episode emits OOB retries without minting control lanes")
    func sameAccountContinuousEpisodeReusesOneSurgicalLane() async throws {
        let identityStore = MockIdentityStore(
            mockUserData: .init(session: session),
            session: session,
            isSender: true)
        try await createSenderSession(store: identityStore)
        let peerDeviceId = try await installLinkedSiblingDevice()
        let before = try await activeIdentityIds(secretName: "alice", deviceId: peerDeviceId)

        try await session.requestMessageResend(
            sharedMessageId: "episode_lane_a",
            senderName: "alice",
            senderDeviceId: peerDeviceId,
            forceFreshControlLane: true)
        try await session.requestMessageResend(
            sharedMessageId: "episode_lane_b",
            senderName: "alice",
            senderDeviceId: peerDeviceId,
            forceFreshControlLane: false)

        try await Task.sleep(nanoseconds: 100_000_000)
        let after = try await activeIdentityIds(secretName: "alice", deviceId: peerDeviceId)
        let oobCount = await transport.outOfBandResendRequestCount
        #expect(oobCount >= 2, "expected two OOB retries, got \(oobCount)")
        #expect(
            after.count == before.count,
            "OOB retry must not mint surgical control lanes; before=\(before) after=\(after)")

        await session.shutdown()
    }

    @Test("Concurrent same-account NACK resolves do not mint control lanes")
    func concurrentSameAccountNacksReserveOneSurgicalLane() async throws {
        let identityStore = MockIdentityStore(
            mockUserData: .init(session: session),
            session: session,
            isSender: true)
        try await createSenderSession(store: identityStore)
        let peerDeviceId = try await installLinkedSiblingDevice()
        let before = try await activeIdentityIds(secretName: "alice", deviceId: peerDeviceId)

        async let a: Void = session.requestMessageResend(
            sharedMessageId: "episode_concurrent_a",
            senderName: "alice",
            senderDeviceId: peerDeviceId,
            forceFreshControlLane: false)
        async let b: Void = session.requestMessageResend(
            sharedMessageId: "episode_concurrent_b",
            senderName: "alice",
            senderDeviceId: peerDeviceId,
            forceFreshControlLane: false)
        _ = try await (a, b)

        try await Task.sleep(nanoseconds: 100_000_000)
        let after = try await activeIdentityIds(secretName: "alice", deviceId: peerDeviceId)
        #expect(after.count == before.count)

        await session.shutdown()
    }
}

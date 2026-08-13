//
//  StrictOOBRetryTests.swift
//  post-quantum-solace
//
//  S1/S7/S13: undecryptable retry must be out-of-band — no DR encrypt / surgical mint.
//

import Foundation
import Crypto
import DoubleRatchetKit
import SessionModels
@testable import PQSSession
import Testing

@Suite(.serialized)
actor StrictOOBRetryTests {
    var session = PQSSession()
    let transport: _MockTransportDelegate
    var senderReceiver: ReceiverDelegate
    let store = TransportStore()

    init() {
        senderReceiver = ReceiverDelegate(session: session)
        transport = _MockTransportDelegate(session: session, store: store)
    }

    private func createSenderSession(store: MockIdentityStore) async throws {
        await store.setLocalSalt("testSaltStrictOOB")
        await session.setLogLevel(.trace)
        await session.setDatabaseDelegate(conformer: store)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: senderReceiver)
        await session.setConnectivity(true)
        await self.store.setPublishableName("alice")
        session = try await session.createAccount(secretName: "alice", appPassword: "123") {}
        await session.setAppPassword("123")
        session = try await session.unlock(appPassword: "123")
        try await senderReceiver.setKey(session.getDatabaseSymmetricKey())
    }

    private func installPeerDevice(secretName: String) async throws -> UUID {
        let peerBundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        await store.upsertUserConfiguration(
            secretName: secretName,
            deviceId: peerBundle.deviceKeys.deviceId,
            config: peerBundle.userConfiguration)
        return peerBundle.deviceKeys.deviceId
    }

    private func activeIdentityCount(secretName: String, deviceId: UUID) async throws -> Int {
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let identities = try await session.cache?.fetchSessionIdentities() ?? []
        var count = 0
        for identity in identities {
            guard let props = await identity.props(symmetricKey: symmetricKey),
                  props.secretName == secretName,
                  props.deviceId == deviceId,
                  !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            else { continue }
            count += 1
        }
        return count
    }

    @Test("S1/S13: requestMessageResend emits OOB without surgical DR mint")
    func undecryptableEmitsOOBWithoutDRMint() async throws {
        let identityStore = MockIdentityStore(
            mockUserData: .init(session: session),
            session: session,
            isSender: true)
        try await createSenderSession(store: identityStore)
        let peerDeviceId = try await installPeerDevice(secretName: "bob")
        let before = try await activeIdentityCount(secretName: "bob", deviceId: peerDeviceId)

        try await session.requestMessageResend(
            sharedMessageId: "failed-envelope-1",
            senderName: "bob",
            senderDeviceId: peerDeviceId)

        try await Task.sleep(nanoseconds: 150_000_000)

        let after = try await activeIdentityCount(secretName: "bob", deviceId: peerDeviceId)
        let oobCount = await transport.outOfBandResendRequestCount
        #expect(
            oobCount >= 1,
            "requestMessageResend must call sendOutOfBandResendRequest; oobCount=\(oobCount)")
        #expect(
            after == before,
            "OOB retry must not surgical-mint a DR control lane; before=\(before) after=\(after)")

        await session.shutdown()
    }

    private func installLinkedSiblingDevice() async throws -> UUID {
        let childBundle = try await session.createDeviceCryptographicBundle(isMaster: false)
        guard let masterContext = await session.sessionContext else {
            throw PQSError.sessionNotInitialized
        }
        guard let childDevice = try childBundle.userConfiguration.getVerifiedDevices().first(where: {
            $0.deviceId == childBundle.deviceKeys.deviceId
        }) else {
            throw PQSError.invalidDeviceIdentity
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

    @Test("S1/S13 same-account: continuous episode emits OOB without minting control lanes")
    func sameAccountContinuousEpisodeDoesNotMintControlLanes() async throws {
        let identityStore = MockIdentityStore(
            mockUserData: .init(session: session),
            session: session,
            isSender: true)
        try await createSenderSession(store: identityStore)
        let peerDeviceId = try await installLinkedSiblingDevice()
        let before = try await activeIdentityCount(secretName: "alice", deviceId: peerDeviceId)

        try await session.requestMessageResend(
            sharedMessageId: "episode_lane_a",
            senderName: "alice",
            senderDeviceId: peerDeviceId)
        try await session.requestMessageResend(
            sharedMessageId: "episode_lane_b",
            senderName: "alice",
            senderDeviceId: peerDeviceId)

        try await Task.sleep(nanoseconds: 100_000_000)
        let after = try await activeIdentityCount(secretName: "alice", deviceId: peerDeviceId)
        let oobCount = await transport.outOfBandResendRequestCount
        #expect(oobCount >= 2, "expected two OOB retries, got \(oobCount)")
        #expect(
            after == before,
            "OOB retry must not mint surgical control lanes; before=\(before) after=\(after)")

        await session.shutdown()
    }

    @Test("S1/S13 same-account: concurrent NACKs do not mint control lanes")
    func concurrentSameAccountNacksDoNotMintControlLanes() async throws {
        let identityStore = MockIdentityStore(
            mockUserData: .init(session: session),
            session: session,
            isSender: true)
        try await createSenderSession(store: identityStore)
        let peerDeviceId = try await installLinkedSiblingDevice()
        let before = try await activeIdentityCount(secretName: "alice", deviceId: peerDeviceId)

        async let a: Void = session.requestMessageResend(
            sharedMessageId: "episode_concurrent_a",
            senderName: "alice",
            senderDeviceId: peerDeviceId)
        async let b: Void = session.requestMessageResend(
            sharedMessageId: "episode_concurrent_b",
            senderName: "alice",
            senderDeviceId: peerDeviceId)
        _ = try await (a, b)

        try await Task.sleep(nanoseconds: 100_000_000)
        let after = try await activeIdentityCount(secretName: "alice", deviceId: peerDeviceId)
        #expect(after == before)

        await session.shutdown()
    }
}

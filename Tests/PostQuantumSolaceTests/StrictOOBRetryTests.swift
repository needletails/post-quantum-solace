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
        await session.setViability(true)
        await self.store.setPublishableName("alice")
        session = try await session.createSession(secretName: "alice", appPassword: "123") {}
        await session.setAppPassword("123")
        session = try await session.startSession(appPassword: "123")
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
            senderDeviceId: peerDeviceId,
            forceFreshControlLane: true)

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
}

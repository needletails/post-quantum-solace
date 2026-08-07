//
//  SelfConfigurationStaleRefreshTests.swift
//  post-quantum-solace
//
//  Dogfood (device linking, 2026-08-08): the master accepted `.syncNewDevice`,
//  merged the child into its local active configuration, and republished — but the
//  transport's configuration lookup still served the pre-link snapshot. A subsequent
//  self `refreshIdentities(forceRefresh: true)`:
//    1. adopted the stale remote snapshot via `synchronizeActiveUserConfiguration`,
//       silently REMOVING the freshly linked child from the local session context, and
//    2. created no session identity for the child, so its post-link inbound messages
//       died with `missingIdentity` and were purged permanently.
//
//  Invariants encoded here:
//  - A self force-refresh must never drop devices the local context has already
//    signed, no matter how stale the fetched snapshot is.
//  - Locally signed devices missing from the fetched snapshot must still get a
//    session identity minted (local context is authoritative for own-account adds;
//    the merged document is still fully signature-validated).
//  - A remote snapshot that is a superset (true convergence) must still be adopted.
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
actor SelfConfigurationStaleRefreshTests {

    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    // MARK: - Helpers

    private func setupSession() async throws -> MockUserData {
        let mockUserData = MockUserData(session: session)
        let cacheStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)

        await cacheStore.setLocalSalt("selfConfigStaleRefreshSalt")
        await session.setLogLevel(.trace)
        await session.setDatabaseDelegate(conformer: cacheStore)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: ReceiverDelegate(session: session))

        await session.setViability(true)
        await store.setPublishableName(mockUserData.ssn)

        session = try await session.createSession(
            secretName: mockUserData.ssn,
            appPassword: mockUserData.sap
        ) {}

        await session.setAppPassword(mockUserData.sap)
        session = try await session.startSession(appPassword: mockUserData.sap)
        return mockUserData
    }

    private func currentDevice(from context: SessionContext) throws -> UserDeviceConfiguration {
        let accountKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: context.activeUserConfiguration.signingPublicKey
        )
        guard let signedSelf = context.activeUserConfiguration.signedDevices.first(where: {
            $0.id == context.sessionUser.deviceId
        }), let device = try signedSelf.verified(using: accountKey) else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }
        return device
    }

    private func makeLinkedChildSignedDevice(
        accountSigningKey: Curve25519.Signing.PrivateKey,
        template: UserDeviceConfiguration
    ) throws -> (signed: UserConfiguration.SignedDeviceConfiguration, deviceId: UUID) {
        let perDeviceSigningKey = Curve25519.Signing.PrivateKey()
        let deviceId = UUID()
        let child = UserDeviceConfiguration(
            deviceId: deviceId,
            signingPublicKey: perDeviceSigningKey.publicKey.rawRepresentation,
            longTermPublicKey: template.longTermPublicKey,
            finalMLKEMPublicKey: template.finalMLKEMPublicKey,
            deviceName: "linked-child-\(UUID().uuidString.prefix(6))",
            hmacData: template.hmacData,
            isMasterDevice: false
        )
        let signed = try UserConfiguration.SignedDeviceConfiguration(
            device: child,
            signingKey: accountSigningKey
        )
        return (signed, deviceId)
    }

    private func persist(context: SessionContext) async throws {
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        await session.setSessionContext(context)
        let encoded = try BinaryEncoder().encode(context)
        guard let encrypted = try await crypto.encrypt(data: encoded, symmetricKey: session.getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encrypted)
    }

    // MARK: - Tests

    @Test("stale self force-refresh must not drop a locally signed linked device")
    func staleSelfRefreshDoesNotDropLocallySignedChild() async throws {
        let mockUserData = try await setupSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        // The remote store keeps serving the PRE-LINK snapshot (only the master
        // device) — the stale lookup-cache shape from the 2026-08-08 dogfood run.
        let masterDevice = try currentDevice(from: originalContext)
        let accountSigningKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: originalContext.sessionUser.deviceKeys.signingPrivateKey
        )

        // Master accepted `.syncNewDevice`: merge the child into the LOCAL context only.
        let child = try makeLinkedChildSignedDevice(
            accountSigningKey: accountSigningKey,
            template: masterDevice
        )
        var linkedContext = originalContext
        linkedContext.activeUserConfiguration.signedDevices.append(child.signed)
        try await persist(context: linkedContext)

        // Self force-refresh against the stale remote snapshot.
        let identities = try await session.refreshIdentities(
            secretName: mockUserData.ssn,
            forceRefresh: true
        )

        guard let postContext = await session.sessionContext else {
            Issue.record("Session context should survive refresh")
            return
        }
        let postDeviceIds = postContext.activeUserConfiguration.signedDevices.map(\.id)
        #expect(postDeviceIds.contains(child.deviceId),
                """
                BUG (device-link missingIdentity): a self force-refresh adopted a stale remote \
                snapshot and removed the freshly linked child from the local session context.
                """)

        // The child must also get a session identity minted from local knowledge so
        // its post-link inbound messages can decrypt while the remote snapshot lags.
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let identityDeviceIds = await identities.asyncCompactMap { identity in
            await identity.props(symmetricKey: symmetricKey)?.deviceId
        }
        #expect(identityDeviceIds.contains(child.deviceId),
                """
                BUG (device-link missingIdentity): no session identity was created for the \
                locally signed child during a stale self refresh, so inbound messages from it \
                fail with missingIdentity and get purged.
                """)

        await session.shutdown()
    }

    @Test("superset remote snapshot is still adopted on self force-refresh")
    func supersetRemoteSnapshotStillAdopted() async throws {
        let mockUserData = try await setupSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let masterDevice = try currentDevice(from: originalContext)
        let accountSigningKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: originalContext.sessionUser.deviceKeys.signingPrivateKey
        )

        // Remote already converged to master + child; local still pre-link.
        let child = try makeLinkedChildSignedDevice(
            accountSigningKey: accountSigningKey,
            template: masterDevice
        )
        var remoteConfig = originalContext.activeUserConfiguration
        remoteConfig.signedDevices.append(child.signed)
        if let index = await store.userConfigurations.firstIndex(where: {
            $0.secretName == mockUserData.ssn
        }) {
            await store.setUserConfigurations(index: index, config: remoteConfig)
        } else {
            Issue.record("Remote store should contain the published configuration")
            return
        }

        _ = try await session.refreshIdentities(
            secretName: mockUserData.ssn,
            forceRefresh: true
        )

        guard let postContext = await session.sessionContext else {
            Issue.record("Session context should survive refresh")
            return
        }
        let postDeviceIds = postContext.activeUserConfiguration.signedDevices.map(\.id)
        #expect(postDeviceIds.contains(child.deviceId),
                "A superset remote snapshot must still be adopted (forward convergence)")

        await session.shutdown()
    }
}

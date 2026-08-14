//
//  SchemaMigrationTests.swift
//  post-quantum-solace
//
//  Schema 1 → 2 unlock migration proofs.
//

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
import SessionModels
import Testing
@testable import PQSSession

@Suite("Schema 2 migration")
struct SchemaMigrationTests {
    private func makeContext(schemaVersion: Int) async throws -> (PQSSession, SessionContext) {
        let session = PQSSession()
        let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        let sessionUser = SessionUser(
            secretName: "alice",
            deviceId: bundle.deviceKeys.deviceId,
            deviceKeys: bundle.deviceKeys)
        let context = SessionContext(
            sessionUser: sessionUser,
            databaseEncryptionKey: Data(repeating: 0x24, count: 32),
            sessionContextId: 1,
            activeUserConfiguration: bundle.userConfiguration,
            registrationState: .registered,
            schemaVersion: schemaVersion)
        return (session, context)
    }

    @Test("schema-1 SessionContext round-trips version 1")
    func schema1ContextDecodesAsVersion1() async throws {
        let (session, context) = try await makeContext(schemaVersion: 1)
        defer { Task { await session.shutdown() } }
        let encoded = try BinaryEncoder().encode(context)
        let decoded = try BinaryDecoder().decode(SessionContext.self, from: encoded)
        #expect(decoded.schemaVersion == 1)
    }

    @Test("new SessionContext persists schema 2")
    func newContextPersistsSchema2() async throws {
        let (session, context) = try await makeContext(schemaVersion: 2)
        defer { Task { await session.shutdown() } }
        #expect(context.schemaVersion == 2)
        let encoded = try BinaryEncoder().encode(context)
        let decoded = try BinaryDecoder().decode(SessionContext.self, from: encoded)
        #expect(decoded.schemaVersion == 2)
    }

    @Test("schema-2 store skips migration (idempotent)")
    func schema2StoreSkipsMigration() async throws {
        let (session, context) = try await makeContext(schemaVersion: 2)
        defer { Task { await session.shutdown() } }
        let encodedBefore = try BinaryEncoder().encode(context)
        let out = try await session.migratePersistedStoreIfNeeded(
            sessionContext: context,
            appSymmetricKey: SymmetricKey(data: Data(repeating: 0x25, count: 32)))
        #expect(out.schemaVersion == 2)
        let encodedAfter = try BinaryEncoder().encode(out)
        #expect(encodedAfter == encodedBefore)
    }

    @Test("bare ChannelInfo metadata migrates to ChannelStoredMetadata")
    func bareChannelInfoMigrates() throws {
        let info = ChannelInfo(
            name: "design",
            administrator: "alice",
            members: ["alice"],
            operators: [])
        let bare = try BinaryEncoder().encode(info)
        #expect(throws: (any Error).self) {
            _ = try BinaryDecoder().decode(ChannelStoredMetadata.self, from: bare)
        }
        let migrated = try #require(ChannelStoredMetadata.migrating(from: bare))
        #expect(migrated.core.name == "design")
        #expect(migrated.overlay == nil)
        let keyed = try BinaryEncoder().encode(migrated)
        let roundTrip = try BinaryDecoder().decode(ChannelStoredMetadata.self, from: keyed)
        #expect(roundTrip.core.name == "design")
    }

    @Test("currentDeviceKeyBundle uses a signed bundle when present")
    func currentDeviceKeyBundlePrefersSignedBundle() async throws {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        let device = try #require(try bundle.userConfiguration.getVerifiedDevices().first)
        let resolved = try bundle.userConfiguration.currentDeviceKeyBundle(for: device)
        #expect(resolved.deviceId == device.deviceId)
        var withoutBundles = bundle.userConfiguration
        withoutBundles.signedDeviceKeyBundles = []
        let synthesized = try withoutBundles.currentDeviceKeyBundle(for: device)
        #expect(synthesized.longTermPublicKey == device.longTermPublicKey)
    }
}

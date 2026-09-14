//
//  PQSSession+SchemaMigration.swift
//  post-quantum-solace
//
//  Schema 1 → 2 unlock migration. Idempotent: schema-2 stores skip this path.
//

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
import SessionModels

extension PQSSession {
    /// Runs on-disk schema upgrades after a successful decrypt of `SessionContext`.
    /// Missing `schemaVersion` is treated as 1. Already-current stores return immediately.
    func migratePersistedStoreIfNeeded(
        sessionContext: SessionContext,
        appSymmetricKey: SymmetricKey
    ) async throws -> SessionContext {
        var context = sessionContext
        var didSchemaMigrate = false
        if context.schemaVersion < PQSSessionConstants.sessionSchemaVersion {
            context = try await migrateSchema1To2(context)
            context.schemaVersion = PQSSessionConstants.sessionSchemaVersion
            didSchemaMigrate = true
        }
        let mintedSealedSender: Bool
        (context, mintedSealedSender) = try mintSealedSenderKeyIfNeeded(context)
        if didSchemaMigrate || mintedSealedSender {
            try await persistSessionContext(context, appSymmetricKey: appSymmetricKey)
        }
        if mintedSealedSender {
            await setSessionContext(context)
            try? await publishLocalDeviceKeyBundle()
        }
        return context
    }

    private func migrateSchema1To2(_ context: SessionContext) async throws -> SessionContext {
        var context = context
        context = try mintLocalDeviceKeyBundleIfNeeded(context)
        try await dropRetiredEncryptedRetryJobs()
        try await rewriteBareChannelMetadata()
        return context
    }

    func mintLocalDeviceKeyBundleIfNeeded(_ context: SessionContext) throws -> SessionContext {
        var context = context
        let deviceId = context.sessionUser.deviceId
        let hasBundle = context.activeUserConfiguration.signedDeviceKeyBundles.contains { $0.id == deviceId }
        guard !hasBundle else { return context }

        guard let device = try context.activeUserConfiguration.getVerifiedDevices().first(where: {
            $0.deviceId == deviceId
        }) else {
            return context
        }
        let signingKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: context.sessionUser.deviceKeys.signingPrivateKey)
        let deviceKeys = context.sessionUser.deviceKeys
        let longTermPublicKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: deviceKeys.longTermPrivateKey
        ).publicKey.rawRepresentation
        let finalRaw = try deviceKeys.finalMLKEMPrivateKey.rawRepresentation.decodeMLKem1024()
        let finalPublicKey = try MLKEMPublicKey(
            id: deviceKeys.finalMLKEMPrivateKey.id,
            finalRaw.publicKey.rawRepresentation)
        let bundle = UserConfiguration.DeviceKeyBundle(
            deviceId: device.deviceId,
            longTermPublicKey: longTermPublicKey,
            finalMLKEMPublicKey: finalPublicKey,
            updatedAt: Date(),
            capabilities: deviceKeys.sealedSenderDeviceCapabilities,
            sealedSenderMLKEMPublicKey: try deviceKeys.sealedSenderMLKEMPublicKey())
        let signed = try UserConfiguration.SignedDeviceKeyBundle(bundle: bundle, signingKey: signingKey)
        context.activeUserConfiguration.signedDeviceKeyBundles.append(signed)
        return context
    }

    /// Mints a dedicated sealed-sender key for existing devices that predate it.
    /// Idempotent: returns false when the key is already present.
    func mintSealedSenderKeyIfNeeded(_ context: SessionContext) throws -> (SessionContext, Bool) {
        var context = context
        guard context.sessionUser.deviceKeys.sealedSenderMLKEMPrivateKey == nil else {
            return (context, false)
        }
        let generated = try crypto.generateMLKem1024PrivateKey()
        let sealedPrivateKey = try MLKEMPrivateKey(id: UUID(), generated.encode())
        context.sessionUser.deviceKeys.replaceSealedSenderMLKEMPrivateKey(
            sealedPrivateKey,
            retainingPrevious: false)
        let deviceId = context.sessionUser.deviceId
        guard let device = try context.activeUserConfiguration.getVerifiedDevices().first(where: {
            $0.deviceId == deviceId
        }) else {
            return (context, true)
        }
        let signingKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: context.sessionUser.deviceKeys.signingPrivateKey)
        let current = try context.activeUserConfiguration.currentDeviceKeyBundle(for: device)
        let signed = try UserConfiguration.SignedDeviceKeyBundle(
            bundle: .init(
                deviceId: deviceId,
                longTermPublicKey: current.longTermPublicKey,
                finalMLKEMPublicKey: current.finalMLKEMPublicKey,
                updatedAt: Date(),
                capabilities: context.sessionUser.deviceKeys.sealedSenderDeviceCapabilities,
                sealedSenderMLKEMPublicKey: try context.sessionUser.deviceKeys.sealedSenderMLKEMPublicKey()
            ),
            signingKey: signingKey)
        context.activeUserConfiguration.signedDeviceKeyBundles.removeAll { $0.id == deviceId }
        context.activeUserConfiguration.signedDeviceKeyBundles.append(signed)
        return (context, true)
    }

    private func dropRetiredEncryptedRetryJobs() async throws {
        guard let cache else { return }
        let databaseKey = try await getDatabaseSymmetricKey()
        let jobs = try await cache.fetchJobs()
        for job in jobs {
            guard let props = await job.props(symmetricKey: databaseKey) else { continue }
            if jobCarriesRetiredEncryptedRetry(props) {
                try await cache.deleteJob(job)
            }
        }
    }

    private func jobCarriesRetiredEncryptedRetry(_ props: JobModel.UnwrappedProps) -> Bool {
        if case .writeMessage(let outbound) = props.task.task,
           let info = outbound.message.transportInfo,
           TransportEvent.carriesRetiredEncryptedRetry(info) {
            return true
        }
        if let event = props.preparedOutbound?.transportEvent,
           TransportEvent.carriesRetiredEncryptedRetry(
            (try? BinaryEncoder().encode(event)) ?? Data()) {
            return true
        }
        return false
    }

    private func rewriteBareChannelMetadata() async throws {
        guard let cache else { return }
        let databaseKey = try await getDatabaseSymmetricKey()
        let communications = try await cache.fetchCommunications()
        for communication in communications {
            guard var props = await communication.props(symmetricKey: databaseKey) else { continue }
            let original = props.metadata
            guard !original.isEmpty else { continue }
            if (try? BinaryDecoder().decode(ChannelStoredMetadata.self, from: original)) != nil {
                continue
            }
            guard let migrated = ChannelStoredMetadata.migrating(from: original) else { continue }
            let rewritten = try BinaryEncoder().encode(migrated)
            guard rewritten != original else { continue }
            props.metadata = rewritten
            _ = try await communication.updateProps(symmetricKey: databaseKey, props: props)
            try await cache.updateCommunication(communication)
        }
    }

    private func persistSessionContext(
        _ context: SessionContext,
        appSymmetricKey: SymmetricKey
    ) async throws {
        guard let cache else {
            throw PQSError.databaseNotInitialized
        }
        let encoded = try BinaryEncoder().encode(context)
        guard let encrypted = try crypto.encrypt(data: encoded, symmetricKey: appSymmetricKey) else {
            throw PQSError.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encrypted)
    }
}

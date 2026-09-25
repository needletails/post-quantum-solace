//
//  PQSSession+OneTimeKeys.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-12.
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

import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
import NeedleTailLogger
import SessionEvents
import SessionModels

/// One-time-key refresh, replacement, and local synchronization for
/// Curve25519 and ML-KEM batches.
extension PQSSession {
    private func removeExpiredOTKeys() {
        refreshOTKeysTask = nil
    }

    private func removeExpiredMLKEMOTKeys() {
        refreshMLKEMOTKeysTask = nil
    }

    /// Whether *this device's* published one-time keys are at or below the low watermark.
    ///
    /// `signedOneTimePublicKeys` / `signedMLKEMOneTimePublicKeys` hold the whole
    /// account's pool: every linked device publishes into the same array. The
    /// account-wide count therefore hides an exhausted device behind its siblings'
    /// keys — a freshly linked child holding its single starter key never trips the
    /// watermark while the master still holds a full batch, so it never replenishes
    /// and the next fresh lane the master opens to it fails with `missingOneTimeKey`.
    /// Peers only ever draw from the recipient device's keys, so the watermark has to
    /// be evaluated per device.
    static func localDeviceOneTimeKeysAreLow(in context: SessionContext, type: KeyKind) -> Bool {
        localDevicePublishedOneTimeKeyCount(in: context, type: type) <= PQSSessionConstants.oneTimeKeyLowWatermark
    }

    static func localDevicePublishedOneTimeKeyCount(in context: SessionContext, type: KeyKind) -> Int {
        let deviceId = context.sessionUser.deviceId
        switch type {
        case .x25519:
            return context.activeUserConfiguration.signedOneTimePublicKeys.filter { $0.deviceId == deviceId }.count
        case .mlKEM:
            return context.activeUserConfiguration.signedMLKEMOneTimePublicKeys.filter { $0.deviceId == deviceId }.count
        }
    }

    /// Manually triggers a refresh of Curve25519 one-time keys
    ///
    /// By default this matches automatic refresh: after syncing with the server, new keys are
    /// generated and uploaded only when the remaining count is at or below
    /// `PQSSessionConstants.oneTimeKeyLowWatermark`. Use `policy` to request an explicit top-up
    /// or to fully replace this device's current batch.
    ///
    /// - Note: The refresh task runs asynchronously. When a replenish runs, it creates up to
    ///   enough keys to reach `PQSSessionConstants.oneTimeKeyBatchSize`.
    /// - Parameter policy: Controls whether the task only refreshes when low, forces a top-up,
    ///   or replaces the current device's one-time-key batch entirely.
    @discardableResult
    public func refreshOneTimeKeysTask(policy: OneTimeKeyRefreshPolicy = .automatic) async -> Bool {
        if otkUploadCircuitOpen {
            if let openedAt = otkUploadCircuitOpenedAt,
               Date().timeIntervalSince(openedAt) < otkCircuitCooldownSeconds {
                let remaining = Int(otkCircuitCooldownSeconds - Date().timeIntervalSince(openedAt))
                logger.log(level: .info, message: "OTK upload circuit breaker open; skipping curve refresh (\(remaining)s until probe)")
                return false
            }
            logger.log(level: .info, message: "OTK circuit breaker cooldown elapsed; allowing probe attempt for curve keys")
        }

        // Coalesce concurrent refresh requests to avoid cancel/restart storms that
        // surface as URLSession cancellation errors (-999) under load.
        if policy != .automatic, let existingTask = refreshOTKeysTask {
            _ = await existingTask.value
        } else if let existingTask = refreshOTKeysTask {
            return await existingTask.value
        }

        refreshOTKeysTask = Task(executorPreference: messagePipeline.keyTransportExecutor) { [weak self] in
            guard let self else { return false }
            let retryDelays: [UInt64] = [1_000_000_000, 3_000_000_000]
            for attempt in 0...retryDelays.count {
                do {
                    try await refreshOneTimeKeys(refreshType: .x25519, policy: policy)
                    await removeExpiredOTKeys()
                    return true
                } catch let sessionError as PQSError where sessionError == .signingKeyMismatchWithServer {
                    await self.logger.log(level: .error, message: "Signing key mismatch detected during curve OTK upload; opening circuit breaker and initiating recovery")
                    await self.openOTKUploadCircuitAndScheduleRecovery()
                    return false
                } catch let sessionError as PQSError where sessionError == .oneTimeKeyUploadFailed {
                    if attempt < retryDelays.count {
                        await logger.log(level: .warning, message: "Curve OTK upload failed (attempt \(attempt + 1)/\(retryDelays.count + 1)), retrying after backoff")
                        do {
                            try await Task.sleep(nanoseconds: retryDelays[attempt])
                        } catch {
                            return false
                        }
                    } else {
                        await logger.log(level: .error, message: "Curve OTK upload failed after \(attempt + 1) attempts")
                        await removeExpiredOTKeys()
                        return false
                    }
                } catch {
                    await logger.log(level: .error, message: "Error refreshing one-time keys: \(error)")
                    await logger.log(level: .warning, message: "Curve one-time-key refresh failed; local/server state may remain out of sync")
                    await removeExpiredOTKeys()
                    return false
                }
            }
            return false
        }

        return await refreshOTKeysTask?.value ?? false
    }

    /// Manually triggers a refresh of MLKEM one-time keys
    ///
    /// Default behavior matches automatic refresh (see `refreshOneTimeKeysTask`). Use `policy`
    /// for reconciliation paths that must top up even when above the low watermark or for
    /// compromise-recovery paths that must replace the current device batch.
    ///
    /// - Parameter policy: Controls whether the task only refreshes when low, forces a top-up,
    ///   or replaces the current device's one-time-key batch entirely.
    @discardableResult
    public func refreshMLKEMOneTimeKeysTask(policy: OneTimeKeyRefreshPolicy = .automatic) async -> Bool {
        if otkUploadCircuitOpen {
            if let openedAt = otkUploadCircuitOpenedAt,
               Date().timeIntervalSince(openedAt) < otkCircuitCooldownSeconds {
                let remaining = Int(otkCircuitCooldownSeconds - Date().timeIntervalSince(openedAt))
                logger.log(level: .info, message: "OTK upload circuit breaker open; skipping MLKEM refresh (\(remaining)s until probe)")
                return false
            }
            logger.log(level: .info, message: "OTK circuit breaker cooldown elapsed; allowing probe attempt for MLKEM keys")
        }

        // Coalesce concurrent refresh requests to avoid cancel/restart storms that
        // surface as URLSession cancellation errors (-999) under load.
        if policy != .automatic, let existingTask = refreshMLKEMOTKeysTask {
            _ = await existingTask.value
        } else if let existingTask = refreshMLKEMOTKeysTask {
            return await existingTask.value
        }

        refreshMLKEMOTKeysTask = Task(executorPreference: messagePipeline.keyTransportExecutor) { [weak self] in
            guard let self else { return false }
            let retryDelays: [UInt64] = [1_000_000_000, 3_000_000_000]
            for attempt in 0...retryDelays.count {
                do {
                    try await refreshOneTimeKeys(refreshType: .mlKEM, policy: policy)
                    await removeExpiredMLKEMOTKeys()
                    return true
                } catch let sessionError as PQSError where sessionError == .signingKeyMismatchWithServer {
                    await self.logger.log(level: .error, message: "Signing key mismatch detected during MLKEM OTK upload; opening circuit breaker and initiating recovery")
                    await self.openOTKUploadCircuitAndScheduleRecovery()
                    return false
                } catch let sessionError as PQSError where sessionError == .oneTimeKeyUploadFailed {
                    if attempt < retryDelays.count {
                        await logger.log(level: .warning, message: "MLKEM OTK upload failed (attempt \(attempt + 1)/\(retryDelays.count + 1)), retrying after backoff")
                        do {
                            try await Task.sleep(nanoseconds: retryDelays[attempt])
                        } catch {
                            return false
                        }
                    } else {
                        await logger.log(level: .error, message: "MLKEM OTK upload failed after \(attempt + 1) attempts")
                        await removeExpiredMLKEMOTKeys()
                        return false
                    }
                } catch {
                    await logger.log(level: .error, message: "Error refreshing one-time keys: \(error)")
                    await logger.log(level: .warning, message: "MLKEM one-time-key refresh failed; local/server state may remain out of sync")
                    await removeExpiredMLKEMOTKeys()
                    return false
                }
            }
            return false
        }
        return await refreshMLKEMOTKeysTask?.value ?? false
    }

    /// Replaces both published one-time-key batches (Curve25519 + ML-KEM) as a
    /// single-flight pair for inbound-recovery paths.
    ///
    /// Concurrent recovery episodes (multiple senders failing in the same backlog
    /// wave) must not each run their own delete/upload cycle: the server serializes
    /// writes to the user-configuration row and rejects overlapping cycles with a
    /// conflict (observed as HTTP 409 "concurrent user update" aborting recovery
    /// mid-flight). Joining the in-flight replacement is semantically equivalent —
    /// any completed replacement publishes a full fresh batch that satisfies every
    /// waiting episode.
    func replacePublishedOneTimeKeyBatchesForRecovery() async -> Bool {
        if let existing = otkBatchReplacementPairTask {
            return await existing.value
        }
        let pair = Task<Bool, Never> { [weak self] in
            guard let self else { return false }
            let x25519Replaced = await refreshOneTimeKeysTask(policy: .replacePublishedBatch)
            guard !Task.isCancelled else { return false }
            let mlKEMReplaced = await refreshMLKEMOneTimeKeysTask(policy: .replacePublishedBatch)
            return x25519Replaced && mlKEMReplaced
        }
        otkBatchReplacementPairTask = pair
        let result = await pair.value
        otkBatchReplacementPairTask = nil
        return result
    }

    /// - Parameter policy: Controls whether the device only tops up when low, always tops up to the
    ///   configured batch size, or replaces the current device's entire one-time-key batch.
    func refreshOneTimeKeys(refreshType: KeyKind, policy: OneTimeKeyRefreshPolicy = .automatic) async throws {
        guard await sessionContext != nil else { return }
        guard let cache else { return }
        if policy == .replaceCurrentDeviceBatch || policy == .replacePublishedBatch {
            try await replaceCurrentDeviceOneTimeKeys(
                cache: cache,
                refreshType: refreshType,
                retainLocalPrivateKeys: policy == .replacePublishedBatch)
            return
        }
        var keys = [UUID]()

        if let sessionContext = await sessionContext,
           let fetched = try await transportDelegate?.fetchOneTimeKeyIdentities(
            for: sessionContext.sessionUser.secretName,
            deviceId: sessionContext.sessionUser.deviceId.uuidString,
            type: refreshType
           ) {
            keys = fetched
        }

        if keys.isEmpty {
            logger.log(level: .warning, message: "No remote one-time key identities found for \(refreshType); regenerating local batch")
        }

        let publicKeysCount = try await synchronizeLocalKeys(cache: cache, keys: keys, type: refreshType)
        let shouldReplenish: Bool
        switch policy {
        case .automatic:
            shouldReplenish = publicKeysCount <= PQSSessionConstants.oneTimeKeyLowWatermark
        case .replenishBatch:
            shouldReplenish = true
        case .replaceCurrentDeviceBatch, .replacePublishedBatch:
            shouldReplenish = false
        }
        if shouldReplenish {
            // Identity inputs only. The new batch is merged into the *live* context after
            // the upload (`commitSessionContextMutation`), never written back from this
            // snapshot: the curve and ML-KEM refreshes run concurrently, and a snapshot
            // taken before the network round-trip would drop the sibling's committed
            // private keys while their publics are already on the server.
            let snapshot = try await currentSessionContext(cache: cache)
            let secretName = snapshot.sessionUser.secretName
            let deviceId = snapshot.sessionUser.deviceId
            let signingKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: snapshot.sessionUser.deviceKeys.signingPrivateKey)
            let keyPairsToCreate = max(0, PQSSessionConstants.oneTimeKeyBatchSize - publicKeysCount)

            logger.log(level: .info, message: "Creating Key Pairs, count: \(keyPairsToCreate)")
            switch refreshType {
            case .x25519:
                // Create needed key pairs
                let privateOneTimeKeyPairs: [KeyPair] = try (0 ..< keyPairsToCreate).map { _ in
                    let id = UUID()
                    let privateKey = crypto.generateCurve25519PrivateKey()
                    let privateKeyRep = try X25519PrivateKey(id: id, privateKey.rawRepresentation)
                    let publicKey = try X25519PublicKey(id: id, privateKey.publicKey.rawRepresentation)
                    return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
                }

                let signedOneTimePublicKeys: [UserConfiguration.SignedOneTimePublicKey] = try privateOneTimeKeyPairs.map { keyPair in
                    try UserConfiguration.SignedOneTimePublicKey(
                        key: keyPair.publicKey,
                        deviceId: deviceId,
                        signingKey: signingKey)
                }

                try await transportDelegate?.updateOneTimeKeys(
                    for: secretName,
                    deviceId: deviceId.uuidString,
                    keys: signedOneTimePublicKeys
                )

                try await commitSessionContextMutation(cache: cache) { context in
                    context.sessionUser.deviceKeys.oneTimePrivateKeys.append(contentsOf: privateOneTimeKeyPairs.map(\.privateKey))
                    context.activeUserConfiguration.signedOneTimePublicKeys.append(contentsOf: signedOneTimePublicKeys)
                }

            case .mlKEM:
                // Create needed key pairs
                let mlKEMOneTimeKeyPairs: [KeyPair] = try (0 ..< keyPairsToCreate).map { _ in
                    let id = UUID()
                    let privateKey = try crypto.generateMLKem1024PrivateKey()
                    let privateKeyRep = try MLKEMPrivateKey(id: id, privateKey.encode())
                    let publicKey = try MLKEMPublicKey(id: id, privateKey.publicKey.rawRepresentation)
                    return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
                }

                let signedMLKEMOneTimeKeys: [UserConfiguration.SignedMLKEMOneTimeKey] = try mlKEMOneTimeKeyPairs.map { keyPair in
                    try UserConfiguration.SignedMLKEMOneTimeKey(
                        key: keyPair.publicKey,
                        deviceId: deviceId,
                        signingKey: signingKey
                    )
                }

                try await transportDelegate?.updateOneTimeMLKEMKeys(
                    for: secretName,
                    deviceId: deviceId.uuidString,
                    keys: signedMLKEMOneTimeKeys
                )

                try await commitSessionContextMutation(cache: cache) { context in
                    context.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.append(contentsOf: mlKEMOneTimeKeyPairs.map(\.privateKey))
                    context.activeUserConfiguration.signedMLKEMOneTimePublicKeys.append(contentsOf: signedMLKEMOneTimeKeys)
                }
            }
        }
    }

    /// The live context when a session is active, otherwise the persisted one
    /// (store-only setups before `unlock`, and tests that seed the store directly).
    private func currentSessionContext(cache: SessionCache) async throws -> SessionContext {
        if let live = _sessionContext {
            return live
        }
        return try await decodePersistedSessionContext(cache: cache)
    }

    private func decodePersistedSessionContext(cache: SessionCache) async throws -> SessionContext {
        let data = try await cache.fetchLocalSessionContext()
        guard let decrypted = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionDecryptionError
        }
        return try BinaryDecoder().decode(SessionContext.self, from: decrypted)
    }

    /// Applies `mutate` to the live context and persists it as one exclusive commit
    /// (`commitLiveSessionContextMutation`). One-time-key workers of different kinds run
    /// concurrently and each awaits the network before committing; writing a pre-upload
    /// snapshot back would overwrite whatever a sibling committed in the meantime (its
    /// new private keys, its pruned publics), leaving the server advertising keys this
    /// device cannot open. Falls back to the persisted context only when no live session
    /// exists (store-only setups before `unlock`).
    @discardableResult
    private func commitSessionContextMutation(
        cache: SessionCache,
        _ mutate: (inout SessionContext) throws -> Void
    ) async throws -> SessionContext {
        if let live = try await commitLiveSessionContextMutation(mutate) {
            return live
        }

        var persisted = try await decodePersistedSessionContext(cache: cache)
        try mutate(&persisted)
        let encodedData = try BinaryEncoder().encode(persisted)
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encryptedConfig)
        return persisted
    }

    /// Replaces this device's one-time-key batch on the server.
    ///
    /// - Parameter retainLocalPrivateKeys: When `true` (recovery paths), existing local
    ///   private keys are kept so in-flight messages encrypted against the previous
    ///   batch can still decrypt; the retained pool is capped at
    ///   `PQSSessionConstants.retainedOneTimePrivateKeyCap` with oldest-first eviction.
    ///   When `false` (compromise rotation), the local private pool is wiped with the
    ///   published batch.
    private func replaceCurrentDeviceOneTimeKeys(
        cache: SessionCache,
        refreshType: KeyKind,
        retainLocalPrivateKeys: Bool = false
    ) async throws {
        guard let transportDelegate else {
            throw PQSError.transportNotInitialized
        }

        // Identity inputs only; the batch swap is merged into the live context after the
        // upload (see `commitSessionContextMutation`) so a concurrent refresh of the other
        // key kind is not overwritten by this pre-upload snapshot.
        let snapshot = try await currentSessionContext(cache: cache)
        let signingKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: snapshot.sessionUser.deviceKeys.signingPrivateKey
        )
        let secretName = snapshot.sessionUser.secretName
        let deviceId = snapshot.sessionUser.deviceId

        try await transportDelegate.batchDeleteOneTimeKeys(
            for: secretName,
            with: deviceId.uuidString,
            type: refreshType
        )

        switch refreshType {
        case .x25519:
            let privateOneTimeKeyPairs: [KeyPair] = try (0 ..< PQSSessionConstants.oneTimeKeyBatchSize).map { _ in
                let id = UUID()
                let privateKey = crypto.generateCurve25519PrivateKey()
                let privateKeyRep = try X25519PrivateKey(id: id, privateKey.rawRepresentation)
                let publicKey = try X25519PublicKey(id: id, privateKey.publicKey.rawRepresentation)
                return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
            }

            let signedOneTimePublicKeys: [UserConfiguration.SignedOneTimePublicKey] = try privateOneTimeKeyPairs.map { keyPair in
                try UserConfiguration.SignedOneTimePublicKey(
                    key: keyPair.publicKey,
                    deviceId: deviceId,
                    signingKey: signingKey
                )
            }

            try await transportDelegate.updateOneTimeKeys(
                for: secretName,
                deviceId: deviceId.uuidString,
                keys: signedOneTimePublicKeys
            )

            let updated = try await commitSessionContextMutation(cache: cache) { context in
                if !retainLocalPrivateKeys {
                    context.sessionUser.deviceKeys.oneTimePrivateKeys.removeAll()
                }
                context.activeUserConfiguration.signedOneTimePublicKeys.removeAll { $0.deviceId == deviceId }
                context.sessionUser.deviceKeys.oneTimePrivateKeys.append(contentsOf: privateOneTimeKeyPairs.map(\.privateKey))
                context.activeUserConfiguration.signedOneTimePublicKeys.append(contentsOf: signedOneTimePublicKeys)
                if retainLocalPrivateKeys {
                    let overflow = context.sessionUser.deviceKeys.oneTimePrivateKeys.count
                        - PQSSessionConstants.retainedOneTimePrivateKeyCap
                    if overflow > 0 {
                        context.sessionUser.deviceKeys.oneTimePrivateKeys.removeFirst(overflow)
                    }
                }
            }
            logger.log(level: .debug, message: "Replaced published curve OTK batch; count=\(signedOneTimePublicKeys.count) retainedPrivates=\(retainLocalPrivateKeys ? updated.sessionUser.deviceKeys.oneTimePrivateKeys.count : 0)")

        case .mlKEM:
            let mlKEMOneTimeKeyPairs: [KeyPair] = try (0 ..< PQSSessionConstants.oneTimeKeyBatchSize).map { _ in
                let id = UUID()
                let privateKey = try crypto.generateMLKem1024PrivateKey()
                let privateKeyRep = try MLKEMPrivateKey(id: id, privateKey.encode())
                let publicKey = try MLKEMPublicKey(id: id, privateKey.publicKey.rawRepresentation)
                return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
            }

            let signedMLKEMOneTimeKeys: [UserConfiguration.SignedMLKEMOneTimeKey] = try mlKEMOneTimeKeyPairs.map { keyPair in
                try UserConfiguration.SignedMLKEMOneTimeKey(
                    key: keyPair.publicKey,
                    deviceId: deviceId,
                    signingKey: signingKey
                )
            }

            try await transportDelegate.updateOneTimeMLKEMKeys(
                for: secretName,
                deviceId: deviceId.uuidString,
                keys: signedMLKEMOneTimeKeys
            )

            let updated = try await commitSessionContextMutation(cache: cache) { context in
                if !retainLocalPrivateKeys {
                    context.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.removeAll()
                }
                context.activeUserConfiguration.signedMLKEMOneTimePublicKeys.removeAll { $0.deviceId == deviceId }
                context.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.append(contentsOf: mlKEMOneTimeKeyPairs.map(\.privateKey))
                context.activeUserConfiguration.signedMLKEMOneTimePublicKeys.append(contentsOf: signedMLKEMOneTimeKeys)
                if retainLocalPrivateKeys {
                    let overflow = context.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.count
                        - PQSSessionConstants.retainedOneTimePrivateKeyCap
                    if overflow > 0 {
                        context.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.removeFirst(overflow)
                    }
                }
            }
            logger.log(level: .debug, message: "Replaced published MLKEM OTK batch; count=\(signedMLKEMOneTimeKeys.count) retainedPrivates=\(retainLocalPrivateKeys ? updated.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.count : 0)")
        }
    }

    func synchronizeLocalKeys(cache: SessionCache, keys: [UUID], type: KeyKind) async throws -> Int {
        let snapshot = try await currentSessionContext(cache: cache)
        let deviceId = snapshot.sessionUser.deviceId
        let secretName = snapshot.sessionUser.secretName
        let remoteKeySet = Set(keys)

        // Only prune the public key list to stop advertising keys the server
        // no longer holds (an empty server list prunes all of this device's publics).
        // Private keys are preserved — a consumed-on-server key means an in-flight
        // message needs the private counterpart for decryption. Private keys are
        // removed after use via updateOneTimeKey(remove:).
        //
        // The prune is applied to the live context, not written back from `snapshot`:
        // a concurrent refresh of the other key kind may commit its new private keys
        // between our read and our write.
        switch type {
        case .x25519:
            let currentDevicePublicKeys = snapshot.activeUserConfiguration.signedOneTimePublicKeys.filter { $0.deviceId == deviceId }
            guard currentDevicePublicKeys.contains(where: { !remoteKeySet.contains($0.id) }) else {
                return currentDevicePublicKeys.count
            }

            let updated = try await commitSessionContextMutation(cache: cache) { context in
                context.activeUserConfiguration.signedOneTimePublicKeys.removeAll {
                    $0.deviceId == deviceId && !remoteKeySet.contains($0.id)
                }
            }

            let remaining = updated.activeUserConfiguration.signedOneTimePublicKeys.filter { $0.deviceId == deviceId }
            if remaining.isEmpty {
                try await transportDelegate?.batchDeleteOneTimeKeys(for: secretName, with: deviceId.uuidString, type: type)
            }
            return remaining.count
        case .mlKEM:
            let currentDevicePublicKeys = snapshot.activeUserConfiguration.signedMLKEMOneTimePublicKeys.filter { $0.deviceId == deviceId }
            guard currentDevicePublicKeys.contains(where: { !remoteKeySet.contains($0.id) }) else {
                return currentDevicePublicKeys.count
            }

            let updated = try await commitSessionContextMutation(cache: cache) { context in
                context.activeUserConfiguration.signedMLKEMOneTimePublicKeys.removeAll {
                    $0.deviceId == deviceId && !remoteKeySet.contains($0.id)
                }
            }

            let remaining = updated.activeUserConfiguration.signedMLKEMOneTimePublicKeys.filter { $0.deviceId == deviceId }
            if remaining.isEmpty {
                try await transportDelegate?.batchDeleteOneTimeKeys(for: secretName, with: deviceId.uuidString, type: type)
            }
            return remaining.count
        }
    }

}

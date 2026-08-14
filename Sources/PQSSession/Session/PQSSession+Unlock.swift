//
//  PQSSession+Unlock.swift
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

/// User creation signing and `unlock`, including per-device signing-key
/// consistency checks.
extension PQSSession {
    /// Creates a new user configuration by signing device configurations and public keys.
    ///
    /// This asynchronous function takes a user configuration, a private signing key,
    /// a list of device configurations, and a list of public keys. It reconstructs the
    /// signing key, verifies the public signing key against the provided configuration,
    /// and signs each device configuration and public key with the private signing key.
    /// If any verification fails, an error is thrown.
    ///
    /// - Parameters:
    ///   - configuration: The initial user configuration containing the public signing key
    ///                    and a list of signed devices.
    ///   - signingPrivateKeyData: The raw data representation of the private signing key
    ///                            used for signing the device configurations and keys.
    ///   - devices: An array of `UserDeviceConfiguration` objects representing the devices
    ///              to be associated with the new user.
    ///   - keys: An array of `X25519PublicKey` objects representing the
    ///           public keys to be signed for the devices.
    ///
    /// - Throws:
    ///   - `PQSError.invalidSignature`: If the public signing key does
    ///     not match the reconstructed private signing key or if any device's signature
    ///     verification fails.
    ///
    /// - Returns: A new `UserConfiguration` object containing the public signing key,
    ///            signed device configurations, and signed public one-time keys.
    public func createNewUser(
        configuration: UserConfiguration,
        signingPrivateKeyData: Data,
        devices: [UserDeviceConfiguration],
        keys: [X25519PublicKey],
        mlKEMKeys: [MLKEMPublicKey]
    ) async throws -> UserConfiguration {
        // 1) Reconstruct your Curve25519 signing key
        let signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: signingPrivateKeyData
        )
        let signingPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: configuration.signingPublicKey)

        // Verify that the public signing key matches the reconstructed private signing key
        guard signingPublicKey.rawRepresentation == signingPrivateKey.publicKey.rawRepresentation else {
            throw PQSError.invalidSignature
        }

        // 2) Verify each signed device using the public signing key
        for device in configuration.signedDevices {
            if try (device.verified(using: signingPublicKey) != nil) == false {
                throw PQSError.invalidSignature
            }
        }

        // 3) For each device, build its SignedDeviceConfiguration
        let signedDevices: [UserConfiguration.SignedDeviceConfiguration] = try devices.map { device in
            try UserConfiguration.SignedDeviceConfiguration(
                device: device,
                signingKey: signingPrivateKey
            )
        }

        let activeDeviceIds = Set(devices.map(\.deviceId))
        let localDevice = devices.first {
            $0.signingPublicKey == signingPrivateKey.publicKey.rawRepresentation
        }
        let retainedSignedKeys = configuration.signedOneTimePublicKeys.filter { signedKey in
            activeDeviceIds.contains(signedKey.deviceId) && signedKey.deviceId != localDevice?.deviceId
        }
        let retainedSignedMLKEMKeys = configuration.signedMLKEMOneTimePublicKeys.filter { signedKey in
            activeDeviceIds.contains(signedKey.deviceId) && signedKey.deviceId != localDevice?.deviceId
        }

        let signedKeys: [UserConfiguration.SignedOneTimePublicKey]
        let signedMLKEMKeys: [UserConfiguration.SignedMLKEMOneTimeKey]
        if let localDevice {
            signedKeys = try retainedSignedKeys + keys.map { key in
                try UserConfiguration.SignedOneTimePublicKey(
                    key: key,
                    deviceId: localDevice.deviceId,
                    signingKey: signingPrivateKey
                )
            }
            signedMLKEMKeys = try retainedSignedMLKEMKeys + mlKEMKeys.map { key in
                try UserConfiguration.SignedMLKEMOneTimeKey(
                    key: key,
                    deviceId: localDevice.deviceId,
                    signingKey: signingPrivateKey
                )
            }
        } else {
            signedKeys = retainedSignedKeys
            signedMLKEMKeys = retainedSignedMLKEMKeys
        }

        var signedDeviceKeyBundles = configuration.signedDeviceKeyBundles.filter { signedBundle in
            devices.contains(where: { $0.deviceId == signedBundle.id })
        }
        if let localDevice {
            let localBundle = try UserConfiguration.SignedDeviceKeyBundle(
                bundle: .init(
                    deviceId: localDevice.deviceId,
                    longTermPublicKey: localDevice.longTermPublicKey,
                    finalMLKEMPublicKey: localDevice.finalMLKEMPublicKey
                ),
                signingKey: signingPrivateKey
            )
            signedDeviceKeyBundles.removeAll { $0.id == localDevice.deviceId }
            signedDeviceKeyBundles.append(localBundle)
        }

        // 4) Return the new account-signed membership plus device-owned key bundles.
        return UserConfiguration(
            signingPublicKey: signingPublicKey.rawRepresentation,
            signedDevices: signedDevices,
            signedOneTimePublicKeys: signedKeys,
            signedMLKEMOneTimePublicKeys: signedMLKEMKeys,
            signedDeviceKeyBundles: signedDeviceKeyBundles
        )
    }

    /// Starts a session using the provided application password.
    ///
    /// This method retrieves the local device salt, derives a symmetric key from the application password,
    /// and attempts to decrypt the local device configuration. If successful, it updates the last user
    /// configuration and returns a shared `PQSSession`.
    ///
    /// After ``shutdown()``, successful authentication also replaces the terminal
    /// task processor/ratchet manager and starts a new session work coordinator.
    /// Runtime revival happens only after the persisted context decrypts, so a
    /// wrong password cannot reopen a shut-down session.
    ///
    /// - Parameters:
    ///   - appPassword: The application password used for encryption and session management.
    /// - Returns: A `PQSSession` object representing the started session.
    /// - Throws: An error of type `PQSError` if the session start fails due to various reasons.
    public func unlock(appPassword: String) async throws -> PQSSession {
        await setAppPassword(appPassword)
        // Ensure the identity store is initialized
        guard let cache else {
            throw PQSError.databaseNotInitialized
        }

        // Retrieve the local device configuration
        let data = try await cache.fetchLocalSessionContext()

        // Convert the application password to Data
        guard let passwordData = appPassword.data(using: .utf8) else {
            throw PQSError.saltError
        }

        // Retrieve salt and derive symmetric key
        let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)

        // Derive the symmetric key from the password and salt - This is the AppSymmetricKey
        let symmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )

        do {
            // Decrypt the configuration data
            guard let configurationData = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else {
                throw PQSError.sessionDecryptionError
            }

            // Decode the session context from the decrypted data
            let sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)

            // Diagnostic-only per-device identity check. Logs (does not throw) when the
            // local `signingPrivateKey` does not match this device's `signingPublicKey` entry in
            // the cached `activeUserConfiguration.signedDevices`. The original write-master-key-
            // onto-child overwrite bug is prevented at the source by:
            //   1. `LinkedDeviceReprovisioningBundle` carrying no private signing material,
            //   2. `installLinkedDeviceReprovisioningBundle` rejecting bundles that re-attest us
            //      with a foreign per-device key,
            //   3. `DeviceKeys.signingPrivateKey` being `private(set)` so future code cannot
            //      silently overwrite it.
            // The startup check is kept as a non-fatal observer because legitimate transient
            // states (right after a fresh link, before the first `refreshIdentities`) can also
            // produce divergence and should not block the user from completing a re-link.
            checkPerDeviceSigningKeyConsistency(sessionContext: sessionContext)

            // Authentication succeeded. Only now revive runtime components so an
            // invalid password cannot reopen a shut-down session.
            try await reviveAfterShutdownIfNeeded()
            await beginSessionLifecycleIfNeeded()
            var migratedContext = sessionContext
            await setSessionContext(migratedContext)
            migratedContext = try await migratePersistedStoreIfNeeded(
                sessionContext: migratedContext,
                appSymmetricKey: symmetricKey)
            await setSessionContext(migratedContext)
            // `shutdown()` parks the processor before delegates/cache are released.
            // A successful context restore is the concrete restart event; if the
            // transport is already viable, unpark and drain durable jobs now.
            // Otherwise the next false → true viability transition owns the drain.
            if isViable {
                try await resumeJobQueue()
            }

            return self
        } catch {
            throw error
        }
    }

    /// Diagnostic-only per-device identity health check.
    ///
    /// Inspects the persisted `activeUserConfiguration` and the local `signingPrivateKey` and
    /// emits a warning log on every form of inconsistency we know how to spot. Never throws.
    /// The historical write-master-key-onto-child corruption is prevented at the source by the
    /// invariants documented in `unlock`; this runtime check exists only so we can see in
    /// the logs if a device ever drifts back into a divergent state.
    private func checkPerDeviceSigningKeyConsistency(sessionContext: SessionContext) {
        let accountKey: Curve25519.Signing.PublicKey
        do {
            accountKey = try Curve25519.Signing.PublicKey(
                rawRepresentation: sessionContext.activeUserConfiguration.signingPublicKey
            )
        } catch {
            logger.log(level: .warning, message: "Cached account signing public key is malformed; identity inspection skipped")
            return
        }

        let myDeviceId = sessionContext.sessionUser.deviceId
        guard let signedSelf = sessionContext.activeUserConfiguration.signedDevices.first(where: { $0.id == myDeviceId }) else {
            logger.log(level: .warning, message: "This device is missing from the cached signedDevices list; identity inspection skipped")
            return
        }

        let verifiedSelf: UserDeviceConfiguration?
        do {
            verifiedSelf = try signedSelf.verified(using: accountKey)
        } catch {
            verifiedSelf = nil
        }
        guard let verifiedSelf else {
            logger.log(level: .warning, message: "This device's signed entry fails verification under cached account key; identity inspection skipped")
            return
        }

        let localPublicKey: Data
        do {
            localPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey
            ).publicKey.rawRepresentation
        } catch {
            logger.log(level: .warning, message: "Local signing private key is unreadable; identity inspection skipped")
            return
        }

        if verifiedSelf.signingPublicKey != localPublicKey {
            logger.log(
                level: .warning,
                message: "Per-device signing key divergence detected: local key does not match this device's entry in signedDevices. This is non-fatal; investigate if peer signature verification fails downstream."
            )
        }
    }

}

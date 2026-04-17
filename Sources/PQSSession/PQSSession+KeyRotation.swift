//
//  PQSSession+KeyRotation.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-06-20.
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

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
import SessionModels

/// This should never be used in Production. PQS uses the NeedleTailLogger's debug loglevel which only logs under DEBUG mode. But for sanity we check for DEBUG also.
@inline(__always)
var shouldEmitKeyPayloadLogs: Bool {
    #if DEBUG
    return ProcessInfo.processInfo.environment["PQS_VERBOSE_KEY_LOGGING"] != nil
    #else
    return false
    #endif
}

/// Extension to `PQSSession` providing comprehensive key rotation and compromise recovery capabilities.
///
/// This extension implements both manual and automatic key rotation mechanisms to ensure long-term
/// security and provide recovery from potential key compromises. It handles both classical (Curve25519)
/// and post-quantum (MLKEM1024) key rotation with proper cryptographic verification and signing.
///
/// ## Key Rotation Types
///
/// - **Compromise Recovery**: Manual rotation of all keys when compromise is suspected
/// - **Automatic Rotation**: Scheduled rotation of MLKEM keys based on time intervals
/// - **Partial Rotation**: Rotation of specific key types while maintaining others
///
/// ## Security Features
///
/// - **Complete Key Replacement**: Rotates all cryptographic keys (Curve25519, MLKEM1024, signing)
/// - **Signed Device Configurations**: All rotated keys are properly signed and verified
/// - **Transport Integration**: Automatically publishes rotated keys to the transport layer
/// - **Session Context Updates**: Maintains consistency across all session data
///
/// ## Usage Examples
///
/// ```swift
/// // Manual rotation due to suspected compromise
/// try await session.rotateKeysOnPotentialCompromise()
///
/// // Automatic rotation check (called periodically)
/// let wasRotated = try await session.rotateMLKEMKeysIfNeeded()
/// ```
///
/// ## Important Notes
///
/// - Key rotation invalidates all existing sessions and requires re-establishment
/// - Recipients must manually verify new key fingerprints after rotation
/// - Automatic rotation only affects MLKEM keys, not signing or Curve25519 keys
/// - All rotation operations are atomic and either complete fully or fail completely

extension PQSSession {

    /// Rotates only this device's long-term and final MLKEM keys.
    ///
    /// Unlike `rotateKeysOnPotentialCompromise()`, this does not roll the account signing key.
    /// It is safe for linked (non-master) devices that need routine local key hygiene.
    public func rotateCurrentDeviceKeys() async throws {
        if keyLoadingState == .rotating {
            logger.log(level: .debug, message: "Key rotation already in progress, skipping duplicate device-only rotation request")
            return
        }
        logger.log(level: .debug, message: "Rotating current device keys")
        setKeyLoadingState(.rotating)
        do {
            var sessionContext = try await getSessionContext()

            let accountSigningPublicKeyData = sessionContext.activeUserConfiguration.signingPublicKey
            let accountSigningPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: accountSigningPublicKeyData)
            let accountSigningPrivateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey)
            
            guard accountSigningPublicKey.rawRepresentation == accountSigningPrivateKey.publicKey.rawRepresentation else {
                throw SessionErrors.signingKeyOutOfSync
            }

            guard let deviceIndex = sessionContext.activeUserConfiguration.signedDevices.firstIndex(where: { signed in
                guard let verified = try? signed.verified(using: accountSigningPublicKey) else { return false }
                return verified.deviceId == sessionContext.sessionUser.deviceId
            }) else {
                throw SessionErrors.invalidDeviceIdentity
            }
            guard var currentDevice = try sessionContext.activeUserConfiguration.signedDevices[deviceIndex]
                .verified(using: accountSigningPublicKey)
            else {
                throw SessionErrors.invalidSignature
            }

            let newLongTermPrivateKey = crypto.generateCurve25519PrivateKey()
            let newMLKEM = try crypto.generateMLKem1024PrivateKey()
            let mlKEMId = UUID()
            let newFinalMLKEMPrivateKey = try MLKEMPrivateKey(id: mlKEMId, newMLKEM.encode())
            let newFinalMLKEMPublicKey = try MLKEMPublicKey(id: mlKEMId, newMLKEM.publicKey.rawRepresentation)

            await currentDevice.updateLongTermPublicKey(newLongTermPrivateKey.publicKey.rawRepresentation)
            await currentDevice.updateFinalMLKEMPublicKey(newFinalMLKEMPublicKey)

            let reSignedCurrentDevice = try UserConfiguration.SignedDeviceConfiguration(
                device: currentDevice,
                signingKey: accountSigningPrivateKey)
            
            sessionContext.activeUserConfiguration.signedDevices[deviceIndex] = reSignedCurrentDevice
            sessionContext.sessionUser.deviceKeys.longTermPrivateKey = newLongTermPrivateKey.rawRepresentation
            sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey = newFinalMLKEMPrivateKey

            guard let transportDelegate else {
                throw SessionErrors.transportNotInitialized
            }
            let pskData = sessionContext.activeUserConfiguration.signingPublicKey
            let allDevices = sessionContext.activeUserConfiguration.signedDevices
            if allDevices.count > 1 {
                try await transportDelegate.publishRotatedKeys(
                    for: sessionContext.sessionUser.secretName,
                    deviceId: sessionContext.sessionUser.deviceId.uuidString,
                    rotated: .init(
                        pskData: pskData,
                        signedDevice: reSignedCurrentDevice,
                        allSignedDevices: allDevices))
            } else {
                try await transportDelegate.publishRotatedKeys(
                    for: sessionContext.sessionUser.secretName,
                    deviceId: sessionContext.sessionUser.deviceId.uuidString,
                    rotated: .init(
                        pskData: pskData,
                        signedDevice: reSignedCurrentDevice))
            }

            try await updateRotatedKeySessionContext(sessionContext: sessionContext)

            guard let cache else {
                throw SessionErrors.databaseNotInitialized
            }
            
            let databaseSymmetricKey = try await getDatabaseSymmetricKey()
            let allIdentities = try await cache.fetchSessionIdentities()
            var notifiedSecretNames = Set<String>()

            for identity in allIdentities {
                guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else { continue }
                guard props.secretName != sessionContext.sessionUser.secretName else { continue }
                guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
                guard notifiedSecretNames.insert(props.secretName).inserted else { continue }

                _ = try await emitSessionReestablishment(
                    kind: .peerRefresh,
                    recipient: .nickname(props.secretName),
                    scope: .peer(secretName: props.secretName)
                )
            }

            if let updatedContext = await self.sessionContext, !otkUploadCircuitOpen {
                if updatedContext.activeUserConfiguration.signedOneTimePublicKeys.count <= PQSSessionConstants.oneTimeKeyLowWatermark {
                    await refreshOneTimeKeysTask()
                }
                if updatedContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.count <= PQSSessionConstants.oneTimeKeyLowWatermark {
                    await refreshMLKEMOneTimeKeysTask()
                }
            } else if await self.sessionContext == nil {
                logger.log(level: .debug, message: "Unable to refresh one-time keys, SessionContext is nil")
            }

            setKeyLoadingState(.complete)
            logger.log(level: .debug, message: "Completed rotating current device keys")
        } catch {
            setKeyLoadingState(.complete)
            throw error
        }
    }

    /// Rotates all cryptographic keys when a potential compromise is suspected.
    ///
    /// This method performs a complete key rotation, replacing all cryptographic keys including
    /// Curve25519 long-term keys, MLKEM1024 MLKEM keys, and signing keys. It's designed for
    /// emergency situations where key compromise is suspected or confirmed.
    ///
    /// ## Rotation Process
    /// 1. **Key Generation**: Creates new Curve25519, MLKEM1024, and signing key pairs
    /// 2. **Device Configuration Update**: Updates the device configuration with new public keys
    /// 3. **Session Context Update**: Updates all session data with new private keys
    /// 4. **Transport Publication**: Publishes new keys to the transport layer for distribution
    /// 5. **Recipient Notification**: Notifies all contacts of the key rotation
    ///
    /// ## Security Implications
    ///
    /// - **Session Invalidation**: All existing sessions become invalid and must be re-established
    /// - **Contact Verification**: Recipients must manually verify new key fingerprints
    /// - **Communication Interruption**: Ongoing communications will be interrupted until re-establishment
    ///
    /// ## Usage Example
    /// ```swift
    /// // Call when compromise is suspected
    /// do {
    ///     try await session.rotateKeysOnPotentialCompromise()
    ///     print("Keys rotated successfully. Notify contacts to verify new fingerprints.")
    /// } catch {
    ///     print("Key rotation failed: \(error)")
    /// }
    /// ```
    ///
    /// - Throws:
    ///   - `SessionErrors.databaseNotInitialized` if the cache is not available
    ///   - `SessionErrors.sessionDecryptionError` if session context cannot be decrypted
    ///   - `SessionErrors.invalidDeviceIdentity` if device identity cannot be verified
    ///   - `SessionErrors.invalidSignature` if cryptographic verification fails
    ///   - `SessionErrors.sessionEncryptionError` if session context cannot be encrypted
    ///   - `SessionErrors.transportNotInitialized` if transport delegate is not set
    ///
    /// - Important: This operation is irreversible and will invalidate all existing sessions.
    ///   Ensure this is called only when compromise is genuinely suspected.
    /// - Note: After rotation, all contacts must manually verify the new key fingerprints
    ///   using the `fingerprint(from:_)` method before communication can resume.
    /// - Warning: This operation may take several seconds to complete due to cryptographic operations.
    /// - Important: Only the master device may perform full compromise rotation.
    public func rotateKeysOnPotentialCompromise() async throws {
        if keyLoadingState == .rotating {
            logger.log(level: .debug, message: "Key rotation already in progress, skipping duplicate rotation request")
            return
        }
        logger.log(level: .debug, message: "Rotating keys")
        setKeyLoadingState(.rotating)
        do {
            let longTerm = try createLongTermKeys()
            let mlKEMId = UUID()
            let mlKEMPrivateKey = try MLKEMPrivateKey(id: mlKEMId, longTerm.mlKem.encode())
            let mlKEMPublicKey = try MLKEMPublicKey(id: mlKEMId, longTerm.mlKem.publicKey.rawRepresentation)

            var sessionContext = try await getSessionContext()

            let oldSigningKeyData = sessionContext.activeUserConfiguration.signingPublicKey
            let oldSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: oldSigningKeyData)
            let oldSigningPrivateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey)
            
            guard let currentSignedDevice = sessionContext.activeUserConfiguration.signedDevices.first(where: { signed in
                guard let verified = try? signed.verified(using: oldSigningKey) else { return false }
                return verified.deviceId == sessionContext.sessionUser.deviceId
            }), let currentDevice = try? currentSignedDevice.verified(using: oldSigningKey) else {
                throw SessionErrors.invalidDeviceIdentity
            }
            guard currentDevice.isMasterDevice else {
                throw SessionErrors.compromiseRotationRequiresMasterDevice
            }
            
            var invalidServerDeviceIds: [UUID] = []
            var validServerDeviceIds: [UUID] = []
            var serverDeviceIds: [UUID] = []

            // Self device lists can be stale when another device was linked after this client registered.
            // For full compromise rotation we must re-sign every current device attestation, so load the
            // latest server bundle before rotating. Do not require `signingPublicKey == oldSigningKeyData`:
            // the top-level field can differ from locally cached `Data` while every `signedDevices` entry
            // still verifies under `oldSigningKey` — skipping merge in that case produced a single-device
            // PUT and `400 Multi-device key rotation requires batch signedDevices payload` on the server.
            if let transportDelegate {
                let latestConfiguration = try await transportDelegate.findConfiguration(for: sessionContext.sessionUser.secretName)
                
                let latestDevices = latestConfiguration.signedDevices
                serverDeviceIds = latestDevices.map(\.id)
                
                let verificationResults = latestDevices.map { signed in
                    let verifiedDevice = try? signed.verified(using: oldSigningKey)
                    return (id: signed.id, isValid: verifiedDevice != nil)
                }
                
                validServerDeviceIds = verificationResults.compactMap { $0.isValid ? $0.id : nil }
                invalidServerDeviceIds = verificationResults.compactMap { $0.isValid ? nil : $0.id }
                let allLatestVerify = !verificationResults.isEmpty && verificationResults.allSatisfy(\.isValid)
                let canAttemptMasterRescue = validServerDeviceIds.isEmpty
                    && serverDeviceIds.count > 1
                    && serverDeviceIds.contains(sessionContext.sessionUser.deviceId)
                
                if !validServerDeviceIds.contains(sessionContext.sessionUser.deviceId), !canAttemptMasterRescue {
                    logger.log(level: .error, message: "Rotation compromise aborted due to signing key divergence.")
                    throw PQSSession.SessionErrors.signingKeyOutOfSync
                }
                if allLatestVerify {
                    sessionContext.activeUserConfiguration.signedDevices = latestDevices
                }
                
            }

            guard sessionContext.activeUserConfiguration.signedDevices.contains(where: { signed in
                guard let verified = try? signed.verified(using: oldSigningKey) else { return false }
                return verified.deviceId == sessionContext.sessionUser.deviceId
            }) else {
                throw PQSSession.SessionErrors.invalidDeviceIdentity
            }

            // Re-sign every `SignedDeviceConfiguration` with the new account signing key so peers'
            // `refreshIdentities` can verify the bundle. Per the per-device identity invariant,
            // each linked device's inner `signingPublicKey` is preserved byte-for-byte —
            // we only swap the account-level wrapper signature. The current (master) entry is the
            // sole exception: master's per-device key is bound to the account key in this model,
            // so its `signingPublicKey` rotates alongside `longTerm.signing`. Linked devices
            // continue to sign their OTKs with their own unchanged per-device key, so their
            // server-side OTK uploads keep verifying through and after the rotation.
            var allReSigned: [UserConfiguration.SignedDeviceConfiguration] = []
            allReSigned.reserveCapacity(sessionContext.activeUserConfiguration.signedDevices.count)
            for signed in sessionContext.activeUserConfiguration.signedDevices {
                guard var peerDevice = try signed.verified(using: oldSigningKey) else {
                    throw SessionErrors.invalidSignature
                }
                if peerDevice.deviceId == sessionContext.sessionUser.deviceId {
                    await peerDevice.updateSigningPublicKey(longTerm.signing.publicKey.rawRepresentation)
                    await peerDevice.updateLongTermPublicKey(longTerm.curve.publicKey.rawRepresentation)
                    await peerDevice.updateFinalMLKEMPublicKey(mlKEMPublicKey)
                }
                allReSigned.append(try UserConfiguration.SignedDeviceConfiguration(device: peerDevice, signingKey: longTerm.signing))
            }

            sessionContext.sessionUser.deviceKeys.rotateAccountSigningKey(longTerm.signing.rawRepresentation)
            sessionContext.activeUserConfiguration.signingPublicKey = longTerm.signing.publicKey.rawRepresentation
            sessionContext.sessionUser.deviceKeys.longTermPrivateKey = longTerm.curve.rawRepresentation
            sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey = mlKEMPrivateKey
            sessionContext.activeUserConfiguration.signedDevices = allReSigned

            guard let transportDelegate else {
                throw SessionErrors.transportNotInitialized
            }

            // Publish to server *before* persisting local keys. If publish fails, local state stays unchanged
            // and we avoid the INVALIDDEVICECONFIGURATION mismatch (server has old keys, local has new).
            logger.log(level: .debug, message: "Publishing rotated keys to server")
            let pskData = longTerm.signing.publicKey.rawRepresentation
            guard let rotatingDeviceSigned = allReSigned.first(where: { $0.id == sessionContext.sessionUser.deviceId }) else {
                throw PQSSession.SessionErrors.invalidDeviceIdentity
            }
            let shouldUseCorruptionRecovery = allReSigned.count == 1
                && validServerDeviceIds == [sessionContext.sessionUser.deviceId]
                && !invalidServerDeviceIds.isEmpty
            var recovery: RotatedKeysRecovery?
            var recoveryPrunedDeviceIds: [UUID] = []
            if shouldUseCorruptionRecovery {
                recoveryPrunedDeviceIds = invalidServerDeviceIds
            } else if allReSigned.count == 1,
                      serverDeviceIds.count > 1,
                      serverDeviceIds.contains(sessionContext.sessionUser.deviceId) {
                // Failed/partial linking can leave local-only view diverged from server bundle.
                // In this case, try a recovery payload that prunes every non-self server device;
                // server still enforces exact invalid-id match before accepting.
                recoveryPrunedDeviceIds = serverDeviceIds.filter { $0 != sessionContext.sessionUser.deviceId }
            }
            if !recoveryPrunedDeviceIds.isEmpty {
                let authorization = RotatedKeysRecoveryAuthorization(
                    secretName: sessionContext.sessionUser.secretName,
                    recoveringDeviceId: sessionContext.sessionUser.deviceId,
                    newSigningPublicKey: pskData,
                    newSignedDeviceData: rotatingDeviceSigned.data,
                    prunedDeviceIds: recoveryPrunedDeviceIds)
                
                let authorizationData = authorization.canonicalSigningData()
                let signature = try oldSigningPrivateKey.signature(for: authorizationData)
                recovery = RotatedKeysRecovery(
                    recoveringDeviceId: sessionContext.sessionUser.deviceId,
                    prunedDeviceIds: recoveryPrunedDeviceIds,
                    oldAccountSignature: signature)
                
            }
            // Multiple PUTs each set `signingPublicKey` before every `signedDevices` entry is updated,
            // leaving the stored bundle unverifiable between requests. Batch when we have >1 device.
            if allReSigned.count > 1 {
                try await transportDelegate.publishRotatedKeys(
                    for: sessionContext.sessionUser.secretName,
                    deviceId: sessionContext.sessionUser.deviceId.uuidString,
                    rotated: .init(
                        pskData: pskData,
                        signedDevice: rotatingDeviceSigned,
                        allSignedDevices: allReSigned,
                        recovery: nil))
            } else {
                try await transportDelegate.publishRotatedKeys(
                    for: sessionContext.sessionUser.secretName,
                    deviceId: sessionContext.sessionUser.deviceId.uuidString,
                    rotated: .init(
                        pskData: pskData,
                        signedDevice: rotatingDeviceSigned,
                        recovery: recovery))
            }

            try await updateRotatedKeySessionContext(sessionContext: sessionContext)
            
            guard let cache else {
                throw SessionErrors.databaseNotInitialized
            }
     
            //Re-establish sessions for self and contacts. Channel recipients are in essences contacts we have a relationship with so sending to their individual nick is sufficient.
            _ = try await emitSessionReestablishment(
                kind: .linkedDeviceRepair,
                recipient: .personalMessage,
                scope: .personal
            )

            try await sendLinkedDeviceReprovisioningBundles(sessionContext: sessionContext)
            
            let databaseSymmetricKey = try await getDatabaseSymmetricKey()
            let allIdentities = try await cache.fetchSessionIdentities()
            var notifiedSecretNames = Set<String>()

            for identity in allIdentities {
                
                guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else { continue }
                // Skip our own identity and archived/inactive snapshot identities.
                guard props.secretName != sessionContext.sessionUser.secretName else { continue }
                guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
                guard notifiedSecretNames.insert(props.secretName).inserted else { continue }
                
                if shouldEmitKeyPayloadLogs {
                    logger.log(level: .debug, message: """
                        rotationReestablishment: recipient=\(props.secretName)\n
                        identityId=\(identity.id.uuidString)\n
                        remoteOTK=\(props.oneTimePublicKey?.id.uuidString ?? "nil")\n
                        remoteMLKEM=\(props.mlKEMPublicKey.id.uuidString)\n
                        contextId=\(props.sessionContextId)
                        """)
                }

                _ = try await emitSessionReestablishment(
                    kind: .peerRefresh,
                    recipient: .nickname(props.secretName),
                    scope: .peer(secretName: props.secretName)
                )
            }

            // Full compromise rotation changes the account signing key, so this device's existing
            // one-time keys must be replaced and re-signed, not merely topped up if low.
            let curveKeysReplaced = await refreshOneTimeKeysTask(policy: .replaceCurrentDeviceBatch)
            let mlKEMKeysReplaced = await refreshMLKEMOneTimeKeysTask(policy: .replaceCurrentDeviceBatch)
            guard curveKeysReplaced, mlKEMKeysReplaced else {
                throw SessionErrors.oneTimeKeyUploadFailed
            }
            
            setKeyLoadingState(.complete)
            logger.log(level: .debug, message: "Completed rotating keys")
        } catch {
            setKeyLoadingState(.complete)
            throw error
        }
    }
}

extension PQSSession {
    /// Automatically rotates MLKEM keys if the scheduled rotation date has passed.
    ///
    /// This method checks if the MLKEM keys need rotation based on the `rotateKeysDate` stored in
    /// the session context. Keys are rotated if the last rotation date is older than one week.
    /// This provides automatic key freshness without requiring manual intervention.
    ///
    /// ## Rotation Criteria
    /// - Keys are rotated if the last rotation date is ≥7 days old
    /// - Only MLKEM keys are rotated (Curve25519 and signing keys remain unchanged)
    /// - The rotation date is updated to the current date after successful rotation
    ///
    /// ## Usage Example
    /// ```swift
    /// // Call periodically (e.g., daily) to check for rotation
    /// let wasRotated = try await session.rotateMLKEMKeysIfNeeded()
    /// if wasRotated {
    ///     print("MLKEM keys were automatically rotated")
    /// } else {
    ///     print("MLKEM keys are still fresh")
    /// }
    /// ```
    ///
    /// - Returns: `true` if keys were rotated, `false` if rotation was not needed or not possible.
    /// - Throws:
    ///   - `SessionErrors.databaseNotInitialized` if the cache is not available
    ///   - `SessionErrors.sessionDecryptionError` if session context cannot be decrypted
    ///   - `SessionErrors.invalidDeviceIdentity` if device identity cannot be verified
    ///   - `SessionErrors.invalidSignature` if cryptographic verification fails
    ///   - `SessionErrors.sessionEncryptionError` if session context cannot be encrypted
    ///   - `SessionErrors.transportNotInitialized` if transport delegate is not set
    ///
    /// - Important: This method only rotates MLKEM keys, not Curve25519 or signing keys.
    ///   For complete key rotation, use `rotateKeysOnPotentialCompromise()`.
    /// - Note: The rotation date is automatically updated to the current date after successful rotation.
    /// - Performance: This method is lightweight and safe to call frequently.
    func rotateMLKEMKeysIfNeeded() async throws -> Bool {
        if let rotateKeyDate = await sessionContext?.sessionUser.deviceKeys.rotateKeysDate {
            // Get the current date
            let currentDate = Date()

            // Create a Calendar instance
            let calendar = Calendar.current

            // Calculate the date for key rotation based on the configured interval
            if let rotationDate = calendar.date(byAdding: .day, value: -PQSSessionConstants.keyRotationIntervalDays, to: currentDate) {
                // Check if rotateKeyDate is older than or equal to the rotation interval
                if rotateKeyDate <= rotationDate {
                    try await rotateMLKEMFinalKey()

                    guard let cache else {
                        throw SessionErrors.databaseNotInitialized
                    }
                    let data = try await cache.fetchLocalSessionContext()

                    let symmetricKey = try await getAppSymmetricKey()
                    guard let configurationData = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else {
                        throw SessionErrors.sessionDecryptionError
                    }

                    var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)
                    await sessionContext.sessionUser.deviceKeys.updateRotateKeysDate(Date())
                    try await updateRotatedKeySessionContext(sessionContext: sessionContext)
                    return true
                } else {
                    logger.log(level: .trace, message: "Not time to rotate keys")
                    return false
                }
            }
        }
        return false
    }
}

extension PQSSession {
    /// Installs a master-issued configuration update for this linked device.
    ///
    /// Bundles never carry signing private keys: each device's per-device signing key was
    /// generated locally during the link ceremony and remains immutable for the lifetime of
    /// its `DeviceID`. This call only refreshes the locally-cached `activeUserConfiguration`
    /// (new account-level signing public key + re-signed device list) so we can verify peers
    /// going forward. Our own `signingPrivateKey` is **not** touched.
    func installLinkedDeviceReprovisioningBundle(_ bundle: LinkedDeviceReprovisioningBundle) async throws {
        var sessionContext = try await getSessionContext()

        guard bundle.targetDeviceId == sessionContext.sessionUser.deviceId else {
            throw SessionErrors.invalidDeviceIdentity
        }

        let accountSigningKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: bundle.activeUserConfiguration.signingPublicKey
        )

        guard let ourSignedEntry = bundle.activeUserConfiguration.signedDevices.first(where: {
            $0.id == sessionContext.sessionUser.deviceId
        }) else {
            throw SessionErrors.invalidDeviceIdentity
        }
        guard let ourDevice = try ourSignedEntry.verified(using: accountSigningKey) else {
            throw SessionErrors.invalidSignature
        }

        // Invariant: the per-device signingPublicKey for this DeviceID must equal the
        // public half of our locally-held signingPrivateKey. If it does not, master tried to
        // re-attest us against a key that isn't ours — which would put us in the exact 996/OTK
        // mismatch state this fix was written to prevent. Reject and require a real re-link.
        let localSigningPublicKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey
        ).publicKey.rawRepresentation
        guard ourDevice.signingPublicKey == localSigningPublicKey else {
            logger.log(level: .error, message: "Reprovisioning bundle re-attests us with a foreign per-device signing key; refusing")
            throw SessionErrors.deviceIdentityCorrupted
        }

        sessionContext.activeUserConfiguration = bundle.activeUserConfiguration
        try await updateRotatedKeySessionContext(sessionContext: sessionContext)

        // Master pushed us a new account-level signing public key; defensively clear the
        // legacy OTK breaker / compromise episode so any in-flight retry isn't suppressed.
        clearCompromiseEpisode()
    }

    func localSigningKeyMatchesActiveConfiguration() async -> Bool {
        guard let context = await sessionContext else { return false }
        guard let signingPrivateKey = try? Curve25519.Signing.PrivateKey(
            rawRepresentation: context.sessionUser.deviceKeys.signingPrivateKey
        ) else {
            return false
        }
        return signingPrivateKey.publicKey.rawRepresentation == context.activeUserConfiguration.signingPublicKey
    }

    /// Recovers from a state where the local signing key diverges from what the server
    /// has stored in the device attestation blob.
    ///
    /// This typically happens when `rotateKeysOnPotentialCompromise()` successfully publishes
    /// new keys to the server but the local session-context persist fails (crash, disk error,
    /// app kill). The master device re-rotates to re-establish agreement; linked devices
    /// request reprovisioning from the master.
    func recoverFromSigningKeyMismatch() async throws {
        logger.log(level: .warning, message: "Beginning signing-key mismatch recovery")
        guard let transportDelegate else {
            throw SessionErrors.transportNotInitialized
        }

        let sessionContext = try await getSessionContext()
        let localSigningPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey
        )
        let localSigningPublicKeyData = localSigningPrivateKey.publicKey.rawRepresentation

        let serverConfig = try await transportDelegate.findConfiguration(
            for: sessionContext.sessionUser.secretName
        )
        let serverAccountKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: serverConfig.signingPublicKey
        )

        let serverDeviceSigned = serverConfig.signedDevices.first(where: {
            $0.id == sessionContext.sessionUser.deviceId
        })

        guard let serverDeviceSigned,
              let serverDevice = try? serverDeviceSigned.verified(using: serverAccountKey) else {
            logger.log(level: .error, message: "Device not verifiable on server during mismatch recovery; cannot self-heal")
            return
        }

        let serverDeviceSigningKeyData = serverDevice.signingPublicKey

        if serverDeviceSigningKeyData == localSigningPublicKeyData {
            logger.log(level: .info, message: "Signing keys match after server fetch; clearing breaker + compromise episode (transient issue)")
            clearCompromiseEpisode()
            return
        }

        logger.log(level: .warning, message: "Confirmed signing key divergence: local vs server device signing key differ")

        if serverDevice.isMasterDevice {
            logger.log(level: .info, message: "Master device detected; re-rotating keys to re-establish signing key agreement")
            otkUploadCircuitOpen = false
            otkUploadCircuitOpenedAt = nil
            try await rotateKeysOnPotentialCompromise()
            // Only reached on successful rotation; clear the episode so future legitimate
            // events are not silenced by the cooldown set during the failed run.
            clearCompromiseEpisode()
        } else {
            logger.log(level: .info, message: "Linked device detected; requesting reprovisioning from master")
            // Throttled emission: if a previous notification is already in-flight within the
            // configured cooldown, this is a no-op so we don't pile up compromise events
            // while the master is offline.
            _ = try await emitSessionReestablishment(
                kind: .linkedDeviceCompromiseObserved,
                recipient: .personalMessage,
                scope: .personal
            )
        }
    }
}

private extension PQSSession {
    func sendLinkedDeviceReprovisioningBundles(sessionContext: SessionContext) async throws {
        let verifiedDevices = try sessionContext.activeUserConfiguration.getVerifiedDevices()
        let childDeviceIds = verifiedDevices
            .filter { $0.deviceId != sessionContext.sessionUser.deviceId }
            .map(\.deviceId)

        for targetDeviceId in childDeviceIds {
            let bundle = LinkedDeviceReprovisioningBundle(
                activeUserConfiguration: sessionContext.activeUserConfiguration,
                issuedByDeviceId: sessionContext.sessionUser.deviceId,
                issuedAt: Date(),
                targetDeviceId: targetDeviceId
            )
            let metadata = try BinaryEncoder().encode(
                TransportEvent.linkedDeviceReprovisioning(bundle)
            )
            try await writeTextMessage(
                recipient: .personalMessage,
                transportInfo: metadata
            )
        }
    }

    func getSessionContext() async throws -> SessionContext {
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }

        let config = try await cache.fetchLocalSessionContext()

        let symmetricKey = try await getAppSymmetricKey()
        guard let configurationData = try crypto.decrypt(data: config, symmetricKey: symmetricKey) else {
            throw SessionErrors.sessionDecryptionError
        }

        return try BinaryDecoder().decode(SessionContext.self, from: configurationData)
    }

    func updateRotatedKeySessionContext(sessionContext: SessionContext) async throws {
        var sessionContext = sessionContext

        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }

        sessionContext.updateSessionUser(sessionContext.sessionUser)
        await setSessionContext(sessionContext)

        // Encrypt and persist
        let encodedData = try BinaryEncoder().encode(sessionContext)
        let symmetricKey = try await getAppSymmetricKey()
        guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: symmetricKey) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }

        try await cache.updateLocalSessionContext(encryptedConfig)
        logger.log(level: .debug, message: "Updated session context during key rotation")
    }

    func rotateMLKEMFinalKey() async throws {
        let mlKEM = try crypto.generateMLKem1024PrivateKey()

        var sessionContext = try await getSessionContext()

        let mlKEMId = UUID()
        let mlKEMPrivateKey = try MLKEMPrivateKey(id: mlKEMId, mlKEM.encode())
        let mlKEMPublicKey = try MLKEMPublicKey(id: mlKEMId, mlKEM.publicKey.rawRepresentation)

        sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey = mlKEMPrivateKey

        let signingKeyData = sessionContext.activeUserConfiguration.signingPublicKey
        let signingKey = try Curve25519.Signing.PublicKey(rawRepresentation: signingKeyData)
        let signingPrivateKeyData = sessionContext.sessionUser.deviceKeys.signingPrivateKey
        let signingPrivateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: signingPrivateKeyData)

        guard let index = sessionContext
            .activeUserConfiguration
            .signedDevices
            .firstIndex(where: { signed in
                guard let verified = try? signed.verified(using: signingKey) else { return false }
                return verified.deviceId == sessionContext.sessionUser.deviceId
            })
        else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }

        guard var device = try sessionContext.activeUserConfiguration.signedDevices[index]
            .verified(using: signingKey)
        else {
            throw SessionErrors.invalidSignature
        }

        await device.updateFinalMLKEMPublicKey(mlKEMPublicKey)
        let reSigned = try UserConfiguration.SignedDeviceConfiguration(device: device, signingKey: signingPrivateKey)
        sessionContext.activeUserConfiguration.signedDevices[index] = reSigned

        guard let transportDelegate else {
            throw SessionErrors.transportNotInitialized
        }

        // Publish to server *before* persisting local keys (same as rotateKeysOnPotentialCompromise).
        // IMPORTANT: `pskData` is the account attestation signing key used to verify signedDevices,
        // not necessarily the per-device signingPublicKey field inside a signed device payload.
        // Multi-device accounts require a batched `allSignedDevices` payload in one PUT (server 400 otherwise).
        let pskData = sessionContext.activeUserConfiguration.signingPublicKey
        let allDevices = sessionContext.activeUserConfiguration.signedDevices
        if allDevices.count > 1 {
            try await transportDelegate.publishRotatedKeys(
                for: sessionContext.sessionUser.secretName,
                deviceId: sessionContext.sessionUser.deviceId.uuidString,
                rotated: .init(
                    pskData: pskData,
                    signedDevice: reSigned,
                    allSignedDevices: allDevices
                ))
        } else {
            try await transportDelegate.publishRotatedKeys(
                for: sessionContext.sessionUser.secretName,
                deviceId: sessionContext.sessionUser.deviceId.uuidString,
                rotated: .init(pskData: pskData, signedDevice: reSigned)
            )
        }

        try await updateRotatedKeySessionContext(sessionContext: sessionContext)
    }
}

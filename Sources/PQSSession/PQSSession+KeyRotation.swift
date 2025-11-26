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

import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
import SessionModels

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
    public func rotateKeysOnPotentialCompromise() async throws {
        logger.log(level: .debug, message: "Rotating keys")
        await setRotatingKeys(true)
        do {
            let longTerm = try createLongTermKeys()
            let mlKEMId = UUID()
            let mlKEMPrivateKey = try MLKEMPrivateKey(id: mlKEMId, longTerm.mlKem.encode())
            let mlKEMPublicKey = try MLKEMPublicKey(id: mlKEMId, longTerm.mlKem.publicKey.rawRepresentation)

            var sessionContext = try await getSessionContext()

            let oldSigningKeyData = sessionContext.activeUserConfiguration.signingPublicKey
            let oldSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: oldSigningKeyData)

            guard let index = sessionContext
                .activeUserConfiguration
                .signedDevices
                .firstIndex(where: { signed in
                    guard let verified = try? signed.verified(using: oldSigningKey) else { return false }
                    return verified.deviceId == sessionContext.sessionUser.deviceId
                })
            else {
                throw PQSSession.SessionErrors.invalidDeviceIdentity
            }
            guard var device = try sessionContext.activeUserConfiguration.signedDevices[index]
                .verified(using: oldSigningKey)
            else {
                throw SessionErrors.invalidSignature
            }

            await device.updateSigningPublicKey(longTerm.signing.publicKey.rawRepresentation)
            await device.updateLongTermPublicKey(longTerm.curve.publicKey.rawRepresentation)
            await device.updateFinalMLKEMPublicKey(mlKEMPublicKey)

            let reSigned = try UserConfiguration.SignedDeviceConfiguration(device: device, signingKey: longTerm.signing)

            sessionContext.sessionUser.deviceKeys.signingPrivateKey = longTerm.signing.rawRepresentation
            sessionContext.activeUserConfiguration.signingPublicKey = longTerm.signing.publicKey.rawRepresentation
            sessionContext.sessionUser.deviceKeys.longTermPrivateKey = longTerm.curve.rawRepresentation
            sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey = mlKEMPrivateKey
            sessionContext.activeUserConfiguration.signedDevices[index] = reSigned

            try await updateRotatedKeySessionContext(sessionContext: sessionContext)

            logger.log(level: .debug, message: "Will publish rotated keys")
            // Send Public Keys to server
            try await transportDelegate?.publishRotatedKeys(
                for: sessionContext.sessionUser.secretName,
                deviceId: sessionContext.sessionUser.deviceId.uuidString,
                rotated: .init(pskData: device.signingPublicKey, signedDevice: reSigned))
            
            guard let cache else {
                throw SessionErrors.databaseNotInitialized
            }
     
            let metadata = try BinaryEncoder().encode(TransportEvent.sessionReestablishment)
            
            //Re-establish sessions for self and contacts. Channel recipients are in essences contacts we have a relationship with so sending to their individual nick is sufficient.
            try await writeTextMessage(
                recipient: .personalMessage,
                transportInfo: metadata)
            
            for secretName in try await cache
                .fetchContacts()
                .asyncMap(transform: { try? await $0.props(symmetricKey: getDatabaseSymmetricKey())?.secretName }) {
                guard let secretName else { continue }
                try await writeTextMessage(
                    recipient: .nickname(secretName),
                    transportInfo: metadata)
            }
            

            logger.log(level: .debug, message: "Completed rotating keys")
        } catch {
            await setRotatingKeys(false)
            throw error
        }
    }

    func setRotatingKeys(_ rotating: Bool) async {
        rotatingKeys = rotating
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

                    guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
                        throw SessionErrors.sessionDecryptionError
                    }

                    // Decode the session context from the decrypted data
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

private extension PQSSession {
    func getSessionContext() async throws -> SessionContext {
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }

        let config = try await cache.fetchLocalSessionContext()

        // Decrypt the session context data using the app's symmetric key
        guard let configurationData = try await crypto.decrypt(data: config, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }

        // Decode the session context from the decrypted data
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
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
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

        try await updateRotatedKeySessionContext(sessionContext: sessionContext)

        // Send Public Keys to server
        try await transportDelegate?.publishRotatedKeys(
            for: sessionContext.sessionUser.secretName,
            deviceId: sessionContext.sessionUser.deviceId.uuidString,
            rotated: .init(pskData: device.signingPublicKey, signedDevice: reSigned)
        )
    }
}

//
//  PQSSession+SessionIdentity.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-02-09.
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

/// Extension to `PQSSession` providing comprehensive session identity management and device discovery.
///
/// This extension handles the creation, management, and synchronization of session identities for
/// secure communication with other users. It implements the Double Ratchet protocol's identity
/// management requirements, including device discovery, key verification, and identity refresh.
///
/// ## Session Identity Components
///
/// Each session identity contains:
/// - **Long-term Curve25519 key** (SPKB): For persistent identity verification
/// - **Signing public key** (IKB): For message authentication
/// - **MLKEM public key** (PQSPKB): For post-quantum key exchange
/// - **One-time Curve25519 key** (OPKBₙ): For immediate communication
///
/// ## Identity Lifecycle
///
/// 1. **Creation**: New identities are created when discovering new devices
/// 2. **Verification**: All identities are cryptographically verified
/// 3. **Refresh**: Identities are refreshed to maintain current device state
/// 4. **Cleanup**: Stale identities are removed when devices are no longer available
///
/// ## Usage Examples
///
/// ```swift
/// // Refresh identities for a contact
/// let identities = try await session.refreshIdentities(secretName: "alice")
///
/// // Get existing identities
/// let existing = try await session.getSessionIdentities(with: "bob")
///
/// // Create new identity for a device
/// let identity = try await session.createEncryptableSessionIdentityModel(
///     with: deviceConfig,
///     oneTimePublicKey: oneTimeKey,
///     mlKEMPublicKey: mlKEMKey,
///     for: "alice",
///     associatedWith: deviceId,
///     new: sessionContextId
/// )
/// ```
///
/// ## Security Features
///
/// - **Cryptographic Verification**: All device configurations are verified using signing keys
/// - **Device Discovery**: Automatic discovery of new devices for contacts
/// - **Stale Identity Cleanup**: Removal of identities for devices no longer in use
/// - **Unique Device Names**: Automatic generation of unique device names to prevent conflicts
///
/// ## Important Notes
///
/// - Identities are automatically refreshed when needed for communication
/// - Device names are automatically made unique by appending numbers if needed
/// - Stale identities are automatically cleaned up during refresh operations
/// - All identity operations are performed asynchronously for performance

// MARK: - PQSSession Extension for Identity Management

public extension PQSSession {
    /// Creates a new encryptable session identity model for secure communication with a specific device.
    ///
    /// This method creates a `SessionIdentity` object that contains all the cryptographic information
    /// needed to establish secure communication with another device. The identity includes both classical
    /// (Curve25519) and post-quantum (MLKEM1024) keys for maximum security.
    ///
    /// ## Identity Components
    ///
    /// The created identity contains:
    /// - **Long-term Curve25519 key** (SPKB): For persistent identity verification
    /// - **Signing public key** (IKB): For message authentication and verification
    /// - **MLKEM public key** (PQSPKB): For post-quantum key exchange
    /// - **One-time Curve25519 key** (OPKBₙ): For immediate communication (optional)
    ///
    /// ## Usage Example
    /// ```swift
    /// let identity = try await session.createEncryptableSessionIdentityModel(
    ///     with: deviceConfiguration,
    ///     oneTimePublicKey: oneTimeKey,
    ///     mlKEMPublicKey: mlKEMKey,
    ///     for: "alice",
    ///     associatedWith: deviceId,
    ///     new: sessionContextId
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - device: The device configuration containing public keys and device metadata.
    ///   - oneTimePublicKey: Optional Curve25519 one-time pre-key for immediate communication.
    ///     If `nil`, the identity will be created without a one-time key.
    ///   - mlKEMPublicKey: The MLKEM1024 post-quantum signed pre-key for secure key exchange.
    ///   - secretName: The secret name of the user associated with this identity.
    ///   - deviceId: The unique identifier of the device this identity represents.
    ///   - sessionContextId: A unique context identifier for this session identity.
    ///
    /// - Returns: A newly created `SessionIdentity` object ready for secure communication.
    /// - Throws:
    ///   - `SessionErrors.databaseNotInitialized` if the cache is not available
    ///   - `SessionErrors.sessionNotInitialized` if the session is not properly initialized
    ///   - `SessionErrors.invalidSignature` if cryptographic operations fail
    ///
    /// - Important: The created identity is automatically stored in the cache and can be used
    ///   immediately for secure communication with the target device.
    /// - Note: Device names are automatically made unique if conflicts exist with existing identities.
    func createEncryptableSessionIdentityModel(
        with device: UserDeviceConfiguration,
        oneTimePublicKey: CurvePublicKey?,
        mlKEMPublicKey: MLKEMPublicKey,
        for secretName: String,
        associatedWith deviceId: UUID,
        new sessionContextId: Int
    ) async throws -> SessionIdentity {
        guard let cache else { throw PQSSession.SessionErrors.databaseNotInitialized }
        let determinedDeviceName = try await determineDeviceName()
        let deviceName = device.deviceName ?? determinedDeviceName

        let identity = try await SessionIdentity(
            id: UUID(),
            props: .init(
                secretName: secretName,
                deviceId: deviceId,
                sessionContextId: sessionContextId,
                longTermPublicKey: device.longTermPublicKey, // → SPKB
                signingPublicKey: device.signingPublicKey, // → IKB
                mlKEMPublicKey: mlKEMPublicKey, // → PQSPKB
                oneTimePublicKey: oneTimePublicKey, // → OPKBₙ
                state: nil,
                deviceName: deviceName,
                isMasterDevice: device.isMasterDevice
            ),
            symmetricKey: getDatabaseSymmetricKey()
        )
        try await cache.createSessionIdentity(identity)
        return identity
    }

    /// Determines a unique device name for the current device.
    /// This method checks existing device names and increments a count if necessary to ensure uniqueness.
    /// - Returns: A unique device name as a `String`.
    /// - Throws: An error if the device name determination fails.
    internal func determineDeviceName() async throws -> String {
        guard let cache else { return "Unknown Device" }
        var existingNames: [String] = []

        // Fetch existing device names
        for context in try await cache.fetchSessionIdentities() {
            guard let props = try await context.props(symmetricKey: getDatabaseSymmetricKey()) else { continue }
            existingNames.append(props.deviceName)
        }

        let baseName = getDeviceName() // e.g., "mac16"
        var count = 1
        var newDeviceName = baseName

        // Check for existing names and increment the count if necessary
        while existingNames.contains(newDeviceName) {
            newDeviceName = "\(baseName) (\(count))"
            count += 1
        }

        return newDeviceName.isEmpty ? "Unknown Device" : newDeviceName
    }

    /// Refreshes session identities for a specific user, ensuring they are up to date.
    ///
    /// This method performs a comprehensive refresh of session identities for the specified user,
    /// including device discovery, identity verification, and cleanup of stale identities. It ensures
    /// that all available devices for the user are represented by current, valid session identities.
    ///
    /// ## Refresh Process
    /// 1. **Device Discovery**: Fetches the latest user configuration from the transport layer
    /// 2. **Identity Verification**: Cryptographically verifies all device configurations
    /// 3. **New Identity Creation**: Creates identities for newly discovered devices
    /// 4. **Stale Identity Cleanup**: Removes identities for devices no longer available
    /// 5. **Key Synchronization**: Ensures one-time keys are available for new devices
    ///
    /// ## Usage Example
    /// ```swift
    /// // Normal refresh
    /// let identities = try await session.refreshIdentities(secretName: "alice")
    ///
    /// // Force refresh (ignores cache)
    /// let identities = try await session.refreshIdentities(secretName: "alice", forceRefresh: true)
    /// ```
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the user whose identities should be refreshed.
    ///   - forceRefresh: If `true`, forces a complete refresh ignoring cached state.
    ///     If `false`, may skip refresh if identities are already current.
    ///
    /// - Returns: An array of updated `SessionIdentity` objects for all available devices.
    /// - Throws:
    ///   - `SessionErrors.sessionNotInitialized` if the session is not properly initialized
    ///   - `SessionErrors.databaseNotInitialized` if the cache is not available
    ///   - `SessionErrors.transportNotInitialized` if the transport delegate is not set
    ///   - `SessionErrors.invalidSignature` if device verification fails
    ///   - `SessionErrors.drainedKeys` if one-time keys are not available
    ///
    /// - Important: This method automatically handles device discovery and key synchronization.
    ///   It should be called when establishing communication with a user or when device changes
    ///   are suspected.
    /// - Note: The method is idempotent and safe to call multiple times. It will only perform
    ///   work when necessary based on the `forceRefresh` parameter and current state.
    func refreshIdentities(
        secretName: String,
        createIdentity: Bool = true,
        forceRefresh: Bool = false,
        sendOneTimeIdentities: Bool = false
    ) async throws -> [SessionIdentity] {
        logger.log(level: .info, message: "LOOKING FOR \(secretName)")
        let existingIdentities = try await getSessionIdentities(with: secretName)
        logger.log(level: .info, message: "existingIdentities \(existingIdentities)")
        // Check if we have valid identities for this specific recipient
        let hasValidIdentities = await hasValidIdentitiesForRecipient(existingIdentities, secretName: secretName)
        
        // Extract synchronization keys if available
        let syncKeys = try await extractSynchronizationKeys()
        
        // Determine if refresh is needed
        let needsRefresh = forceRefresh || !hasValidIdentities
        
        if needsRefresh {
            do {
                return try await refreshSessionIdentities(
                    for: secretName,
                    from: existingIdentities,
                    createIdentity: createIdentity,
                    forceRefresh: forceRefresh,
                    sendOneTimeIdentities: sendOneTimeIdentities,
                    oneTime: syncKeys?.curveId,
                    oneTime: syncKeys?.mlKEMId
                )
            } catch {
                logger.log(level: .error, message: "Error in refreshIdentities for \(secretName): \(error)")
                return existingIdentities
            }
        } else {
            return existingIdentities
        }
    }

    /// Checks if there are valid identities for a specific recipient
    /// - Parameters:
    ///   - identities: Array of existing identities to check
    ///   - secretName: The secret name to validate against
    /// - Returns: True if valid identities exist for the recipient
    private func hasValidIdentitiesForRecipient(_ identities: [SessionIdentity], secretName: String) async -> Bool {
        for identity in identities {
            if let props = try? await identity.props(symmetricKey: getDatabaseSymmetricKey()),
               props.secretName == secretName {
                return true
            }
        }
        return false
    }
    
    /// Extracts synchronization keys from adding contact data if available
    /// - Returns: Optional tuple containing curve and mlKEM key IDs
    private func extractSynchronizationKeys() async throws -> (curveId: String?, mlKEMId: String?)? {
        guard let addingContactData else { return nil }
        
        let keys = try BinaryDecoder().decode(SynchronizationKeyIdentities.self, from: addingContactData)
        await setAddingContact(nil)
        
        return (curveId: keys.senderCurveId, mlKEMId: keys.senderMLKEMId)
    }
    
    /// Retrieves session identities associated with a specified recipient name.
    /// This method filters out identities that do not match the recipient name or are the current user's identities.
    /// - Parameter recipientName: The name of the recipient for which to retrieve identities.
    /// - Returns: An array of `SessionIdentity` objects associated with the recipient.
    /// - Throws: An error if the retrieval fails.
    func getSessionIdentities(with recipientName: String) async throws -> [SessionIdentity] {
        guard let sessionContext = await sessionContext else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        guard let cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }

        let identities = try await cache.fetchSessionIdentities()
        return await identities.asyncFilter { identity in
            do {
                let symmetricKey = try await getDatabaseSymmetricKey()
                guard let props = await identity.props(symmetricKey: symmetricKey) else { return false }
                // Check if the identity is not the current user's identity
                let myChildIdentity = props.secretName == sessionContext.sessionUser.secretName && props.deviceId != sessionContext.sessionUser.deviceId
                // Return true if the secret name matches the recipient name or if it's a different identity
                return (props.secretName == recipientName) || myChildIdentity
            } catch {
                return false
            }
        }
    }



    /// Refreshes the session identities for a specified recipient name based on the provided filtered identities.
    /// This method verifies the devices and removes any stale identities that are no longer valid.
    /// - Parameters:
    ///   - secretName: The name of the party for whom to refresh identities.
    ///   - filtered: An array of previously filtered `SessionIdentity` objects.
    /// - Returns: An updated array of `SessionIdentity` objects.
    /// - Throws: An error if the refresh operation fails.
    internal func refreshSessionIdentities(
        for secretName: String,
        from existingIdentities: [SessionIdentity],
        createIdentity: Bool = true,
        forceRefresh: Bool,
        sendOneTimeIdentities: Bool = false,
        oneTime curveId: String?,
        oneTime mlKEMId: String?
    ) async throws -> [SessionIdentity] {
        
        if let sessionContext = await sessionContext, sessionContext.activeUserConfiguration.signedOneTimePublicKeys.count <= 10 {
            await refreshOneTimeKeysTask()
        }
        if let sessionContext = await sessionContext, sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.count <= 10 {
            await refreshMLKEMOneTimeKeysTask()
        }
        
        var identities = existingIdentities
        guard let transportDelegate else {
            throw PQSSession.SessionErrors.transportNotInitialized
        }

        guard let sessionUser = await sessionContext?.sessionUser else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }

        let symmetricKey = try await getDatabaseSymmetricKey()
        
        if createIdentity, forceRefresh || sessionIdentities.isEmpty || !sessionIdentities.contains(secretName) {

            // Get the user configuration for the recipient
            let configuration = try await transportDelegate.findConfiguration(for: secretName)
            var verifiedDevices = try configuration.getVerifiedDevices()
            var collected = [UserDeviceConfiguration]()
            // Create a set of existing device IDs from the existing identities for quick lookup
            let existingDeviceIds = await Set(identities.asyncCompactMap {
                await $0.props(symmetricKey: symmetricKey)?.deviceId
            })

            for device in verifiedDevices {
                // Only collect devices that are not already in the existing identities
                if !existingDeviceIds.contains(device.deviceId), device.deviceId != sessionUser.deviceId {
                    collected.append(device)
                }
            }

            // Ensure that the identities of the user configuration are legitimate
            let signingPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: configuration.signingPublicKey)

            for device in configuration.signedDevices {
                if try (device.verified(using: signingPublicKey) != nil) == false {
                    throw PQSSession.SessionErrors.invalidSignature
                }
            }

            var generatedSessionContextIds = Set<Int>()
            for device in collected {
                // Check if the device ID is already in the existing identities
                if !existingDeviceIds.contains(device.deviceId), device.deviceId != sessionUser.deviceId {
                    var sessionContextId: Int
                    repeat {
                        sessionContextId = Int.random(in: 1 ..< Int.max)
                    } while generatedSessionContextIds.contains(sessionContextId)

                    generatedSessionContextIds.insert(sessionContextId)
                    
                    let (curve, mlKEM) = try await createOneTimeKeys(
                        secretName: secretName,
                        deviceId: device.deviceId,
                        curveId: curveId,
                        mlKEMId: mlKEMId,
                        configuration: configuration,
                        fetchOneTimeKeys: sendOneTimeIdentities)

                    let identity = try await createEncryptableSessionIdentityModel(
                        with: device,
                        oneTimePublicKey: curve,
                        mlKEMPublicKey: mlKEM,
                        for: secretName,
                        associatedWith: device.deviceId,
                        new: sessionContextId
                    )
                    logger.log(level: .info, message: "Created Session Identity: \(identity)")
                    identities.append(identity)

                    if let curveId = curve?.id {
                        try await notifyIdentityCreation(
                            for: secretName,
                            curveId: curveId.uuidString,
                            mlKEMId: mlKEM.id.uuidString)
                    }
                }
            }

            // This will get all identities that are the recipient name and a child device.
            let newfilter = try await getSessionIdentities(with: secretName)
            let newDeviceIds = await Set(newfilter.asyncCompactMap {
                await $0.props(symmetricKey: symmetricKey)?.deviceId
            })

            guard let myDevices = try await sessionContext?.activeUserConfiguration.getVerifiedDevices() else { return [] }
            verifiedDevices.append(contentsOf: myDevices)

            for deviceId in newDeviceIds {
                let isVerified = verifiedDevices.contains { verifiedDevice in
                    verifiedDevice.deviceId == deviceId
                }

                if !isVerified {
                    logger.log(level: .info, message: "Will remove stale session identity for recipient: \(secretName)")
                    // If our current list in the DB contains a session identity that is not in the master list, we need to remove it.
                    if let identityToRemove = await identities.asyncFirst(where: { element in
                        // Try to get the properties for each element.
                        guard let props = await element.props(symmetricKey: symmetricKey) else {
                            return false
                        }
                        // Compare the deviceIds; make sure deviceId is available in this scope.
                        return props.deviceId == deviceId
                    }) {
                        do {
                            try await cache?.deleteSessionIdentity(identityToRemove.id)
                            logger.log(level: .info, message: "Did remove stale session identity for recipient: \(secretName)")

                            // Remove the identity from the identities array.
                            if let index = identities.firstIndex(where: { identity in
                                identity.id == identityToRemove.id
                            }) {
                                identities.remove(at: index)
                            }
                        } catch {
                            logger.log(level: .warning, message: "Failed to delete stale session identity for recipient \(secretName): \(error)")
                        }
                    }
                }
            }

            
            for foundIdentity in await identities.asyncFilter( { await $0.props(symmetricKey: symmetricKey)?.secretName == secretName }) {
                guard var props = await foundIdentity.props(symmetricKey: symmetricKey) else {
                    continue
                }
                for device in verifiedDevices {
                    if props.deviceId == device.deviceId {
                        props.longTermPublicKey = device.longTermPublicKey
                    }
                }
                try await foundIdentity.updateIdentityProps(symmetricKey: symmetricKey, props: props)
                try await cache?.updateSessionIdentity(foundIdentity)
                if let index = identities.firstIndex(where: { $0.id == foundIdentity.id }) {
                    identities[index] = foundIdentity
                }
            }
            
            sessionIdentities.insert(secretName)
        }
        return identities
    }
    
    func createOneTimeKeys(
        secretName: String,
        deviceId: UUID,
        curveId: String?,
        mlKEMId: String?,
        configuration: UserConfiguration,
        fetchOneTimeKeys: Bool
    ) async throws -> (curve: CurvePublicKey?, mlKEM: MLKEMPublicKey){
        
        var curveId: String?
        var mlKEMId: String?
        
        let signingPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: configuration.signingPublicKey)
        
        guard let transportDelegate else {
            throw PQSSession.SessionErrors.transportNotInitialized
        }
        
            // On Contact Creation this will be false for the requester. The recipient will contained the passed identities, thus containing values.
        if fetchOneTimeKeys {
            let keys = try await transportDelegate.fetchOneTimeKeys(for: secretName, deviceId: deviceId.uuidString)
            curveId = keys.curve?.id.uuidString
            mlKEMId = keys.mlKEM?.id.uuidString
        }
        
        let curvePublicKey = try configuration.signedOneTimePublicKeys.first(where: { $0.id.uuidString == curveId })?.verified(using: signingPublicKey)

        var mlKEMPublicKey: MLKEMPublicKey
        if let signedKey = try configuration.signedMLKEMOneTimePublicKeys.first(where: { $0.id.uuidString == mlKEMId })?.verified(using: signingPublicKey) {
            mlKEMPublicKey = signedKey
        } else if let verifiedDevice = configuration.signedDevices.first(where: {
            (try? $0.verified(using: signingPublicKey))?.deviceId == deviceId
        }),
            let finalKey = try verifiedDevice.verified(using: signingPublicKey)?.finalMLKEMPublicKey
        {
            mlKEMPublicKey = finalKey
        } else {
            throw PQSSession.SessionErrors.drainedKeys
        }
        return (curvePublicKey, mlKEMPublicKey)
    }

    /// Notifies the network of identity creation with associated keys.
    ///
    /// Announces the creation of a new user identity along with their initial
    /// cryptographic keys. This allows other users to discover and establish
    /// communication with the new identity.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the newly created identity
    ///   - curveId: The initial one-time Curve Key Id associated with the new identity
    ///   - mlKEMId: The initial one-time MLKEM Key Id associated with the new identity
    /// - Throws: An error if the identity creation could not be notified
    private func notifyIdentityCreation(
        for secretName: String,
        curveId: String,
        mlKEMId: String
    ) async throws {
        let identityInfo = SynchronizationKeyIdentities(
            recipientCurveId: curveId,
            recipientMLKEMId: mlKEMId
        )
        let metadata = try BinaryEncoder().encode(TransportEvent.synchronizeOneTimeKeys(identityInfo))

        try await writeTextMessage(
            recipient: .nickname(secretName),
            text: "",
            transportInfo: metadata,
            metadata: metadata)
    }
}

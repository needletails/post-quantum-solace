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
import BinaryCodable
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
        // Hide inactive snapshot identities from normal identity refresh flows.
        let existingIdentities = try await getSessionIdentities(with: secretName)
        logger.log(level: .info, message: "existingIdentities \(existingIdentities.count)")
        // Check if we have valid identities for this specific recipient
        let hasValidIdentities = await hasValidIdentitiesForRecipient(existingIdentities, secretName: secretName)
        
        // Extract synchronization keys if available
        let syncKeys = try await extractSynchronizationKeys()
        
        // Determine if refresh is needed
        let needsRefresh = forceRefresh || !hasValidIdentities
        
        if needsRefresh {
            do {
                
                let refreshed = try await refreshSessionIdentities(
                    for: secretName,
                    from: existingIdentities,
                    createIdentity: createIdentity,
                    forceRefresh: forceRefresh,
                    sendOneTimeIdentities: sendOneTimeIdentities,
                    oneTime: syncKeys?.curveId,
                    oneTime: syncKeys?.mlKEMId)
                
                // Ensure we never return inactive snapshots.
                let symmetricKey = try await getDatabaseSymmetricKey()
                
                return await refreshed.asyncFilter { identity in
                    guard let props = await identity.props(symmetricKey: symmetricKey) else { return false }
                    return !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
                }
                
            } catch let sessionError as PQSSession.SessionErrors {
                // Do not silently mask critical verification/rotation failures; callers
                // need to react (e.g. force re-sync / re-link) instead of using stale identities.
                switch sessionError {
                case .invalidSignature, .signingKeyOutOfSync, .peerSigningKeyOutOfSync, .longTermKeyRotationFailed:
                    logger.log(level: .error, message: "Critical refreshIdentities failure for \(secretName): \(sessionError)")
                    throw sessionError
                default:
                    logger.log(level: .error, message: "Error in refreshIdentities for \(secretName): \(sessionError)")
                    return existingIdentities
                }
            } catch {
                logger.log(level: .error, message: "Error in refreshIdentities for \(secretName): \(error)")
                return existingIdentities
            }
        } else {
            return existingIdentities
        }
    }

    /// Chat fan-out: one active `SessionIdentity` per server-verified device.
    ///
    /// Refreshes when the local set is empty, contains devices absent from the verified
    /// snapshot, or is missing a verified device. Encrypt prepares initiating sessions
    /// for state-less rows — this helper does not run a second prep engine.
    func sessionIdentitiesForChatFanout(secretName: String) async throws -> [SessionIdentity] {
        guard let transportDelegate else {
            throw PQSSession.SessionErrors.transportNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        let existing = try await getSessionIdentities(with: secretName)

        let localActiveDeviceIds = await Set(existing.asyncCompactMap { identity -> UUID? in
            guard let props = await identity.props(symmetricKey: symmetricKey) else { return nil }
            guard props.secretName == secretName else { return nil }
            guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else {
                return nil
            }
            return props.deviceId
        })

        var verifiedIds: Set<UUID>
        if let cached = lastVerifiedDeviceIdsBySecretName[secretName], !cached.isEmpty {
            verifiedIds = cached
        } else {
            let configuration = try await transportDelegate.findConfiguration(for: secretName)
            try validateUserConfigurationSignatures(configuration)
            let verifiedDevices = try verifiedDevicesWithUsableKeyMaterial(
                in: configuration,
                secretName: secretName,
                source: "remote")
            verifiedIds = Set(verifiedDevices.map(\.deviceId))
            lastVerifiedDeviceIdsBySecretName[secretName] = verifiedIds
        }

        let hasDevicesAbsentFromVerified = !localActiveDeviceIds.isSubset(of: verifiedIds)
        let missingVerifiedDevices = !verifiedIds.isSubset(of: localActiveDeviceIds)
        let forceRefresh = existing.isEmpty
            || hasDevicesAbsentFromVerified
            || missingVerifiedDevices

        if forceRefresh {
            let configuration = try await transportDelegate.findConfiguration(for: secretName)
            try validateUserConfigurationSignatures(configuration)
            let verifiedDevices = try verifiedDevicesWithUsableKeyMaterial(
                in: configuration,
                secretName: secretName,
                source: "remote")
            verifiedIds = Set(verifiedDevices.map(\.deviceId))
            lastVerifiedDeviceIdsBySecretName[secretName] = verifiedIds
        }

        let refreshed = try await refreshIdentities(
            secretName: secretName,
            createIdentity: true,
            forceRefresh: forceRefresh,
            sendOneTimeIdentities: false)

        var byDevice: [UUID: SessionIdentity] = [:]
        for deviceId in verifiedIds {
            guard let identity = await taskProcessor.outboundSessionIdentity(
                secretName: secretName,
                deviceId: deviceId,
                in: refreshed,
                symmetricKey: symmetricKey,
                session: self,
                preferredDevice: nil
            ) else {
                continue
            }
            byDevice[deviceId] = identity
        }
        if byDevice.isEmpty, !verifiedIds.isEmpty {
            // The refreshed snapshot can go stale mid-flight: a concurrent lane
            // reset demotes the row this list contains while inserting its
            // replacement (the store itself always keeps ≥1 active row per lane
            // during a reset). Re-read the store once and re-select on live rows.
            let live = try await getSessionIdentities(with: secretName)
            for deviceId in verifiedIds {
                guard let identity = await taskProcessor.outboundSessionIdentity(
                    secretName: secretName,
                    deviceId: deviceId,
                    in: live,
                    symmetricKey: symmetricKey,
                    session: self,
                    preferredDevice: nil
                ) else {
                    continue
                }
                byDevice[deviceId] = identity
            }
        }
        let result = Array(byDevice.values)
        logger.log(
            level: .info,
            message: "Chat fan-out resolved \(result.count) device lane(s) for \(secretName) forceRefresh=\(forceRefresh)")
        return result
    }

    /// Removes local `SessionIdentity` rows whose device IDs are absent from `verifiedDeviceIds`.
    private func pruneStaleSessionIdentities(
        secretName: String,
        identities: inout [SessionIdentity],
        verifiedDeviceIds: Set<UUID>,
        symmetricKey: SymmetricKey
    ) async {
        let cachedIdentities: [SessionIdentity]
        if let fromCache = try? await getSessionIdentities(with: secretName) {
            cachedIdentities = fromCache
        } else {
            cachedIdentities = identities
        }

        let deviceIds = await Set(cachedIdentities.asyncCompactMap {
            await $0.props(symmetricKey: symmetricKey)?.deviceId
        })

        for deviceId in deviceIds where !verifiedDeviceIds.contains(deviceId) {
            logger.log(level: .info, message: "Will remove stale session identity for recipient: \(secretName)")
            let candidates = await cachedIdentities.asyncFilter { element in
                guard let props = await element.props(symmetricKey: symmetricKey) else { return false }
                return props.deviceId == deviceId
            }
            for identityToRemove in candidates {
                do {
                    try await cache?.deleteSessionIdentity(identityToRemove.id)
                    logger.log(level: .info, message: "Did remove stale session identity for recipient: \(secretName)")
                    DecryptFailureAuditLog.log(
                        "pqs.recovery.laneStalePruned peer=\(secretName) deviceId=\(deviceId.uuidString) verifiedDeviceCount=\(verifiedDeviceIds.count)")
                    identities.removeAll { $0.id == identityToRemove.id }
                } catch {
                    logger.log(
                        level: .warning,
                        message: "Failed to delete stale session identity for recipient \(secretName): \(error)")
                }
            }
        }
    }

    internal func refreshIdentitiesAssessingImpact(
        secretName: String,
        deviceId: UUID,
        createIdentity: Bool = true,
        forceRefresh: Bool = false,
        sendOneTimeIdentities: Bool = false
    ) async throws -> PeerIdentityRefreshAssessment {
        let symmetricKey = try await getDatabaseSymmetricKey()

        struct Snapshot: Sendable, Equatable {
            let signingPublicKey: Data
            let longTermPublicKey: Data
            let oneTimeKeyId: UUID?
            let mlKEMKeyId: UUID
        }

        func snapshot(
            from identities: [SessionIdentity]
        ) async -> Snapshot? {
            for identity in identities {
                guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
                guard props.secretName == secretName else { continue }
                guard props.deviceId == deviceId else { continue }
                guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
                return Snapshot(
                    signingPublicKey: props.signingPublicKey,
                    longTermPublicKey: props.longTermPublicKey,
                    oneTimeKeyId: props.oneTimePublicKey?.id,
                    mlKEMKeyId: props.mlKEMPublicKey.id
                )
            }
            return nil
        }

        let beforeIdentities = try await getSessionIdentities(with: secretName)
        let before = await snapshot(from: beforeIdentities)
        let refreshed = try await refreshIdentities(
            secretName: secretName,
            createIdentity: createIdentity,
            forceRefresh: forceRefresh,
            sendOneTimeIdentities: sendOneTimeIdentities
        )
        let after = await snapshot(from: refreshed)

        let impact: PeerIdentityRefreshImpact = {
            switch (before, after) {
            case (nil, nil):
                return .noSessionImpact
            case (nil, .some):
                return .freshSessionRecommended
            case (.some, nil):
                return .freshSessionRecommended
            case let (.some(before), .some(after)):
                if before.signingPublicKey != after.signingPublicKey
                    || before.longTermPublicKey != after.longTermPublicKey {
                    return .freshSessionRecommended
                }
                if before.oneTimeKeyId != after.oneTimeKeyId
                    || before.mlKEMKeyId != after.mlKEMKeyId {
                    return .resendRecommended
                }
                return .noSessionImpact
            }
        }()

        return PeerIdentityRefreshAssessment(
            identities: refreshed,
            impact: impact
        )
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

    /// Whether an established inbound ratchet exists for traffic from the given peer
    /// device (`props.state != nil`). A session-identity row alone is not enough: the
    /// OTK handshake packet must complete before friendship payloads can decrypt.
    func hasActiveInboundSessionIdentity(
        secretName: String,
        deviceId: UUID
    ) async -> Bool {
        guard let cache else { return false }
        do {
            let symmetricKey = try await getDatabaseSymmetricKey()
            let identities = try await cache.fetchSessionIdentities()
            for identity in identities {
                guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
                if props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) {
                    continue
                }
                if props.secretName == secretName,
                   props.deviceId == deviceId,
                   props.state != nil {
                    return true
                }
            }
            return false
        } catch {
            return false
        }
    }

    /// True while the local side is still completing the first inbound ratchet with a peer
    /// (outbound OTK notify in flight, or no established inbound state yet).
    func isAwaitingInboundPeerRatchetHandshake(
        secretName: String,
        deviceId: UUID
    ) async -> Bool {
        if addingContactData != nil {
            return true
        }
        return !(await hasActiveInboundSessionIdentity(
            secretName: secretName,
            deviceId: deviceId))
    }

    /// Whether outbound traffic to this peer can encrypt without a fresh OTK bootstrap.
    ///
    /// True when the bootstrap-target peer device (online / OTK-capable / master)
    /// has initialized outbound ratchet state. A session-identity row alone is not
    /// enough. Ghost master rows must not veto a live device that already has state.
    internal func hasInitializedOutboundRatchetForPeer(_ secretName: String) async throws -> Bool {
        let symmetricKey = try await getDatabaseSymmetricKey()
        let identities = try await getSessionIdentities(with: secretName)
        let preferredDeviceId = try await peerMasterDevice(for: secretName)?.deviceId

        if let preferredDeviceId {
            for identity in identities {
                guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
                guard props.secretName == secretName else { continue }
                guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
                if props.deviceId == preferredDeviceId {
                    return props.state != nil
                }
            }
            return false
        }

        var sawMasterRow = false
        var masterHasState = false
        var sawAnyActiveRow = false

        for identity in identities {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            guard props.secretName == secretName else { continue }
            guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }

            sawAnyActiveRow = true
            if props.isMasterDevice {
                sawMasterRow = true
                if props.state != nil {
                    masterHasState = true
                }
            }
        }

        if sawMasterRow {
            return masterHasState
        }

        guard sawAnyActiveRow else { return false }

        for identity in identities {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            guard props.secretName == secretName else { continue }
            guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
            if props.state != nil {
                return true
            }
        }
        return false
    }

    /// True when OTK bootstrap and first outbound sender init are still required for this peer.
    func peerNeedsOutboundBootstrap(_ secretName: String) async throws -> Bool {
        !(try await hasInitializedOutboundRatchetForPeer(secretName))
    }

    /// Clears stale peer identity rows and reconciliation cooldown before OTK bootstrap.
    ///
    /// Failed friendship attempts can leave state-less `SessionIdentity` rows in the DB.
    /// Encrypting on those rows hits `ratchet.stateUninitialized`, consumes the outbound
    /// repair cooldown, and suppresses the friendship packet — the same outcome as
    /// delete-contact + re-add, but without requiring user action.
    internal func preparePeerIdentitiesForOutboundBootstrap(
        secretName: String,
        forceHandshakeReplay: Bool = false
    ) async throws {
        guard let targetDevice = try await peerMasterDevice(for: secretName) else {
            return
        }

        clearOutboundReconciliationCooldown(
            secretName: secretName,
            deviceId: targetDevice.deviceId)

        let needsBootstrap = try await peerNeedsOutboundBootstrap(secretName)
        guard needsBootstrap || forceHandshakeReplay else { return }

        _ = try await resetSessionIdentityForFreshSession(
            secretName: secretName,
            deviceId: targetDevice.deviceId,
            sendOneTimeIdentities: false,
            reason: "friendshipOutboundBootstrap")

        logger.log(
            level: .info,
            message: forceHandshakeReplay
                ? "preparePeerIdentitiesForOutboundBootstrap: reset identity for \(secretName) deviceId=\(targetDevice.deviceId) to replay OTK notify on existing outbound row"
                : "preparePeerIdentitiesForOutboundBootstrap: reset state-less identity for \(secretName) deviceId=\(targetDevice.deviceId) before OTK notify")
    }

    /// Resets the peer master identity before an accept/reply OTK so the subsequent
    /// friendship packet does not encrypt on a stale inbound-only ratchet row.
    internal func preparePeerIdentitiesForFriendshipReply(secretName: String) async throws {
        guard let targetDevice = try await peerMasterDevice(for: secretName) else {
            return
        }

        clearOutboundReconciliationCooldown(
            secretName: secretName,
            deviceId: targetDevice.deviceId)

        _ = try await resetSessionIdentityForFreshSession(
            secretName: secretName,
            deviceId: targetDevice.deviceId,
            sendOneTimeIdentities: false,
            reason: "friendshipReplyPrepare")

        logger.log(
            level: .info,
            message: "preparePeerIdentitiesForFriendshipReply: reset peer identity for \(secretName) deviceId=\(targetDevice.deviceId) before accept OTK")
    }

    /// Sends OTK handshake notify while the peer row is still state-less so the peer can
    /// establish inbound decrypt before this device initializes its outbound sender ratchet.
    @discardableResult
    internal func deliverPeerHandshakeNotifyBeforeOutboundSenderInit(secretName: String) async throws -> Bool {
        guard let transportDelegate else {
            throw PQSSession.SessionErrors.transportNotInitialized
        }
        guard let targetDevice = try await peerMasterDevice(for: secretName) else {
            return false
        }

        let configuration = try await transportDelegate.findConfiguration(for: secretName)
        let symmetricKey = try await getDatabaseSymmetricKey()
        let identities = try await getSessionIdentities(with: secretName)
        guard let identity = await identities.asyncFirst(where: { candidate in
            guard let props = await candidate.props(symmetricKey: symmetricKey) else { return false }
            guard props.secretName == secretName, props.deviceId == targetDevice.deviceId else { return false }
            guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { return false }
            return props.state == nil
        }) else {
            logger.log(
                level: .warning,
                message: "deliverPeerHandshakeNotifyBeforeOutboundSenderInit: no state-less identity for \(secretName) deviceId=\(targetDevice.deviceId)")
            return false
        }

        guard var props = await identity.props(symmetricKey: symmetricKey) else { return false }
        if props.oneTimePublicKey == nil {
            try await attachPublishedPeerOneTimeKeys(
                to: &props,
                secretName: secretName,
                device: targetDevice,
                configuration: configuration)
            try await identity.updateIdentityProps(symmetricKey: symmetricKey, props: props)
            try await cache?.updateSessionIdentity(identity)
        }

        guard let recipientCurveId = props.oneTimePublicKey?.id.uuidString else {
            logger.log(
                level: .warning,
                message: "deliverPeerHandshakeNotifyBeforeOutboundSenderInit: no peer curve OTK for \(secretName) deviceId=\(targetDevice.deviceId)")
            throw PQSSession.SessionErrors.cannotFindOneTimeKey
        }

        let recipientMLKEMId = props.mlKEMPublicKey.id.uuidString
        try await notifyIdentityCreation(
            for: secretName,
            curveId: recipientCurveId,
            mlKEMId: recipientMLKEMId)
        logger.log(
            level: .info,
            message: "deliverPeerHandshakeNotifyBeforeOutboundSenderInit: sent OTK notify outbound to \(secretName) deviceId=\(targetDevice.deviceId)")
        return true
    }

    /// Returns the peer device that should own OTK / friendship bootstrap.
    ///
    /// Order of preference:
    /// 1. Host-reported online device (ISON) that can supply a curve OTK
    /// 2. Master-flagged device that can supply a curve OTK
    /// 3. Any peer device that can supply a curve OTK
    /// 4. Online device / master / first peer as a last resort
    ///
    /// Ghost devices left in published account configs after reinstall must not win
    /// over a live online peer — that is what broke delete→re-add.
    internal func peerMasterDevice(for secretName: String) async throws -> UserDeviceConfiguration? {
        guard let transportDelegate else {
            throw PQSSession.SessionErrors.transportNotInitialized
        }
        guard let sessionUser = await sessionContext?.sessionUser else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }

        let configuration = try await transportDelegate.findConfiguration(for: secretName)
        let devices = try configuration.getVerifiedDevices().map {
            try configuration.deviceWithCurrentKeyBundle($0)
        }
        let peerDevices = devices.filter { $0.deviceId != sessionUser.deviceId }
        guard !peerDevices.isEmpty else { return nil }

        let preferredOnlineId = await sessionDelegate?.preferredOnlinePeerDeviceId(for: secretName)
        if let preferredOnlineId,
           let online = peerDevices.first(where: { $0.deviceId == preferredOnlineId }),
           try await peerCanSupplyCurveOneTimeKey(
            secretName: secretName,
            deviceId: online.deviceId) {
            return online
        }

        let masters = peerDevices.filter(\.isMasterDevice)
        let masterCandidates = masters.isEmpty ? peerDevices : masters
        for device in masterCandidates {
            if try await peerCanSupplyCurveOneTimeKey(
                secretName: secretName,
                deviceId: device.deviceId) {
                return device
            }
        }

        for device in peerDevices {
            if try await peerCanSupplyCurveOneTimeKey(
                secretName: secretName,
                deviceId: device.deviceId) {
                return device
            }
        }

        if let preferredOnlineId,
           let online = peerDevices.first(where: { $0.deviceId == preferredOnlineId }) {
            return online
        }

        return masterCandidates.first
    }

    /// True when the peer still has at least one published curve OTK id on the server.
    internal func peerHasPublishedCurveOneTimeKey(
        secretName: String,
        deviceId: UUID
    ) async throws -> Bool {
        guard let transportDelegate else { return false }
        let curveIds = try await transportDelegate.fetchOneTimeKeyIdentities(
            for: secretName,
            deviceId: deviceId.uuidString,
            type: .curve)
        return !curveIds.isEmpty
    }

    /// True when the peer has a published curve OTK that can be verified from live configuration.
    internal func peerCanSupplyCurveOneTimeKey(
        secretName: String,
        deviceId: UUID
    ) async throws -> Bool {
        guard let transportDelegate else { return false }
        let configuration = try await transportDelegate.findConfiguration(for: secretName)
        let accountSigningPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: configuration.signingPublicKey)
        guard let accountSignedDevice = configuration.signedDevices.first(where: {
            (try? $0.verified(using: accountSigningPublicKey))?.deviceId == deviceId
        }),
              let verifiedDevice = try accountSignedDevice.verified(using: accountSigningPublicKey)
        else {
            return false
        }
        let device = try configuration.deviceWithCurrentKeyBundle(verifiedDevice)
        let curveIds = try await transportDelegate.fetchOneTimeKeyIdentities(
            for: secretName,
            deviceId: deviceId.uuidString,
            type: .curve)
        return try resolvePublishedCurveOneTimeKey(
            curveIds: curveIds,
            configuration: configuration,
            device: device) != nil
    }

    /// Creates a peer session-identity row when a contact exists but no encryptable row was cached yet.
    internal func ensurePeerSessionIdentityRow(for secretName: String) async throws {
        let identities = try await getSessionIdentities(with: secretName)
        guard identities.isEmpty else { return }
        logger.log(
            level: .info,
            message: "ensurePeerSessionIdentityRow: creating missing peer identity row for \(secretName)")
        _ = try await refreshIdentities(
            secretName: secretName,
            createIdentity: true,
            forceRefresh: false,
            sendOneTimeIdentities: false)
    }

    /// True when an active peer identity row can encrypt outbound control traffic.
    internal func peerHasEncryptableSessionForControl(
        secretName: String,
        deviceId: UUID
    ) async throws -> Bool {
        let symmetricKey = try await getDatabaseSymmetricKey()
        let identities = try await getSessionIdentities(with: secretName)
        for identity in identities {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            guard props.deviceId == deviceId, props.state != nil else { continue }
            return true
        }
        return false
    }

    /// Deletes every active and archived session-identity row for a peer and clears handshake state.
    ///
    /// Call from contact removal so re-adding the same peer starts from a clean cryptographic slate.
    func wipePeerRelationshipState(secretName: String) async throws {
        guard let cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        let identities = try await cache.fetchSessionIdentities()
        var deletedCount = 0
        for identity in identities {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            guard props.secretName == secretName else { continue }
            try await cache.deleteSessionIdentity(identity.id)
            deletedCount += 1
        }
        clearPeerTransientState(secretName: secretName)
        logger.log(
            level: .info,
            message: "wipePeerRelationshipState: removed \(deletedCount) session identity row(s) and transient handshake state for \(secretName)")
        DecryptFailureAuditLog.log(
            "pqs.recovery.laneWiped peer=\(secretName) deletedRows=\(deletedCount)")
    }

    /// Waits briefly for the peer to replenish published OTKs. Returns whether keys are available.
    internal func awaitPeerReplenishCompletion(
        secretName: String,
        deviceId: UUID,
        maxWait: TimeInterval? = nil
    ) async -> Bool {
        let waitBudget = maxWait ?? peerOneTimeReplenishWaitTimeout
        if (try? await peerCanSupplyCurveOneTimeKey(secretName: secretName, deviceId: deviceId)) == true {
            return true
        }
        if peerOneTimeReplenishAcknowledgedPeers.remove(secretName) != nil {
            if (try? await peerCanSupplyCurveOneTimeKey(secretName: secretName, deviceId: deviceId)) == true {
                return true
            }
        }

        let timeoutTask = Task { [secretName, deviceId, waitBudget] in
            try await Task.sleep(nanoseconds: UInt64(waitBudget * 1_000_000_000))
            await self.cancelPeerOneTimeReplenishWait(secretName: secretName, deviceId: deviceId)
        }
        defer { timeoutTask.cancel() }

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            peerOneTimeReplenishWaiters[secretName] = continuation
        }

        return (try? await peerCanSupplyCurveOneTimeKey(secretName: secretName, deviceId: deviceId)) == true
    }

    internal func cancelPeerOneTimeReplenishWait(secretName: String, deviceId: UUID) async {
        guard let waiter = peerOneTimeReplenishWaiters.removeValue(forKey: secretName) else { return }
        waiter.resume()
    }

    internal func completePeerPublishedOneTimeKeysReplenishmentWait(secretName: String) {
        if let waiter = peerOneTimeReplenishWaiters.removeValue(forKey: secretName) {
            waiter.resume()
        } else {
            peerOneTimeReplenishAcknowledgedPeers.insert(secretName)
        }
    }

    /// Ensures this device has published curve and ML-KEM one-time keys on the server.
    /// Call after the transport/API path is viable (e.g. IRC `registered("true")`).
    func ensurePublishedOneTimeKeysOnServerIfNeeded() async {
        guard isViable else {
            logger.log(
                level: .info,
                message: "ensurePublishedOneTimeKeysOnServerIfNeeded: deferring until session transport is viable")
            return
        }
        guard let transportDelegate, let sessionContext = await sessionContext else { return }
        let secretName = sessionContext.sessionUser.secretName
        let deviceId = sessionContext.sessionUser.deviceId.uuidString
        do {
            let curveIds = try await transportDelegate.fetchOneTimeKeyIdentities(
                for: secretName,
                deviceId: deviceId,
                type: .curve)
            let mlKEMIds = try await transportDelegate.fetchOneTimeKeyIdentities(
                for: secretName,
                deviceId: deviceId,
                type: .mlKEM)
            if curveIds.isEmpty || mlKEMIds.isEmpty {
                logger.log(
                    level: .info,
                    message: "ensurePublishedOneTimeKeysOnServerIfNeeded: server pool empty; replenishing for \(secretName)")
                async let curveRefresh = refreshOneTimeKeysTask(policy: .replenishBatch)
                async let mlKEMRefresh = refreshMLKEMOneTimeKeysTask(policy: .replenishBatch)
                _ = await (curveRefresh, mlKEMRefresh)
            }
        } catch {
            logger.log(
                level: .warning,
                message: "ensurePublishedOneTimeKeysOnServerIfNeeded failed for \(secretName): \(error)")
        }
    }

    /// Acknowledges that this device finished uploading a published OTK replenish batch.
    internal func ackPublishedOneTimeKeysReplenished(to secretName: String) async throws {
        let metadata = try BinaryEncoder().encode(TransportEvent.publishedOneTimeKeysReplenished)
        logger.log(
            level: .info,
            message: "ackPublishedOneTimeKeysReplenished: notifying \(secretName) that published one-time keys were replenished")
        try await writeTextMessage(
            recipient: .nickname(secretName),
            transportInfo: metadata)
        await waitForOutboundJobDrain()
    }

    /// Repair-only: asks the peer to replenish when accept bootstrap needs a published OTK.
    internal func repairPeerPublishedOneTimeKeysIfPossible(
        secretName: String,
        deviceId: UUID
    ) async throws {
        guard try await !peerCanSupplyCurveOneTimeKey(secretName: secretName, deviceId: deviceId) else {
            return
        }
        guard try await peerHasEncryptableSessionForControl(
            secretName: secretName,
            deviceId: deviceId) else {
            logger.log(
                level: .warning,
                message: "repairPeerPublishedOneTimeKeysIfPossible: cannot request OTK replenish for \(secretName); no encryptable peer session row")
            return
        }
        try await requestPeerToReplenishPublishedOneTimeKeys(secretName: secretName)
        _ = await awaitPeerReplenishCompletion(secretName: secretName, deviceId: deviceId)
    }

    /// Asks the peer to upload a fresh published OTK batch before accept bootstrap retries.
    /// Uses the current session row so the control packet can encrypt before identity reset.
    internal func requestPeerToReplenishPublishedOneTimeKeys(secretName: String) async throws {
        let now = Date()
        if let last = lastPeerOneTimeRefreshRequestAt[secretName],
           now.timeIntervalSince(last) < peerOneTimeRefreshRequestCooldown {
            logger.log(
                level: .info,
                message: "requestPeerToReplenishPublishedOneTimeKeys: skipping duplicate refresh request for \(secretName)")
            return
        }
        lastPeerOneTimeRefreshRequestAt[secretName] = now

        let metadata = try BinaryEncoder().encode(TransportEvent.refreshOneTimeKeys)
        logger.log(
            level: .info,
            message: "requestPeerToReplenishPublishedOneTimeKeys: asking \(secretName) to replenish published one-time keys")
        try await writeTextMessage(
            recipient: .nickname(secretName),
            transportInfo: metadata)
        await waitForOutboundJobDrain()
        logger.log(
            level: .info,
            message: "requestPeerToReplenishPublishedOneTimeKeys: refresh control queued for \(secretName)")
    }

    /// Resolves peer OTK material from the published pool without consuming server keys.
    internal func attachPublishedPeerOneTimeKeys(
        to props: inout SessionIdentity.UnwrappedProps,
        secretName: String,
        device: UserDeviceConfiguration,
        configuration: UserConfiguration
    ) async throws {
        guard let transportDelegate else {
            throw PQSSession.SessionErrors.transportNotInitialized
        }

        let curveIds = try await transportDelegate.fetchOneTimeKeyIdentities(
            for: secretName,
            deviceId: device.deviceId.uuidString,
            type: .curve)
        if let signedCurve = try resolvePublishedCurveOneTimeKey(
            curveIds: curveIds,
            configuration: configuration,
            device: device) {
            props.oneTimePublicKey = signedCurve
        } else {
            props.oneTimePublicKey = nil
        }

        let mlKEMIds = try await transportDelegate.fetchOneTimeKeyIdentities(
            for: secretName,
            deviceId: device.deviceId.uuidString,
            type: .mlKEM)
        let deviceSigningPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: device.signingPublicKey)
        if let signedMLKEM = try resolvePublishedMLKEMOneTimeKey(
            mlKEMIds: mlKEMIds,
            configuration: configuration,
            deviceSigningPublicKey: deviceSigningPublicKey) {
            props.mlKEMPublicKey = signedMLKEM
        } else {
            props.mlKEMPublicKey = device.finalMLKEMPublicKey
        }
    }

    private func resolvePublishedCurveOneTimeKey(
        curveIds: [UUID],
        configuration: UserConfiguration,
        device: UserDeviceConfiguration
    ) throws -> CurvePublicKey? {
        let deviceSigningPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: device.signingPublicKey)
        for curveId in curveIds.reversed() {
            if let signedCurve = try configuration.signedOneTimePublicKeys
                .first(where: { $0.id == curveId })?
                .verified(using: deviceSigningPublicKey) {
                return signedCurve
            }
        }
        return nil
    }

    private func resolvePublishedMLKEMOneTimeKey(
        mlKEMIds: [UUID],
        configuration: UserConfiguration,
        deviceSigningPublicKey: Curve25519.Signing.PublicKey
    ) throws -> MLKEMPublicKey? {
        for mlKEMId in mlKEMIds.reversed() {
            if let signedMLKEM = try configuration.signedMLKEMOneTimePublicKeys
                .first(where: { $0.id == mlKEMId })?
                .verified(using: deviceSigningPublicKey) {
                return signedMLKEM
            }
        }
        return nil
    }

    /// Returns the active (non-archived) session identity used for outbound traffic
    /// to one peer device, refreshing identities when none is cached yet.
    internal func activeSessionIdentityForPeer(
        secretName: String,
        deviceId: UUID,
        sendOneTimeIdentities: Bool = false
    ) async throws -> SessionIdentity {
        let symmetricKey = try await getDatabaseSymmetricKey()

        func matchingIdentity(in identities: [SessionIdentity]) async -> SessionIdentity? {
            for identity in identities {
                guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
                if props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) {
                    continue
                }
                if props.secretName == secretName, props.deviceId == deviceId {
                    return identity
                }
            }
            return nil
        }

        var identities = try await getSessionIdentities(with: secretName)
        if let identity = await matchingIdentity(in: identities) {
            return identity
        }

        _ = try await refreshIdentities(
            secretName: secretName,
            forceRefresh: true,
            sendOneTimeIdentities: sendOneTimeIdentities)
        identities = try await getSessionIdentities(with: secretName)
        guard let identity = await matchingIdentity(in: identities) else {
            throw PQSSession.SessionErrors.missingSessionIdentity
        }
        return identity
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
                // Never surface inactive snapshot identities to callers.
                if props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) { return false }
                // Never surface this device's own identity as a recipient row.
                if props.deviceId == sessionContext.sessionUser.deviceId { return false }
                return props.secretName == recipientName
            } catch {
                return false
            }
        }
    }



    /// Fetches archived (inactive) session identities for a specific peer device, sorted newest-first.
    ///
    /// Unlike `getSessionIdentities` and `refreshIdentities`, this method returns **only** rows
    /// that carry the `inactiveSessionDeviceNamePrefix`. These are ratchet-state snapshots preserved
    /// during compromise recovery so that delayed in-flight messages encrypted under the old epoch
    /// can still be decrypted.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the peer whose archived identities should be fetched.
    ///   - deviceId: The device ID to filter on.
    /// - Returns: Archived `SessionIdentity` rows sorted by `sessionContextId` descending (newest first).
    internal func fetchArchivedSessionIdentities(
        secretName: String,
        deviceId: UUID
    ) async throws -> [SessionIdentity] {
        guard let cache else { return [] }
        let symmetricKey = try await getDatabaseSymmetricKey()
        let all = try await cache.fetchSessionIdentities()

        struct Ranked: Sendable {
            let identity: SessionIdentity
            let contextId: Int
        }

        var ranked = [Ranked]()
        for identity in all {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            guard props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
            guard props.secretName == secretName, props.deviceId == deviceId else { continue }
            ranked.append(Ranked(identity: identity, contextId: props.sessionContextId))
        }

        ranked.sort { $0.contextId > $1.contextId }
        return ranked.map(\.identity)
    }

    /// Ensures one state-less Active exists for inbound try-all on this device.
    ///
    /// Inbound decrypt tries sessions for this peer device. Sender orphan remint
    /// encrypts on a new initiating SessionIdentity; receiver PQXDH
    /// (`recipientInitialization` → `setState`) only runs when `state == nil`.
    /// Call this only when the peer device has no blank Active yet — the slot
    /// is part of the try-all set, not a post-failure matching recovery mint.
    /// Do not demote siblings here; activate after proven decrypt.
    internal func ensureInboundInitiatingSessionIdentity(
        secretName: String,
        deviceId: UUID,
        longTermPublicKey: Data,
        signingPublicKey: Data,
        oneTimePublicKey: CurvePublicKey?,
        mlKEMPublicKey: MLKEMPublicKey,
        deviceNameHint: String?
    ) async throws -> SessionIdentity {
        guard let cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        let allIdentities = try await cache.fetchSessionIdentities()
        var usedContextIds = Set<Int>()
        for identity in allIdentities {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            usedContextIds.insert(props.sessionContextId)
        }
        var sessionContextId: Int
        repeat {
            sessionContextId = Int.random(in: 1 ..< Int.max)
        } while usedContextIds.contains(sessionContextId)

        let rawName: String
        if let deviceNameHint, !deviceNameHint.isEmpty,
           !deviceNameHint.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) {
            rawName = deviceNameHint
        } else {
            rawName = try await determineDeviceName()
        }

        let identity = try await SessionIdentity(
            id: UUID(),
            props: .init(
                secretName: secretName,
                deviceId: deviceId,
                sessionContextId: sessionContextId,
                longTermPublicKey: longTermPublicKey,
                signingPublicKey: signingPublicKey,
                mlKEMPublicKey: mlKEMPublicKey,
                oneTimePublicKey: oneTimePublicKey,
                state: nil,
                deviceName: rawName,
                isMasterDevice: false
            ),
            symmetricKey: symmetricKey
        )
        try await cache.createSessionIdentity(identity)
        sessionIdentities.remove(secretName)
        return identity
    }

    /// Inbound decrypt: after inbound decrypt succeeds, make `proven` the sole
    /// active session for that peer device.
    ///
    /// - Inactive (archived) rows are promoted.
    /// - Other actives for the same `(secretName, deviceId)` are demoted in place.
    /// - The proven row is never deleted; losers stay available for later decrypt.
    ///
    /// Orphan-resend waves must not suppress this activate. Instead the task
    /// processor defers *inbound jobs* for that peer until pending orphan-resend replays
    /// finish (serial recovery mailbox vs resend).
    @discardableResult
    internal func activateSessionIdentityAfterInboundDecrypt(
        _ proven: SessionIdentity
    ) async throws -> SessionIdentity {
        let symmetricKey = try await getDatabaseSymmetricKey()
        guard let provenProps = await proven.props(symmetricKey: symmetricKey) else {
            return proven
        }

        if provenProps.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) {
            return try await promoteArchivedSessionIdentityToActive(proven)
        }

        guard let cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let allIdentities = try await cache.fetchSessionIdentities()
        var demotedSiblingCount = 0
        for identity in allIdentities {
            guard identity.id != proven.id,
                  let props = await identity.props(symmetricKey: symmetricKey),
                  props.secretName == provenProps.secretName,
                  props.deviceId == provenProps.deviceId,
                  !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            else {
                continue
            }
            // Proven decrypt becomes the sole active for this peer device.
            // Remint encrypt passes `recipientIdentity` explicitly — the orphan row
            // must not remain a second active (that captured general outbound).
            let demotingOrphan = isOrphanResendInitiatingSession(
                secretName: props.secretName,
                deviceId: props.deviceId,
                sessionId: identity.id)
            if try await demoteActiveSessionIdentityToInactive(identity) {
                demotedSiblingCount += 1
                if demotingOrphan {
                    clearOrphanResendInitiatingSession(
                        secretName: props.secretName,
                        deviceId: props.deviceId)
                }
            }
        }
        if demotedSiblingCount > 0 {
            // Do not call `removeIdentity` / `clearPeerTransientState`: that drops
            // recovery state for the whole secretName beyond this device.
            sessionIdentities.remove(provenProps.secretName)
            DecryptFailureAuditLog.log(
                "pqs.recovery.laneActivatedAfterDecrypt peer=\(provenProps.secretName) deviceId=\(provenProps.deviceId.uuidString) demotedSiblings=\(demotedSiblingCount)")
        }
        // When `proven` is itself the orphan remint row, keep the mark — orphan
        // resend may still reuse that initiating SessionID until MessageRecord settles.
        return proven
    }

    /// Demotes an active session row to inactive in place (device record).
    ///
    /// Inbound decrypt activates the session that decrypts and moves the previous
    /// current into the inactive list. Deleting the losing active destroyed
    /// concurrent Automatic Session Reset / `peerRefresh` initiating lanes while
    /// offline backlog still decrypted on an older archive (heal-then-diverge).
    @discardableResult
    internal func demoteActiveSessionIdentityToInactive(
        _ identity: SessionIdentity
    ) async throws -> Bool {
        guard let cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        guard let props = await identity.props(symmetricKey: symmetricKey),
              !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
        else {
            return false
        }

        let demotedProps = SessionIdentity.UnwrappedProps(
            secretName: props.secretName,
            deviceId: props.deviceId,
            // Retention / newest-first ordering treat this as archive time.
            sessionContextId: Int(Date().timeIntervalSince1970),
            longTermPublicKey: props.longTermPublicKey,
            signingPublicKey: props.signingPublicKey,
            mlKEMPublicKey: props.mlKEMPublicKey,
            oneTimePublicKey: props.oneTimePublicKey,
            state: props.state,
            deviceName: PQSSessionConstants.inactiveSessionDeviceNamePrefix + props.deviceName,
            serverTrusted: props.serverTrusted,
            previousRekey: props.previousRekey,
            isMasterDevice: props.isMasterDevice,
            verifiedIdentity: props.verifiedIdentity,
            verificationCode: props.verificationCode)
        try await identity.updateIdentityProps(
            symmetricKey: symmetricKey,
            props: demotedProps)
        try await cache.updateSessionIdentity(identity)
        return true
    }

    /// Recovery allows a state-less initiating active after orphan-resend insert. A *zombie*
    /// is a state-less active left after failed outbound repair with no successful
    /// initiating encrypt — it cannot decrypt peer Whisper frames and poisons try-all.
    /// Demote such rows so they stop being preferred/current.
    @discardableResult
    internal func demoteZombieStateLessActives(
        secretName: String,
        deviceId: UUID
    ) async throws -> Int {
        guard let cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        let allIdentities = try await cache.fetchSessionIdentities()
        var demoted = 0
        for identity in allIdentities {
            guard let props = await identity.props(symmetricKey: symmetricKey),
                  props.secretName == secretName,
                  props.deviceId == deviceId,
                  !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix),
                  props.state == nil
            else {
                continue
            }
            // Do not demote an in-flight orphan-resend initiating session.
            if isOrphanResendInitiatingSession(
                secretName: secretName,
                deviceId: deviceId,
                sessionId: identity.id
            ) {
                continue
            }
            if try await demoteActiveSessionIdentityToInactive(identity) {
                demoted += 1
            }
        }
        if demoted > 0 {
            // Do not call `removeIdentity` / `clearPeerTransientState` here: that
            // clears in-flight orphan-resend `orphanResend` marks for the whole secretName.
            // Prefer the surviving initiating active on the next encrypt lookup.
            sessionIdentities.remove(secretName)
            DecryptFailureAuditLog.log(
                "pqs.recovery.zombieStateLessDemoted peer=\(secretName) deviceId=\(deviceId.uuidString) demoted=\(demoted)")
            logger.log(
                level: .warning,
                message: "Demoted \(demoted) zombie state-less active SessionIdentity row(s) for \(secretName) (\(deviceId))")
        }
        return demoted
    }

    /// Promotes the exact archived row that successfully decrypted inbound
    /// ciphertext (decrypt on inactive → activate for send/receive).
    /// Preserves the proven ratchet state so subsequent outbound uses the same
    /// lane, instead of rematerializing a failed active or a freshly reset row.
    ///
    /// Previous actives are demoted to inactive (inbound decrypt), not deleted.
    internal func promoteArchivedSessionIdentityToActive(
        _ archived: SessionIdentity
    ) async throws -> SessionIdentity {
        guard let cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        guard let archivedProps = await archived.props(symmetricKey: symmetricKey),
              archivedProps.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
        else {
            return archived
        }

        let allIdentities = try await cache.fetchSessionIdentities()
        var demotedActiveCount = 0
        for identity in allIdentities {
            guard identity.id != archived.id,
                  let props = await identity.props(symmetricKey: symmetricKey),
                  props.secretName == archivedProps.secretName,
                  props.deviceId == archivedProps.deviceId,
                  !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            else {
                continue
            }
            // Promoting a proven archive makes it the sole active for this peer device.
            let demotingOrphan = isOrphanResendInitiatingSession(
                secretName: props.secretName,
                deviceId: props.deviceId,
                sessionId: identity.id)
            if try await demoteActiveSessionIdentityToInactive(identity) {
                demotedActiveCount += 1
                if demotingOrphan {
                    clearOrphanResendInitiatingSession(
                        secretName: props.secretName,
                        deviceId: props.deviceId)
                }
            }
        }

        let restoredDeviceName = String(
            archivedProps.deviceName.dropFirst(
                PQSSessionConstants.inactiveSessionDeviceNamePrefix.count))
        let restoredProps = SessionIdentity.UnwrappedProps(
            secretName: archivedProps.secretName,
            deviceId: archivedProps.deviceId,
            sessionContextId: archivedProps.sessionContextId,
            longTermPublicKey: archivedProps.longTermPublicKey,
            signingPublicKey: archivedProps.signingPublicKey,
            mlKEMPublicKey: archivedProps.mlKEMPublicKey,
            oneTimePublicKey: archivedProps.oneTimePublicKey,
            state: archivedProps.state,
            deviceName: restoredDeviceName,
            serverTrusted: archivedProps.serverTrusted,
            previousRekey: archivedProps.previousRekey,
            isMasterDevice: archivedProps.isMasterDevice,
            verifiedIdentity: archivedProps.verifiedIdentity,
            verificationCode: archivedProps.verificationCode)
        try await archived.updateIdentityProps(
            symmetricKey: symmetricKey,
            props: restoredProps)
        try await cache.updateSessionIdentity(archived)
        // Do not call `removeIdentity` / `clearPeerTransientState`: that drops
        // in-flight orphan-resend marks for the whole secretName.
        sessionIdentities.remove(archivedProps.secretName)
        logger.log(
            level: .info,
            message: "Promoted cryptographically proven archived SessionIdentity for \(archivedProps.secretName) (\(archivedProps.deviceId)); demotedActive=\(demotedActiveCount)")
        DecryptFailureAuditLog.log(
            "pqs.recovery.lanePromotedFromArchive peer=\(archivedProps.secretName) deviceId=\(archivedProps.deviceId.uuidString) demotedActive=\(demotedActiveCount)")
        return archived
    }

    /// Archives and replaces the active identity for one peer device with a fresh,
    /// state-less identity built from the currently advertised key bundle.
    ///
    /// This is the PostQuantumSolace-side session reestablishment primitive. A
    /// rotated peer key bundle must never be grafted onto an existing ratchet
    /// state; doing so leaves the ratchet with old state and new identity keys.
    ///
    /// - Important: One-time prekeys are used at most once, and only via the atomic
    ///   server consume (`sendOneTimeIdentities: true`). Recovery / repair callers pass
    ///   `false` and get a **nil** curve OTK — X3DH permits a bundle without a one-time
    ///   prekey, with the final MLKEM key playing the signed-prekey role. Binding a
    ///   published, un-consumed OTK is forbidden: two initiators can race onto the same
    ///   key and the losing handshake fails with `ratchet.missingOneTimeKey` at the peer.
    @discardableResult
    internal func resetSessionIdentityForFreshSession(
        secretName: String,
        deviceId: UUID,
        sendOneTimeIdentities: Bool = true,
        reason: String = "unspecified"
    ) async throws -> SessionIdentity {
        guard let cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        guard let transportDelegate else {
            throw PQSSession.SessionErrors.transportNotInitialized
        }
        guard let sessionUser = await sessionContext?.sessionUser else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }

        let symmetricKey = try await getDatabaseSymmetricKey()
        let configuration = try await transportDelegate.findConfiguration(for: secretName)
        // Config lookup succeeded — clear any dependency block for this lane so a
        // subsequent decrypt failure may emit peerRefresh again.
        clearRecoveryEmitBlocked(sender: secretName, deviceId: deviceId)
        // A non-orphanReset replaces the intentional orphan-resend initiating mark and
        // recovery-session history; orphanResend callers re-mark the returned row after
        // this returns.
        if reason != "orphanResend" {
            clearOrphanResendRecoveryState(secretName: secretName, deviceId: deviceId)
        }

        try validateUserConfigurationSignatures(configuration)
        if secretName != sessionUser.secretName {
            try await enforcePeerAccountSigningKeyPin(
                for: secretName,
                configuration: configuration,
                symmetricKey: symmetricKey)
        }

        let verifiedDevices = try configuration.getVerifiedDevices().map {
            try configuration.deviceWithCurrentKeyBundle($0)
        }

        guard let device = verifiedDevices.first(where: { $0.deviceId == deviceId }),
              device.deviceId != sessionUser.deviceId else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }

        if secretName == sessionUser.secretName {
            try await synchronizeActiveUserConfiguration(configuration)
        }

        let allIdentities = try await cache.fetchSessionIdentities()
        var generatedSessionContextIds = Set<Int>()
        var activeMatches: [(identity: SessionIdentity, props: SessionIdentity.UnwrappedProps)] = []

        for identity in allIdentities {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            generatedSessionContextIds.insert(props.sessionContextId)
            guard props.secretName == secretName,
                  props.deviceId == deviceId,
                  !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            else { continue }
            activeMatches.append((identity, props))
        }

        // Repair-lane reuse: a prior repair may already have left a state-less row.
        // Reuse it instead of tearing the row down again under concurrent recovery.
        // Consume-lane callers (`sendOneTimeIdentities == true`) must fall through to
        // the atomic OTK consume below so bootstrap semantics stay exact.
        if !sendOneTimeIdentities,
           let reusable = activeMatches.last(where: { $0.props.state == nil }),
           activeMatches.allSatisfy({ $0.props.state == nil }) {
            let keysMatchDevice =
                reusable.props.longTermPublicKey == device.longTermPublicKey
                && reusable.props.signingPublicKey == device.signingPublicKey
            if keysMatchDevice {
                // If the row already carries an OTK it was atomically consumed by an
                // earlier bootstrap; keep it. Never attach published (non-consumed)
                // OTKs here — that breaks the at-most-once one-time-prekey contract.
                logger.log(
                    level: .info,
                    message: "Reusing existing state-less SessionIdentity for \(secretName) (\(device.deviceId)); repair lane does not consume OTKs")
                DecryptFailureAuditLog.log(
                    "pqs.recovery.laneReset outcome=reusedStateLessRow reason=\(reason) peer=\(secretName) deviceId=\(device.deviceId.uuidString)")
                return reusable.identity
            }
        }

        // Acquire replacement key material BEFORE tearing down the active row.
        // A failed OTK fetch must not leave the peer with no SessionIdentity.
        // Repair lane (`sendOneTimeIdentities == false`) intentionally yields a nil
        // curve OTK; the ratchet handshake proceeds on long-term + final MLKEM keys.
        let (curve, mlKEM) = try await createOneTimeKeys(
            secretName: secretName,
            deviceId: device.deviceId,
            curveId: nil,
            mlKEMId: nil,
            configuration: configuration,
            fetchOneTimeKeys: sendOneTimeIdentities)

        var sessionContextId: Int
        repeat {
            sessionContextId = Int.random(in: 1 ..< Int.max)
        } while generatedSessionContextIds.contains(sessionContextId)

        // Insert the replacement BEFORE demoting the previous actives: the store
        // must never hold zero active rows for a live device lane, or a concurrent
        // outbound fan-out resolves no lane and surfaces `.missingSessionIdentity`
        // to the host. A failed insert also leaves the old lane intact this way.
        let identity = try await createEncryptableSessionIdentityModel(
            with: device,
            oneTimePublicKey: curve,
            mlKEMPublicKey: mlKEM,
            for: secretName,
            associatedWith: device.deviceId,
            new: sessionContextId)

        // Device record: previous current becomes inactive (demote in place).
        // Do not copy+delete — that minted a second inactive UUID and destroyed the
        // original row id outbound ledgers may still reference.
        var demotedActiveCount = 0
        for match in activeMatches {
            if try await demoteActiveSessionIdentityToInactive(match.identity) {
                demotedActiveCount += 1
            }
        }

        removeIdentity(with: secretName)
        await cleanupInactiveSessionSnapshots(
            cache: cache,
            symmetricKey: symmetricKey,
            secretName: secretName,
            deviceId: device.deviceId)

        logger.log(
            level: .info,
            message: "Reset SessionIdentity for \(secretName) (\(device.deviceId)); demotedActive=\(demotedActiveCount) consumedOTK=\(sendOneTimeIdentities)")
        // Lane teardown in the same audit file as the decrypt failures: a proven
        // inbound lane failing right after one of these entries identifies the
        // caller that clobbered it.
        DecryptFailureAuditLog.log(
            "pqs.recovery.laneReset outcome=reset reason=\(reason) peer=\(secretName) deviceId=\(device.deviceId.uuidString) demotedActive=\(demotedActiveCount) consumedOTK=\(sendOneTimeIdentities)")

        return identity
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
        
        if !otkUploadCircuitOpen {
            if let sessionContext = await sessionContext, sessionContext.activeUserConfiguration.signedOneTimePublicKeys.count <= PQSSessionConstants.oneTimeKeyLowWatermark {
                await refreshOneTimeKeysTask()
            }
            if let sessionContext = await sessionContext, sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.count <= PQSSessionConstants.oneTimeKeyLowWatermark {
                await refreshMLKEMOneTimeKeysTask()
            }
        }
        
        var identities = existingIdentities
        guard let transportDelegate else {
            throw PQSSession.SessionErrors.transportNotInitialized
        }

        guard let sessionUser = await sessionContext?.sessionUser else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        let isSelfSecretName = secretName == sessionUser.secretName

        let symmetricKey = try await getDatabaseSymmetricKey()
        
        if createIdentity, forceRefresh || sessionIdentities.isEmpty || !sessionIdentities.contains(secretName) {

            // Get the user configuration for the recipient
            let configuration = try await transportDelegate.findConfiguration(for: secretName)
            try validateUserConfigurationSignatures(configuration)

            if isSelfSecretName, forceRefresh {
                // For linked-device convergence, force-refreshing self identities should also
                // synchronize the persisted active account bundle.
                try await synchronizeActiveUserConfiguration(configuration)
            } else if !isSelfSecretName {
                try await enforcePeerAccountSigningKeyPin(
                    for: secretName,
                    configuration: configuration,
                    symmetricKey: symmetricKey)
            }

            var verifiedDevices = try verifiedDevicesWithUsableKeyMaterial(
                in: configuration,
                secretName: secretName,
                source: "remote")
            lastVerifiedDeviceIdsBySecretName[secretName] = Set(verifiedDevices.map(\.deviceId))
            var collected = [UserDeviceConfiguration]()
            var oneTimeNotifiedDeviceIds = Set<UUID>()
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
                        new: sessionContextId)
                    
                    logger.log(level: .info, message: "Created Session Identity: \(identity)")
                    identities.append(identity)

                    // OTK handshake must target the peer master only. Ghost / non-master
                    // rows in a published account config must not consume the notify lane.
                    if sendOneTimeIdentities,
                       !isSelfSecretName,
                       device.isMasterDevice,
                       let curveId = curve?.id {
                        try await notifyIdentityCreation(
                            for: secretName,
                            curveId: curveId.uuidString,
                            mlKEMId: mlKEM.id.uuidString)
                        oneTimeNotifiedDeviceIds.insert(device.deviceId)
                    }
                }
            }

            guard let localConfiguration = await sessionContext?.activeUserConfiguration else { return [] }
            let myDevices = try verifiedDevicesWithUsableKeyMaterial(
                in: localConfiguration,
                secretName: secretName,
                source: "local")
            verifiedDevices.append(contentsOf: myDevices)

            await pruneStaleSessionIdentities(
                secretName: secretName,
                identities: &identities,
                verifiedDeviceIds: Set(verifiedDevices.map(\.deviceId)),
                symmetricKey: symmetricKey)

            
            for foundIdentity in await identities.asyncFilter( { await $0.props(symmetricKey: symmetricKey)?.secretName == secretName }) {
                guard var currentProps = await foundIdentity.props(symmetricKey: symmetricKey) else {
                    continue
                }
                for device in verifiedDevices {
                    if currentProps.deviceId == device.deviceId {
                        let identityKeyChanged = currentProps.longTermPublicKey != device.longTermPublicKey
                            || currentProps.signingPublicKey != device.signingPublicKey

                        if identityKeyChanged {
                            logger.log(
                                level: .info,
                                message: "Detected rotated identity keys for \(secretName) (\(device.deviceId)); replacing active SessionIdentity")

                        let replacement = try await resetSessionIdentityForFreshSession(
                            secretName: secretName,
                            deviceId: device.deviceId,
                            sendOneTimeIdentities: sendOneTimeIdentities,
                            reason: "rotatedIdentityKeysDetected")

                            identities.removeAll(where: { identity in
                                identity.id == foundIdentity.id
                            })
                            identities.append(replacement)
                            if sendOneTimeIdentities {
                                try await deliverOneTimeIdentityNotifyIfNeeded(
                                    secretName: secretName,
                                    device: device,
                                    configuration: configuration,
                                    identity: replacement,
                                    symmetricKey: symmetricKey,
                                    alreadyNotified: &oneTimeNotifiedDeviceIds)
                            }
                            break
                        }

                        currentProps.setLongTermPublicKey(device.longTermPublicKey)
                        currentProps.setSigningPublicKey(device.signingPublicKey)
                        
                        if forceRefresh, currentProps.state == nil {
                            do {
                                try await attachPublishedPeerOneTimeKeys(
                                    to: &currentProps,
                                    secretName: secretName,
                                    device: device,
                                    configuration: configuration)
                            } catch {
                                logger.log(level: .warning, message: "Failed to refresh one-time keys for \(secretName) (\(device.deviceId)): \(error)")
                            }
                        } else if forceRefresh {
                            logger.log(
                                level: .debug,
                                message: "Skipping one-time key refresh for initialized SessionIdentity \(secretName) (\(device.deviceId))")
                        }
                        try await foundIdentity.updateIdentityProps(symmetricKey: symmetricKey, props: currentProps)
                        try await cache?.updateSessionIdentity(foundIdentity)
                        if let index = identities.firstIndex(where: { $0.id == foundIdentity.id }) {
                            identities[index] = foundIdentity
                        }
                        if sendOneTimeIdentities,
                           !isSelfSecretName,
                           device.deviceId != sessionUser.deviceId {
                            try await deliverOneTimeIdentityNotifyIfNeeded(
                                secretName: secretName,
                                device: device,
                                configuration: configuration,
                                identity: foundIdentity,
                                symmetricKey: symmetricKey,
                                alreadyNotified: &oneTimeNotifiedDeviceIds)
                        }
                        break
                    }
                }
            }
            
            // Do not memoize "refreshed" for the local account until sibling rows exist when the
            // account configuration lists other devices. Otherwise the next `refreshIdentities`
            // skips this block (`sessionIdentities` already contains `secretName`) while the cache
            // is still empty — linked devices never get SessionIdentity rows and personal/control
            // delivery to siblings silently no-ops.
            let accountDevices = try configuration.getVerifiedDevices()
            let accountListsPeerDevices = accountDevices.contains { $0.deviceId != sessionUser.deviceId }
            let hasSiblingIdentity = await identities.asyncContains(where: { identity in
                guard let p = await identity.props(symmetricKey: symmetricKey) else { return false }
                return p.secretName == secretName && p.deviceId != sessionUser.deviceId
            })
            if isSelfSecretName {
                if !accountListsPeerDevices {
                    sessionIdentities.insert(secretName)
                } else if hasSiblingIdentity {
                    sessionIdentities.insert(secretName)
                }
            } else {
                sessionIdentities.insert(secretName)
            }
        }
        return identities
    }

    private func verifiedDevicesWithUsableKeyMaterial(
        in configuration: UserConfiguration,
        secretName: String,
        source: String
    ) throws -> [UserDeviceConfiguration] {
        let verifiedDevices = try configuration.getVerifiedDevices()
        var usableDevices = [UserDeviceConfiguration]()

        for device in verifiedDevices {
            do {
                _ = try Curve25519.Signing.PublicKey(rawRepresentation: device.signingPublicKey)
                let currentDevice = try configuration.deviceWithCurrentKeyBundle(device)
                _ = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: currentDevice.longTermPublicKey)
                _ = try MLKEMPublicKey(
                    id: currentDevice.finalMLKEMPublicKey.id,
                    currentDevice.finalMLKEMPublicKey.rawRepresentation)
                usableDevices.append(currentDevice)
            } catch {
                logger.log(
                    level: .warning,
                    message: "Skipping malformed \(source) device during identity refresh for \(secretName): deviceId=\(device.deviceId), error=\(error)")
            }
        }

        return usableDevices
    }

    private func validateUserConfigurationSignatures(_ configuration: UserConfiguration) throws {
        do {
            let accountSigningPublicKey = try Curve25519.Signing.PublicKey(
                rawRepresentation: configuration.signingPublicKey
            )
            var verifiedDevices = [UserDeviceConfiguration]()

            for signedDevice in configuration.signedDevices {
                guard let device = try signedDevice.verified(using: accountSigningPublicKey) else {
                    throw PQSSession.SessionErrors.invalidSignature
                }
                verifiedDevices.append(device)
            }

            for signedBundle in configuration.signedDeviceKeyBundles {
                guard let device = verifiedDevices.first(where: { $0.deviceId == signedBundle.id }) else {
                    throw PQSSession.SessionErrors.invalidDeviceIdentity
                }
                let deviceSigningPublicKey = try Curve25519.Signing.PublicKey(
                    rawRepresentation: device.signingPublicKey
                )
                guard let bundle = try signedBundle.verified(using: deviceSigningPublicKey),
                      bundle.deviceId == device.deviceId
                else {
                    throw PQSSession.SessionErrors.invalidSignature
                }
            }
        } catch let sessionError as PQSSession.SessionErrors {
            throw sessionError
        } catch {
            throw PQSSession.SessionErrors.invalidSignature
        }
    }

    private func enforcePeerAccountSigningKeyPin(
        for secretName: String,
        configuration: UserConfiguration,
        symmetricKey: SymmetricKey
    ) async throws {
        guard let cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }

        let contacts = try await cache.fetchContacts()
        var foundPinnedContact = false

        for contact in contacts {
            guard let props = await contact.props(symmetricKey: symmetricKey),
                  props.secretName == secretName
            else {
                continue
            }

            let pinnedSigningPublicKey = props.configuration.signingPublicKey
            guard !pinnedSigningPublicKey.isEmpty else {
                continue
            }

            foundPinnedContact = true
            if pinnedSigningPublicKey != configuration.signingPublicKey {
                logger.log(
                    level: .error,
                    message: "[refreshSessionIdentities] peer account signing key changed without authenticated reestablishment; refusing to refresh \(secretName)")
                throw PQSSession.SessionErrors.peerSigningKeyOutOfSync
            }
        }

        if foundPinnedContact {
            logger.log(
                level: .debug,
                message: "Verified pinned peer account signing key for \(secretName)")
        }
    }

    /// Fetches the remote peer configuration and refuses recovery emit when the
    /// advertised signing key no longer matches the locally pinned contact.
    internal func validatePeerAccountSigningKeyAgainstRemote(secretName: String) async throws {
        guard let transportDelegate else {
            throw PQSSession.SessionErrors.transportNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        let configuration = try await transportDelegate.findConfiguration(for: secretName)
        try validateUserConfigurationSignatures(configuration)
        try await enforcePeerAccountSigningKeyPin(
            for: secretName,
            configuration: configuration,
            symmetricKey: symmetricKey)
    }
    
    func createOneTimeKeys(
        secretName: String,
        deviceId: UUID,
        curveId: String?,
        mlKEMId: String?,
        configuration: UserConfiguration,
        fetchOneTimeKeys: Bool
    ) async throws -> (curve: CurvePublicKey?, mlKEM: MLKEMPublicKey){
        
        let accountSigningPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: configuration.signingPublicKey)
        guard let accountSignedDevice = configuration.signedDevices.first(where: {
            (try? $0.verified(using: accountSigningPublicKey))?.deviceId == deviceId
        }),
              let verifiedDevice = try accountSignedDevice.verified(using: accountSigningPublicKey)
        else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }
        let currentDevice = try configuration.deviceWithCurrentKeyBundle(verifiedDevice)
        let deviceSigningPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: verifiedDevice.signingPublicKey)
        
        guard let transportDelegate else {
            throw PQSSession.SessionErrors.transportNotInitialized
        }
        
            // On Contact Creation this will be false for the requester. The recipient will contained the passed identities, thus containing values.
        if fetchOneTimeKeys {
            let keys = try await transportDelegate.fetchOneTimeKeys(for: secretName, deviceId: deviceId.uuidString)
            // Prefer the consumed key material itself. Looking up only by id against a
            // stale findConfiguration snapshot can miss keys that were just consumed.
            let consumedCurveId = keys.curve?.id.uuidString ?? curveId
            let consumedMLKEMId = keys.mlKEM?.id.uuidString ?? mlKEMId
            let fallbackCurve = try configuration.signedOneTimePublicKeys
                .first(where: { $0.id.uuidString == consumedCurveId })?
                .verified(using: deviceSigningPublicKey)
            let fallbackMLKEM = try configuration.signedMLKEMOneTimePublicKeys
                .first(where: { $0.id.uuidString == consumedMLKEMId })?
                .verified(using: deviceSigningPublicKey)
            let curvePublicKey = keys.curve ?? fallbackCurve
            let mlKEMPublicKey = keys.mlKEM ?? fallbackMLKEM ?? currentDevice.finalMLKEMPublicKey
            return (curvePublicKey, mlKEMPublicKey)
        }
        
        let curvePublicKey = try configuration.signedOneTimePublicKeys.first(where: { $0.id.uuidString == curveId })?.verified(using: deviceSigningPublicKey)

        var mlKEMPublicKey: MLKEMPublicKey
        if let signedKey = try configuration.signedMLKEMOneTimePublicKeys.first(where: { $0.id.uuidString == mlKEMId })?.verified(using: deviceSigningPublicKey) {
            mlKEMPublicKey = signedKey
        } else {
            mlKEMPublicKey = currentDevice.finalMLKEMPublicKey
        }
        return (curvePublicKey, mlKEMPublicKey)
    }

    /// Notifies the network of identity creation with associated keys.
    ///
    /// Announces the creation of a new user identity along with their initial
    /// cryptographic keys. This allows other users to discover and establish
    /// communication with the new identity.
    ///
    /// Sends OTK notify for a peer identity row that already exists but has no outbound ratchet
    /// state yet. `sendOneTimeIdentities` previously only notified on brand-new device rows;
    /// bootstrap paths that reset a stale row first need this follow-up notify.
    private func deliverOneTimeIdentityNotifyIfNeeded(
        secretName: String,
        device: UserDeviceConfiguration,
        configuration: UserConfiguration,
        identity: SessionIdentity,
        symmetricKey: SymmetricKey,
        alreadyNotified: inout Set<UUID>
    ) async throws {
        guard !alreadyNotified.contains(device.deviceId) else { return }
        // Peer OTK handshake is master-scoped; ghost devices stay in the account
        // config after reinstall and must not receive (or burn) the notify.
        guard device.isMasterDevice else {
            logger.log(
                level: .debug,
                message: "refreshSessionIdentities: skipping OTK notify for non-master \(secretName) deviceId=\(device.deviceId)")
            return
        }
        guard var props = await identity.props(symmetricKey: symmetricKey) else { return }
        guard props.state == nil else { return }

        if props.oneTimePublicKey == nil {
            try await attachPublishedPeerOneTimeKeys(
                to: &props,
                secretName: secretName,
                device: device,
                configuration: configuration)
            try await identity.updateIdentityProps(symmetricKey: symmetricKey, props: props)
            try await cache?.updateSessionIdentity(identity)
        }

        guard let recipientCurveId = props.oneTimePublicKey?.id.uuidString else {
            logger.log(
                level: .warning,
                message: "refreshSessionIdentities: skipping OTK notify for \(secretName) deviceId=\(device.deviceId); no peer curve OTK available")
            return
        }

        let recipientMLKEMId = props.mlKEMPublicKey.id.uuidString
        try await notifyIdentityCreation(
            for: secretName,
            curveId: recipientCurveId,
            mlKEMId: recipientMLKEMId)
        alreadyNotified.insert(device.deviceId)
        logger.log(
            level: .info,
            message: "refreshSessionIdentities: delivered OTK notify for existing state-less identity \(secretName) deviceId=\(device.deviceId)")
    }

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
        logger.log(
            level: .info,
            message: "Sent notifyIdentityCreation outbound to nickname(\"\(secretName)\") curveId=\(curveId)")
    }
    
    private func synchronizeActiveUserConfiguration(_ configuration: UserConfiguration) async throws {
        // Route through the public TOFU-pinned adoption helper so the account
        // signing key cannot silently change via a self-refresh path.
        try await adoptVerifiedUserConfiguration(configuration)
    }
}

//
//  TaskProcessor+Ratchet.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-14.
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
import SessionEvents
import SessionModels

/// Extension of `TaskProcessor` conforming to `SessionIdentityDelegate`.
/// This extension handles session identity management, including updating and fetching one-time keys,
/// performing message ratcheting, and managing session contexts.
///
/// ## Cryptographic Operations
/// This extension implements the Double Ratchet protocol for secure messaging, including:
/// - Key generation and rotation for Curve25519 and PQ-KEM keys
/// - Message encryption and decryption using ratchet chains
/// - Signature verification and message signing
/// - Session state management and persistence
///
/// ## Security Model
/// - All cryptographic operations are performed on dedicated serial executors
/// - Keys are rotated automatically to prevent forward secrecy attacks
/// - Message integrity is ensured through digital signatures
/// - Session state is encrypted and persisted securely
extension TaskProcessor: SessionIdentityDelegate, TaskSequenceDelegate {
    /// Updates the session identity with the provided identity.
    ///
    /// This method persists an updated session identity to the cache, typically after
    /// key rotation or session state changes. The identity is encrypted before storage.
    ///
    /// ## Usage Context
    /// Called during key rotation, session initialization, or when receiving new
    /// identity information from remote peers.
    ///
    /// - Parameter identity: The new session identity to be updated. Must contain
    ///                      valid cryptographic keys and session state.
    /// - Throws: An error if the update fails due to cache unavailability or encryption errors.
    public func updateSessionIdentity(_ identity: DoubleRatchetKit.SessionIdentity) async throws {
        guard let session else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        // Outbound encryption mutates the in-memory identity first. Persistence is
        // intentionally deferred until the exact signed frame is ready, so the
        // identity and prepared JobModel can be committed atomically.
        if atomicOutboundPreparationIdentityIds.contains(identity.id) {
            return
        }
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        do {
            try await cache.updateSessionIdentity(identity)
        } catch SessionCache.CacheErrors.sessionIdentityNotFound {
            if try await isRetiredSessionIdentity(identity, session: session, cache: cache) {
                return
            }
            throw SessionCache.CacheErrors.sessionIdentityNotFound
        }
    }

    private func isRetiredSessionIdentity(
        _ identity: DoubleRatchetKit.SessionIdentity,
        session: PQSSession,
        cache: SessionCache
    ) async throws -> Bool {
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        guard let retiredProps = await identity.props(symmetricKey: symmetricKey) else {
            return false
        }

        let currentIdentities = try await cache.fetchSessionIdentities()
        let hasActiveReplacement = await currentIdentities.asyncContains { current in
            guard current.id != identity.id,
                  let currentProps = await current.props(symmetricKey: symmetricKey),
                  currentProps.secretName == retiredProps.secretName,
                  currentProps.deviceId == retiredProps.deviceId,
                  !currentProps.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            else {
                return false
            }
            return true
        }

        if hasActiveReplacement {
            logger.log(
                level: .debug,
                message: "Skipping persistence for retired SessionIdentity \(retiredProps.secretName) (\(retiredProps.deviceId)); active replacement exists")
        }
        return hasActiveReplacement
    }
    
    /// Fetches a private one-time key by its identifier.
    ///
    /// This method retrieves a Curve25519 one-time private key from the current session
    /// context. One-time keys are used for initial message encryption and are consumed
    /// after use to maintain forward secrecy.
    ///
    /// ## Key Lifecycle
    /// - One-time keys are generated during session initialization
    /// - Keys are consumed when used for message encryption
    /// - New keys are generated automatically when needed
    /// - Expired or used keys are cleaned up automatically
    ///
    /// ## Security Considerations
    /// - Private keys are stored encrypted in session context
    /// - Keys are validated before use to prevent invalid key attacks
    /// - Key IDs must match exactly to prevent key confusion attacks
    ///
    /// - Parameter id: The UUID of the one-time key to fetch. If nil, no key is returned.
    /// - Returns: The corresponding private one-time key, or nil if not found.
    /// - Throws: `PQSSession.SessionErrors.sessionNotInitialized` if the session is not initialized.
    public func fetchOneTimePrivateKey(_ id: UUID?) async throws -> DoubleRatchetKit.CurvePrivateKey? {
        guard let sessionContext = await session?.sessionContext else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        guard let key = sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.first(where: { $0.id == id }) else {
            return nil
        }
        return key
    }
    
    /// Updates the one-time key for the current session.
    ///
    /// This method performs key rotation by generating a new Curve25519 one-time key pair
    /// and removing the old key. The operation is performed asynchronously on a dedicated
    /// executor to prevent blocking the main cryptographic operations.
    ///
    /// ## Key Rotation Process
    /// 1. Generates new Curve25519 key pair
    /// 2. Signs the new public key with the device's signing key
    /// 3. Updates session context with new keys
    /// 4. Removes the old key from storage
    /// 5. Notifies transport layer of key updates
    /// 6. Persists encrypted session context
    ///
    /// ## Security Considerations
    /// - Key rotation prevents forward secrecy attacks
    /// - New keys are signed to prevent impersonation
    /// - Old keys are securely removed from storage
    /// - Operation is performed on dedicated executor to prevent timing attacks
    ///
    /// ## Performance Considerations
    /// - Key generation is performed asynchronously to avoid blocking
    /// - Network operations are detached to prevent delays
    /// - Failed operations are logged but don't block the session
    ///
    /// - Parameter id: The UUID of the one-time key to remove and replace.
    public func updateOneTimeKey(remove id: UUID) async {
        // If we do not detach then the ratchet encrypt takes too long due to the network
        updateKeyTasks.append(Task(executorPreference: keyTransportExecutor) { [weak self] in
            guard let self else { return }
            do {
                guard let session = await session else {
                    throw PQSSession.SessionErrors.sessionNotInitialized
                }
                guard var sessionContext = await session.sessionContext else {
                    throw PQSSession.SessionErrors.sessionNotInitialized
                }
                
                let newID = UUID()
                let keypair = crypto.generateCurve25519PrivateKey()
                let privateKeyRep = try CurvePrivateKey(id: newID, keypair.rawRepresentation)
                let publicKey = try CurvePublicKey(id: newID, keypair.publicKey.rawRepresentation)
                
                var deviceKeys = sessionContext.sessionUser.deviceKeys
                deviceKeys.oneTimePrivateKeys.removeAll { $0.id == id }
                deviceKeys.oneTimePrivateKeys.append(privateKeyRep)
                
                sessionContext.sessionUser.deviceKeys = deviceKeys
                sessionContext.updateSessionUser(sessionContext.sessionUser)
                
                guard var signedKeys = await session
                    .sessionContext?
                    .activeUserConfiguration
                    .signedOneTimePublicKeys
                else { return }
                
                let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey)
                let newSignedKey = try UserConfiguration.SignedOneTimePublicKey(key: publicKey, deviceId: sessionContext.sessionUser.deviceId, signingKey: signingKey)
                
                signedKeys.removeAll { $0.id == id }
                signedKeys.append(newSignedKey)
                
                try await session.transportDelegate?.updateOneTimeKeys(
                    for: sessionContext.sessionUser.secretName,
                    deviceId: sessionContext.sessionUser.deviceId.uuidString,
                    keys: [newSignedKey]
                )
                
                // Update the user configuration only after the server accepted the replacement key.
                sessionContext.activeUserConfiguration.signedOneTimePublicKeys = signedKeys
                await session.setSessionContext(sessionContext)
                
                // Encrypt and persist
                let encodedData = try BinaryEncoder().encode(sessionContext)
                guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: session.getAppSymmetricKey()) else {
                    throw PQSSession.SessionErrors.sessionEncryptionError
                }
                
                try await session.cache?.updateLocalSessionContext(encryptedConfig)
                await cancelAndRemoveUpdateKeyTasks()
            } catch {
                await cancelAndRemoveUpdateKeyTasks()
                await logger.log(level: .error, message: "Failed to update one time key: \(error)")
            }
        })
    }
    
    private func cancelAndRemoveUpdateKeyTasks() async {
        guard !updateKeyTasks.isEmpty else { return }
        let item = updateKeyTasks.removeFirst()
        item.cancel()
    }
    
    private func cancelAndRemoveDeleteKeyTasks() async {
        guard !deleteKeyTasks.isEmpty else { return }
        let item = deleteKeyTasks.removeFirst()
        item.cancel()
    }

    /// Cancels all in-flight key transport offload tasks (session shutdown).
    func cancelBackgroundKeyTasks() async {
        let updates = updateKeyTasks
        let deletes = deleteKeyTasks
        updateKeyTasks.removeAll()
        deleteKeyTasks.removeAll()
        for task in updates {
            task.cancel()
        }
        for task in deletes {
            task.cancel()
        }
        for task in updates {
            await task.value
        }
        for task in deletes {
            await task.value
        }
    }
    
    /// Performs a ratchet operation based on the specified task.
    ///
    /// This method is the main entry point for cryptographic operations, routing tasks
    /// to either outbound message encryption or inbound message decryption based on
    /// the task type. It manages the Double Ratchet protocol state and ensures proper
    /// key management throughout the process.
    ///
    /// ## Task Types
    /// - `.writeMessage`: Encrypts and signs outbound messages
    /// - `.streamMessage`: Decrypts and verifies inbound messages
    ///
    /// ## Protocol Flow
    /// 1. Sets up ratchet manager delegate for key management
    /// 2. Routes task to appropriate handler based on type
    /// 3. Manages session state and key rotation
    /// 4. Handles cryptographic operations and error recovery
    ///
    /// ## Security Considerations
    /// - All operations use the Double Ratchet protocol for forward secrecy
    /// - Keys are rotated automatically to prevent attacks
    /// - Message integrity is verified through signatures
    /// - Session state is maintained securely
    ///
    /// - Parameters:
    ///   - task: The task to perform, which can be either writing or streaming a message.
    ///           Contains the message data and metadata needed for processing.
    ///   - session: The current crypto session providing context and keys.
    /// - Throws: An error if the ratchet operation fails due to cryptographic errors,
    ///           missing keys, or protocol violations.
    func performRatchet(
        task: TaskType,
        session: PQSSession
    ) async throws {
        self.session = session
        await ratchetManager.setDelegate(self)
        // Strict OTK enforcement stays OFF: PQS recovery replays the first encrypted
        // outbound frame (transport failure / lane repair), which requires the initial
        // one-time key to remain resolvable until the handshake is confirmed in both
        // directions. Enforcement consumes the OTK on first decrypt and fails fast on
        // replays, stalling rotation/repair flows. Enabling it needs a deferred
        // consumption design (consume once the reverse handshake lands), not a flag flip.
        // TODO: Design deferred OTK consumption so strict enforcement can be enabled:
        // consume the local one-time prekey only after the reverse handshake confirms
        // (peer's first authenticated reply lands), then delete it via the delegate.
            // Until then the private OTK is retained longer than the Double Ratchet
            // specification's ideal, which
        // slightly extends the window in which a later device compromise could decrypt
        // a recorded initial handshake frame. Wire confidentiality is unaffected and
        // server-side single-use of published OTKs still holds.
        await ratchetManager.setEnforceOTKConsistency(false)
        switch task {
        case let .writeMessage(outboundTask):
            try await handleWriteMessage(
                outboundTask: outboundTask,
                session: session)
        case let .streamMessage(inboundTask):
            try await handleStreamMessage(
                inboundTask: inboundTask,
                session: session)
        }
    }
    
    struct LoadedKeysResult: Sendable {
        var localOneTimePrivateKey: CurvePrivateKey?
        var localMLKEMPrivateKey: MLKEMPrivateKey
        var remoteLongTermPublicKey: Data
        var remoteOneTimePublicKey: CurvePublicKey?
        var remoteMLKEMPublicKey: MLKEMPublicKey
        var needsRemoteDeletion = false
    }
    
    func loadKeys(
        props: SessionIdentity.UnwrappedProps,
        sessionContext: SessionContext,
        session: PQSSession
    ) async throws -> LoadedKeysResult {
        /// What are our requirements? We need to ensure that the proper keys are loaded for local and remote
        /// What are our scenarios?
        /// 1. Initial write -  No State
        /// 2. Rotating - State Reset and archived, essentially a new initial write
        /// 3. Has state
        /// 4. Has state - Rotated keys, but didn't clear state (Maintenance?)
        
        var localOneTimePrivateKey: CurvePrivateKey?
        var localMLKEMPrivateKey: MLKEMPrivateKey
        var remoteLongTermPublicKey: Data
        var remoteOneTimePublicKey: CurvePublicKey?
        var remoteMLKEMPublicKey: MLKEMPublicKey
        var needsRemoteDeletion = false
        var effectiveSessionContext = sessionContext
        
        switch await session.keyLoadingState {
        case .initial:
            if let privateOneTimeKey = effectiveSessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.last {
                localOneTimePrivateKey = privateOneTimeKey
            }

            if let mlKEMOneTimePrivateKey = effectiveSessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.last {
                localMLKEMPrivateKey = mlKEMOneTimePrivateKey
            } else {
                localMLKEMPrivateKey = effectiveSessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
            }
        case .rotating:
            // `keyLoadingState` is session-scoped, but ratchet state is recipient-scoped.
            // In multi-recipient sends (e.g. channels), we may have `.rotating`/`.complete` while
            // a particular recipient has no established ratchet state yet. Treat missing state as
            // an initial handshake for that recipient instead of failing the whole job.
            if let state = props.state {
                localOneTimePrivateKey = state.localOneTimePrivateKey
                localMLKEMPrivateKey = state.localMLKEMPrivateKey
            } else {
                localOneTimePrivateKey = effectiveSessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.last
                localMLKEMPrivateKey = effectiveSessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.last
                ?? effectiveSessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
            }
        case .complete:
            if let state = props.state {
                localOneTimePrivateKey = state.localOneTimePrivateKey
                localMLKEMPrivateKey = state.localMLKEMPrivateKey
            } else {
                localOneTimePrivateKey = effectiveSessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.last
                localMLKEMPrivateKey = effectiveSessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.last
                ?? effectiveSessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
            }
        }
        
        switch await session.keyLoadingState {
        case .initial, .rotating:
            remoteLongTermPublicKey = props.longTermPublicKey
            remoteMLKEMPublicKey = props.mlKEMPublicKey
            remoteOneTimePublicKey = props.oneTimePublicKey
            
            await session.setKeyLoadingState(.complete)
        case .complete:
            if try await session.rotateMLKEMKeysIfNeeded() && !needsRemoteDeletion {
                if let refreshedContext = await session.sessionContext {
                    effectiveSessionContext = refreshedContext
                }
                guard let state = props.state else {
                    // No prior ratchet state for this recipient yet; skip rotate-on-complete path.
                    remoteLongTermPublicKey = props.longTermPublicKey
                    remoteOneTimePublicKey = props.oneTimePublicKey
                    remoteMLKEMPublicKey = props.mlKEMPublicKey
                    return LoadedKeysResult(
                        localOneTimePrivateKey: localOneTimePrivateKey,
                        localMLKEMPrivateKey: localMLKEMPrivateKey,
                        remoteLongTermPublicKey: remoteLongTermPublicKey,
                        remoteOneTimePublicKey: remoteOneTimePublicKey,
                        remoteMLKEMPublicKey: remoteMLKEMPublicKey,
                        needsRemoteDeletion: false
                    )
                }
                needsRemoteDeletion = true
                localOneTimePrivateKey = state.localOneTimePrivateKey
                if let privateMLKEMOneTimeKey = effectiveSessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.last {
                    localMLKEMPrivateKey = privateMLKEMOneTimeKey
                } else {
                    localMLKEMPrivateKey = effectiveSessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
                }
            }
            remoteLongTermPublicKey = props.longTermPublicKey
            remoteOneTimePublicKey = props.oneTimePublicKey
            remoteMLKEMPublicKey = props.mlKEMPublicKey
        }
        
        if shouldEmitKeyPayloadLogs {
            logger.log(level: .debug, message: """
                loadKeys: recipient=\(props.secretName) \n
                remoteLTK=\(remoteLongTermPublicKey.prefix(10).base64EncodedString())\n
                remoteOTK=\(remoteOneTimePublicKey?.id.uuidString ?? "nil")\n
                remoteMLKEM=\(remoteMLKEMPublicKey.id.uuidString)\n
                localOTK=\(localOneTimePrivateKey?.id.uuidString ?? "nil")\n
                localMLKEM=\(localMLKEMPrivateKey.id.uuidString)
                """)
        }
        
        return LoadedKeysResult(
            localOneTimePrivateKey: localOneTimePrivateKey,
            localMLKEMPrivateKey: localMLKEMPrivateKey,
            remoteLongTermPublicKey: remoteLongTermPublicKey,
            remoteOneTimePublicKey: remoteOneTimePublicKey,
            remoteMLKEMPublicKey: remoteMLKEMPublicKey,
            needsRemoteDeletion: needsRemoteDeletion)
    }
    
    // MARK: - Outbound Message Handling
    
    /// Handles writing a message and performing the necessary ratchet operations.
    ///
    /// This method implements the sender side of the Double Ratchet protocol for outbound
    /// messages. It manages key selection, ratchet initialization, message encryption,
    /// and signature generation. The method handles both initial message setup and
    /// subsequent message encryption with proper key rotation.
    ///
    /// ## Encryption Process
    /// 1. Validates session context and recipient identity
    /// 2. Selects appropriate keys (long-term, one-time, PQ-KEM)
    /// 3. Initializes ratchet state for sender
    /// 4. Encrypts message using ratchet encryption
    /// 5. Signs the encrypted message
    /// 6. Removes used keys and updates session state
    /// 7. Sends message through transport layer
    ///
    /// ## Key Management
    /// - Long-term keys are used for session establishment
    /// - One-time keys provide forward secrecy
    /// - PQ-KEM keys provide post-quantum security
    /// - Keys are rotated automatically when needed
    ///
    /// ## Security Considerations
    /// - All cryptographic operations use secure random number generation
    /// - Keys are validated before use to prevent attacks
    /// - Used keys are immediately removed to maintain forward secrecy
    /// - Message signatures prevent tampering and impersonation
    ///
    /// - Parameters:
    ///   - outboundTask: The outbound task message to be processed. Contains the
    ///                   plaintext message and recipient information.
    ///   - session: The current crypto session providing context and keys.
    /// - Throws: An error if the message handling fails due to missing keys,
    ///           cryptographic errors, or transport failures.
    ///
    /// Outbound jobs embed a `SessionIdentity` snapshot at enqueue time. Identity refresh can delete,
    /// archive, and recreate rows while preserving `(secretName, deviceId)`, leaving jobs with stale ids.
    /// Always reselect the current active row for that device so archived snapshots are never used to send.
    private func resolveSessionIdentityForOutbound(
        embeddedRecipient: SessionIdentity,
        session: PQSSession,
        databaseSymmetricKey: SymmetricKey
    ) async throws -> SessionIdentity {
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        let stored = try await cache.fetchSessionIdentities()

        // Pin heal/initiating explicit recipients only. Blanket "any live active"
        // would defeat intentional rebind (same-account orphan ownership for queued
        // jobs still naming a poison initialized row). StickyAdvancedRemint must
        // not steal surgical/orphan blanks (dogfood: DEE14418 mint → NACK on 995FE37C).
        if let pinned = await pinnedExplicitOutboundRecipient(
            embeddedRecipient,
            in: stored,
            session: session,
            symmetricKey: databaseSymmetricKey
        ) {
            return try await prepareStateLessPersonalSessionIdentityForOutbound(
                pinned,
                session: session,
                databaseSymmetricKey: databaseSymmetricKey)
        }

        let lookupProps: SessionIdentity.UnwrappedProps?
        if let embeddedProps = await embeddedRecipient.props(symmetricKey: databaseSymmetricKey) {
            lookupProps = embeddedProps
        } else if let direct = stored.first(where: { $0.id == embeddedRecipient.id }),
                  let directProps = await direct.props(symmetricKey: databaseSymmetricKey) {
            lookupProps = directProps
        } else {
            lookupProps = nil
        }

        guard let lookupProps else {
            throw PQSSession.SessionErrors.missingSessionIdentity
        }

        let preferredDevice = await currentDeviceConfiguration(
            secretName: lookupProps.secretName,
            deviceId: lookupProps.deviceId,
            session: session)
        if let match = await outboundSessionIdentity(
            secretName: lookupProps.secretName,
            deviceId: lookupProps.deviceId,
            in: stored,
            symmetricKey: databaseSymmetricKey,
            session: session,
            preferredDevice: preferredDevice
        ) {
            return try await prepareStateLessPersonalSessionIdentityForOutbound(
                match,
                session: session,
                databaseSymmetricKey: databaseSymmetricKey)
        }
        _ = try await session.refreshIdentities(secretName: lookupProps.secretName, forceRefresh: true)
        let refreshed = try await cache.fetchSessionIdentities()
        if let match = await outboundSessionIdentity(
            secretName: lookupProps.secretName,
            deviceId: lookupProps.deviceId,
            in: refreshed,
            symmetricKey: databaseSymmetricKey,
            session: session,
            preferredDevice: preferredDevice
        ) {
            return try await prepareStateLessPersonalSessionIdentityForOutbound(
                match,
                session: session,
                databaseSymmetricKey: databaseSymmetricKey)
        }
        throw PQSSession.SessionErrors.missingSessionIdentity
    }

    /// Returns the stored row when the task-embedded recipient is still a live
    /// heal/initiating lane that must not be rebound by `outboundSessionIdentity`.
    private func pinnedExplicitOutboundRecipient(
        _ candidate: SessionIdentity,
        in identities: [SessionIdentity],
        session: PQSSession,
        symmetricKey: SymmetricKey
    ) async -> SessionIdentity? {
        guard let stored = identities.first(where: { $0.id == candidate.id }),
              let props = await stored.props(symmetricKey: symmetricKey)
        else {
            return nil
        }
        let isLiveActive = !props.deviceName.hasPrefix(
            PQSSessionConstants.inactiveSessionDeviceNamePrefix)
        let orphanId = await session.orphanResendInitiatingSessionId(
            secretName: props.secretName,
            deviceId: props.deviceId)
        let recoveryId = await session.orphanResendRecoverySessionId(
            secretName: props.secretName,
            deviceId: props.deviceId)
        let isOrphanOrRecoveryLane =
            stored.id == orphanId || stored.id == recoveryId
        guard ExplicitOutboundRecipientPinPolicy.shouldHonorExplicitRecipient(
            isLiveActive: isLiveActive,
            isStateLess: props.state == nil,
            isOrphanOrRecoveryLane: isOrphanOrRecoveryLane
        ) else {
            return nil
        }
        return stored
    }

    private func prepareStateLessPersonalSessionIdentityForOutbound(
        _ identity: SessionIdentity,
        session: PQSSession,
        databaseSymmetricKey: SymmetricKey
    ) async throws -> SessionIdentity {
        guard let context = await session.sessionContext else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else {
            return identity
        }

        guard props.secretName == context.sessionUser.secretName,
              props.deviceId != context.sessionUser.deviceId,
              !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix),
              props.state == nil
        else {
            return identity
        }

        // Heal lanes must not be reminted: orphan initiating, recovery SessionID,
        // or control/repair blank (state-less, no curve OTK).
        let hasOrphanMark = await session.orphanResendInitiatingSessionId(
            secretName: props.secretName,
            deviceId: props.deviceId) != nil
        let hasRecovery = await session.orphanResendRecoverySessionId(
            secretName: props.secretName,
            deviceId: props.deviceId) != nil
        let isRepairLaneBlank = props.state == nil && props.oneTimePublicKey == nil
        if PersonalOutboundRefreshPolicy.shouldSkipRefresh(
            hasOrphanInitiatingMark: hasOrphanMark,
            hasRecoverySession: hasRecovery,
            isRepairLaneBlank: isRepairLaneBlank
        ) {
            logger.log(
                level: .info,
                message: "pqs.recovery.orphanResendProtectsPersonalRefresh peer=\(props.secretName) deviceId=\(props.deviceId) sessionId=\(identity.id)")
            PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendProtectsPersonalRefresh peer=\(props.secretName) deviceId=\(props.deviceId.uuidString) sessionId=\(identity.id.uuidString)")
            return identity
        }

        logger.log(
            level: .info,
            message: "Refreshing state-less personal SessionIdentity for \(props.secretName) (\(props.deviceId)) before outbound establishment")

        return try await session.resetSessionIdentityForFreshSession(
            secretName: props.secretName,
            deviceId: props.deviceId,
            sendOneTimeIdentities: true,
            reason: "stateLessPersonalOutboundRefresh")
    }
    
    /// Picks the active identity row for a peer device.
    ///
    /// Active `sessionContextId`s are intentionally random, so they are not a recency signal.
    /// If duplicate active rows survive from an older persistence failure, prefer the row whose
    /// key bundle matches the peer's currently advertised device bundle, then prefer initialized
    /// ratchet state, then preserve store order by choosing the last row.
    /// Archived (inactive) identities are excluded so they are never used for outbound encryption.
    private func bestSessionIdentity(
        secretName: String,
        deviceId: UUID,
        in identities: [SessionIdentity],
        symmetricKey: SymmetricKey,
        preferredDevice: UserDeviceConfiguration? = nil
    ) async -> SessionIdentity? {
        var candidates: [(identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, index: Int)] = []
        for (index, identity) in identities.enumerated() {
            guard let p = await identity.props(symmetricKey: symmetricKey),
                  p.secretName == secretName,
                  p.deviceId == deviceId,
                  !p.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
            candidates.append((identity, p, index))
        }

        guard candidates.isEmpty == false else { return nil }
        guard candidates.count > 1 else { return candidates[0].identity }

        let preferenceKey = peerDeviceIdentityPreferenceKey(
            secretName: secretName,
            deviceId: deviceId)
        if let preferredId = preferredSessionIdentityIdByPeerDevice[preferenceKey],
           let preferred = candidates.first(where: { $0.identity.id == preferredId }) {
            return preferred.identity
        }

        if let preferredDevice {
            let currentBundleMatches = candidates.filter { candidate in
                candidate.props.longTermPublicKey == preferredDevice.longTermPublicKey &&
                candidate.props.signingPublicKey == preferredDevice.signingPublicKey
            }
            let initializedBundleMatches = currentBundleMatches.filter { $0.props.state != nil }
            if let match = bestCandidatePreservingStoreOrder(
                initializedBundleMatches.isEmpty ? currentBundleMatches : initializedBundleMatches
            ) {
                return match.identity
            }
        }

        let initialized = candidates.filter { $0.props.state != nil }
        if initialized.count == 1 {
            return initialized[0].identity
        }

        let previouslyRekeyed = candidates.filter { $0.props.previousRekey != nil }
        if let newestRekey = previouslyRekeyed.max(by: { lhs, rhs in
            (lhs.props.previousRekey ?? .distantPast) < (rhs.props.previousRekey ?? .distantPast)
        }) {
            return newestRekey.identity
        }

        return bestCandidatePreservingStoreOrder(candidates)?.identity
    }

    /// Outbound lane for a peer device: encrypt with that peer-device’s **active**
    /// session only.
    ///
    /// Orphan remint **inserts** a new initiating session (becomes active) and
    /// encrypts that replay via explicit `recipientIdentity` on the outbound task.
    ///
    /// When an orphan mark and another initialized active both exist (transient):
    /// - **Same-account (personal/sibling):** bind outbound to the orphan recovery
    ///   row so sibling sync does not keep riding the dead maxSkipped lane.
    /// - **Cross-account (peer):** StickyAdvancedRemint — prefer the initialized
    ///   non-orphan active (one-active invariant); remint encrypt uses explicit
    ///   `recipientIdentity`.
    func outboundSessionIdentity(
        secretName: String,
        deviceId: UUID,
        in identities: [SessionIdentity],
        symmetricKey: SymmetricKey,
        session: PQSSession,
        preferredDevice: UserDeviceConfiguration? = nil
    ) async -> SessionIdentity? {
        // Drop a stale orphan mark that no longer names a live active row.
        if let orphanId = await session.orphanResendInitiatingSessionId(
            secretName: secretName,
            deviceId: deviceId
        ) {
            var orphanStillActive = false
            for identity in identities where identity.id == orphanId {
                guard let props = await identity.props(symmetricKey: symmetricKey),
                      props.secretName == secretName,
                      props.deviceId == deviceId,
                      !props.deviceName.hasPrefix(
                        PQSSessionConstants.inactiveSessionDeviceNamePrefix)
                else { continue }
                orphanStillActive = true
                break
            }
            if !orphanStillActive {
                await session.clearOrphanResendInitiatingSession(
                    secretName: secretName,
                    deviceId: deviceId)
            }
        }

        let orphanId = await session.orphanResendInitiatingSessionId(
            secretName: secretName,
            deviceId: deviceId)
        let recoveryId = await session.orphanResendRecoverySessionId(
            secretName: secretName,
            deviceId: deviceId)

        var actives: [(identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, index: Int)] = []
        for (index, identity) in identities.enumerated() {
            guard let p = await identity.props(symmetricKey: symmetricKey),
                  p.secretName == secretName,
                  p.deviceId == deviceId,
                  !p.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            else { continue }
            actives.append((identity, p, index))
        }
        guard !actives.isEmpty else { return nil }

        let localSecretName = await session.sessionContext?.sessionUser.secretName
        let isSameAccount = localSecretName == secretName
        // Prefer initiating mark, else surviving recovery SessionID (mark may clear
        // after StickyAdvancedRemint while recovery row is still the heal lane).
        let recoveryBindId = orphanId ?? recoveryId
        let orphanRow = recoveryBindId.flatMap { id in
            actives.first(where: { $0.identity.id == id })
        }
        let nonOrphanInitialized = actives.filter { candidate in
            guard let recoveryBindId else { return candidate.props.state != nil }
            return candidate.identity.id != recoveryBindId && candidate.props.state != nil
        }
        switch OutboundOrphanSessionSelectionPolicy.decision(
            isSameAccount: isSameAccount,
            hasLiveOrphanRow: orphanRow != nil,
            hasNonOrphanInitialized: !nonOrphanInitialized.isEmpty
        ) {
        case .preferOrphanRecovery:
            if let orphanRow {
                return orphanRow.identity
            }
        case .preferNonOrphanInitialized:
            clearPreferredSessionIdentity(secretName: secretName, deviceId: deviceId)
            if let match = bestCandidatePreservingStoreOrder(nonOrphanInitialized) {
                return match.identity
            }
        case .fallThroughBest:
            break
        }

        return await bestSessionIdentity(
            secretName: secretName,
            deviceId: deviceId,
            in: identities,
            symmetricKey: symmetricKey,
            preferredDevice: preferredDevice)
    }

    /// Single-device control write: resolves one session identity for
    /// `(secretName, deviceId)` and feeds exactly one outbound task. Recipient
    /// `.personalMessage` / `.nickname` is only a label — device scope is the identity.
    /// Must never call `gatherPersonalIdentities` / multi-device fan-out.
    func feedDeviceScopedControlWrite(
        message: CryptoMessage,
        secretName: String,
        deviceId: UUID,
        sharedId: String,
        session: PQSSession,
        forceFreshInitiating: Bool = false
    ) async throws {
        let identity = try await resolveControlDeliverySessionIdentity(
            secretName: secretName,
            deviceId: deviceId,
            session: session,
            forceFreshInitiating: forceFreshInitiating)
        try await feedDeviceScopedControlWrite(
            message: message,
            recipientIdentity: identity,
            sharedId: sharedId,
            session: session)
    }

    /// Device-scoped control write with a pre-resolved recipient identity.
    func feedDeviceScopedControlWrite(
        message: CryptoMessage,
        recipientIdentity: SessionIdentity,
        sharedId: String,
        session: PQSSession
    ) async throws {
        let task = EncryptableTask(
            task: .writeMessage(OutboundTaskMessage(
                message: message,
                recipientIdentity: recipientIdentity,
                localId: UUID(),
                sharedId: sharedId,
                isPersistedOutbound: false
            )),
            priority: .urgent)
        try await feedTask(task, session: session)
    }

    /// Control-plane delivery identity for resend requests and similar urgent frames.
    /// Cross-account: healthy control may ride ``outboundSessionIdentity`` (orphan →
    /// recovery → preferred); a try-all-proven poison lane requires surgical insert.
    /// Same-account: surgical mint once per continuous peer-device episode unless
    /// orphan/recovery already owns the heal lane; later NACKs reuse that episode lane.
    /// Explicit `forceFreshInitiating` (prove-fail rearm) replaces the episode lane once.
    /// Never demote-all; never write preference on try-all failure.
    func resolveControlDeliverySessionIdentity(
        secretName: String,
        deviceId: UUID,
        session: PQSSession,
        forceFreshInitiating: Bool = false
    ) async throws -> SessionIdentity {
        if forceFreshInitiating {
            clearPreferredSessionIdentity(secretName: secretName, deviceId: deviceId)
        }

        let localSecretName = await session.sessionContext?.sessionUser.secretName
        let isSameAccount = localSecretName == secretName
        let liveInitiating = await session.orphanResendInitiatingSessionId(
            secretName: secretName, deviceId: deviceId) != nil
        let liveRecovery = await session.orphanResendRecoverySessionId(
            secretName: secretName, deviceId: deviceId) != nil
        let liveOrphanOrRecovery = liveInitiating || liveRecovery
        let episodeKey = peerDeviceIdentityPreferenceKey(
            secretName: secretName,
            deviceId: deviceId)
        let callerEpisodeGeneration =
            surgicalControlEpisodeGenerationByPeerDevice[episodeKey, default: 0]

        // Orphan/recovery owns the heal lane: ride outbound selection (do not mint).
        var requireSurgical = ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
            isSameAccount: isSameAccount,
            forceFreshInitiating: forceFreshInitiating,
            liveOrphanOrRecovery: liveOrphanOrRecovery)

        // Same continuous episode: reuse the live surgical control identity unless this
        // call is an explicit prove-fail rearm (`forceFreshInitiating`).
        if !forceFreshInitiating, !liveOrphanOrRecovery {
            switch try await surgicalControlEpisodeLane(
                episodeKey: episodeKey,
                secretName: secretName,
                deviceId: deviceId,
                session: session) {
            case .live(let identity):
                auditSurgicalControlEpisodeLaneReuse(
                    identity,
                    secretName: secretName,
                    deviceId: deviceId)
                return identity
            case .stale:
                // The episode already proved normal outbound unsafe. If its owned lane
                // disappeared or became inactive, replace it surgically even for
                // cross-account control; never fall back onto the prior poison active.
                requireSurgical = true
            case .absent:
                break
            }
        }

        // Actor reentrancy: a peer resolve may be suspended inside resetSessionIdentity.
        // Park on an event-driven continuation instead of minting a second blank. Loop
        // after wake-up because another waiter may claim an explicit replacement first.
        while surgicalControlEpisodeMintInFlight.contains(episodeKey) {
            let completion = await waitForSurgicalControlEpisodeMint(episodeKey: episodeKey)
            guard completion.episodeGeneration == callerEpisodeGeneration else {
                // A caller from a newer episode must not inherit an older episode's
                // completion or failure. It will claim/reuse its own generation below.
                continue
            }
            switch completion.result {
            case .success(let sessionIdentityId):
                if !forceFreshInitiating,
                   !liveOrphanOrRecovery,
                   let reused = try await liveSurgicalControlIdentity(
                    sessionIdentityId: sessionIdentityId,
                    secretName: secretName,
                    deviceId: deviceId,
                    session: session)
                {
                    auditSurgicalControlEpisodeLaneReuse(
                        reused,
                        secretName: secretName,
                        deviceId: deviceId)
                    return reused
                }
                // Explicit rearm (or stale lane) falls through to mint a replacement
                // once the prior mint slot is free.
            case .failure(let error):
                throw error
            }
        }

        // Successful inbound decrypt wins over a resolver that began in the prior
        // generation. The now-proven preferred lane is safe for this already-pending
        // control; do not open a new surgical episode solely because this actor resumed.
        if surgicalControlEpisodeGenerationByPeerDevice[episodeKey, default: 0]
            != callerEpisodeGeneration
        {
            requireSurgical = false
        }

        if !requireSurgical {
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            var identities = try await session.cache?.fetchSessionIdentities() ?? []
            let preferredDevice = await currentDeviceConfiguration(
                secretName: secretName,
                deviceId: deviceId,
                session: session)

            if let match = await outboundSessionIdentity(
                secretName: secretName,
                deviceId: deviceId,
                in: identities,
                symmetricKey: symmetricKey,
                session: session,
                preferredDevice: preferredDevice
            ) {
                return match
            }

            _ = try await session.refreshIdentities(secretName: secretName, forceRefresh: true)
            identities = try await session.cache?.fetchSessionIdentities() ?? []
            if let match = await outboundSessionIdentity(
                secretName: secretName,
                deviceId: deviceId,
                in: identities,
                symmetricKey: symmetricKey,
                session: session,
                preferredDevice: preferredDevice
            ) {
                return match
            }
        }

        // Claim the episode mint slot synchronously before awaiting PQSSession so a
        // re-entrant resolver cannot also mint for this peer-device.
        let mintEpisodeGeneration =
            surgicalControlEpisodeGenerationByPeerDevice[episodeKey, default: 0]
        surgicalControlEpisodeMintInFlight.insert(episodeKey)
        do {
            // Surgical insert without demoting other peer-device rows (recovery / honest
            // actives must survive NACK escape). Same-account and proven-poison
            // cross-account hit this for the first NACK of an episode (or an explicit
            // prove-fail rearm).
            let fresh = try await session.resetSessionIdentityForFreshSession(
                secretName: secretName,
                deviceId: deviceId,
                sendOneTimeIdentities: false,
                reason: "resendRequestControlDelivery",
                demotePriorActives: false)
            let episodeIsCurrent =
                surgicalControlEpisodeGenerationByPeerDevice[episodeKey, default: 0]
                    == mintEpisodeGeneration
            if episodeIsCurrent {
                clearPreferredSessionIdentity(secretName: secretName, deviceId: deviceId)
                surgicalControlSessionIdentityIdByPeerDevice[episodeKey] = fresh.id
            } else {
                PQSAuditLog.log(.recovery, "pqs.recovery.controlDeliveryFreshLaneDetached peer=\(secretName) deviceId=\(deviceId.uuidString) sessionId=\(fresh.id.uuidString) reason=episodeAdvanced")
            }
            finishSurgicalControlEpisodeMint(
                episodeKey: episodeKey,
                completion: SurgicalControlEpisodeMintCompletion(
                    episodeGeneration: mintEpisodeGeneration,
                    result: .success(fresh.id)))
            PQSAuditLog.log(.recovery, "pqs.recovery.controlDeliveryFreshLane peer=\(secretName) deviceId=\(deviceId.uuidString) sessionId=\(fresh.id.uuidString) sameAccount=\(isSameAccount) surgicalRequired=\(requireSurgical) episodeCurrent=\(episodeIsCurrent)")
            return fresh
        } catch {
            finishSurgicalControlEpisodeMint(
                episodeKey: episodeKey,
                completion: SurgicalControlEpisodeMintCompletion(
                    episodeGeneration: mintEpisodeGeneration,
                    result: .failure(error)))
            throw error
        }
    }

    private enum SurgicalControlEpisodeLane {
        case absent
        case stale
        case live(SessionIdentity)
    }

    /// Validates the currently owned episode lane. If actor reentrancy replaces or
    /// clears the mapping while storage is being read, retry against the new mapping;
    /// never remove a newer lane based on an older lookup.
    private func surgicalControlEpisodeLane(
        episodeKey: String,
        secretName: String,
        deviceId: UUID,
        session: PQSSession
    ) async throws -> SurgicalControlEpisodeLane {
        while true {
            guard let episodeLaneId =
                    surgicalControlSessionIdentityIdByPeerDevice[episodeKey]
            else {
                return .absent
            }
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            let identities = try await session.cache?.fetchSessionIdentities() ?? []

            // Actor reentrancy may have cleared/replaced this map entry while awaiting
            // storage. Retry rather than deleting or returning the superseded identity.
            guard surgicalControlSessionIdentityIdByPeerDevice[episodeKey] == episodeLaneId
            else {
                continue
            }
            guard let live = await liveSurgicalControlIdentity(
                sessionIdentityId: episodeLaneId,
                secretName: secretName,
                deviceId: deviceId,
                in: identities,
                symmetricKey: symmetricKey)
            else {
                surgicalControlSessionIdentityIdByPeerDevice.removeValue(forKey: episodeKey)
                return .stale
            }
            return .live(live)
        }
    }

    private func liveSurgicalControlIdentity(
        sessionIdentityId: UUID,
        secretName: String,
        deviceId: UUID,
        session: PQSSession
    ) async throws -> SessionIdentity? {
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        let identities = try await session.cache?.fetchSessionIdentities() ?? []
        return await liveSurgicalControlIdentity(
            sessionIdentityId: sessionIdentityId,
            secretName: secretName,
            deviceId: deviceId,
            in: identities,
            symmetricKey: symmetricKey)
    }

    private func liveSurgicalControlIdentity(
        sessionIdentityId: UUID,
        secretName: String,
        deviceId: UUID,
        in identities: [SessionIdentity],
        symmetricKey: SymmetricKey
    ) async -> SessionIdentity? {
        guard let identity = identities.first(where: { $0.id == sessionIdentityId }),
              let props = await identity.props(symmetricKey: symmetricKey),
              props.secretName == secretName,
              props.deviceId == deviceId,
              !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
        else {
            return nil
        }
        return identity
    }

    private func auditSurgicalControlEpisodeLaneReuse(
        _ identity: SessionIdentity,
        secretName: String,
        deviceId: UUID
    ) {
        PQSAuditLog.log(.recovery, "pqs.recovery.controlDeliveryEpisodeLaneReused peer=\(secretName) deviceId=\(deviceId.uuidString) sessionId=\(identity.id.uuidString)")
    }

    private func waitForSurgicalControlEpisodeMint(
        episodeKey: String
    ) async -> SurgicalControlEpisodeMintCompletion {
        await withCheckedContinuation { continuation in
            surgicalControlEpisodeMintWaiters[episodeKey, default: []].append(continuation)
        }
    }

    private func finishSurgicalControlEpisodeMint(
        episodeKey: String,
        completion: SurgicalControlEpisodeMintCompletion
    ) {
        surgicalControlEpisodeMintInFlight.remove(episodeKey)
        let waiters = surgicalControlEpisodeMintWaiters.removeValue(forKey: episodeKey) ?? []
        for waiter in waiters {
            waiter.resume(returning: completion)
        }
    }

    /// Re-mints the outbound lane toward a peer device when our initiating
    /// handshake provably never completed.
    ///
    /// An initiating session pins the peer's one-time prekey at mint time and
    /// re-references it on every frame until the peer's first reply advances the
    /// ratchet. If the peer replaced its published batch since the mint (every
    /// missingOneTimeKey episode replaces it) and the retention cap evicted the
    /// old private, the peer fails every one of our frames with
    /// missingOneTimeKey — including the peerRefresh envelopes that are supposed
    /// to heal the lane, so a bilaterally dead pair can never recover on its own.
    /// The identity force-refresh path deliberately skips re-pinning initialized
    /// rows; only a lane reset heals this.
    ///
    /// Trigger and state are both event-derived: callers invoke this when the
    /// peer signals it cannot decrypt us (inbound peerRefresh request) or when we
    /// open a missingOneTimeKey episode for the peer device.
    /// `receivedMessagesCount == 0` on an initialized state proves the peer has
    /// never advanced our session; answered lanes are never touched. The repair
    /// mint (`sendOneTimeIdentities: false`) rides long-term + final ML-KEM keys
    /// only, so it cannot re-enter the missingOneTimeKey failure.
    ///
    /// - Parameter forceRemintEvenIfAnswered: same-account `missingOneTimeKeyEpisode`
    ///   only (`UnansweredInitiatingLanePolicy`). Cross-account answered lanes stay
    ///   untouched so we do not remint on every undecryptable NACK.
    func resetUnansweredInitiatingLane(
        peerSecretName: String,
        peerDeviceId: UUID,
        trigger: String,
        forceRemintEvenIfAnswered: Bool = false,
        session: PQSSession
    ) async {
        do {
            guard let localUser = await session.sessionContext?.sessionUser,
                  peerDeviceId != localUser.deviceId
            else { return }
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            let identities = try await session.getSessionIdentities(with: peerSecretName)
            var shouldRemint = false
            for identity in identities {
                guard let props = await identity.props(symmetricKey: symmetricKey),
                      props.deviceId == peerDeviceId,
                      !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix),
                      let state = props.state
                else { continue }
                if state.receivedMessagesCount > 0 {
                    // The peer has decrypted us on this session before, so the
                    // handshake is not the failure — unless same-account OTK
                    // evidence forces remint so peerRefresh cannot ride the
                    // answered poison pin (dogfood echo primary↔linked deadlock).
                    if forceRemintEvenIfAnswered {
                        shouldRemint = true
                        break
                    }
                    return
                }
                shouldRemint = true
            }
            guard shouldRemint else { return }
            _ = try await session.resetSessionIdentityForFreshSession(
                secretName: peerSecretName,
                deviceId: peerDeviceId,
                sendOneTimeIdentities: false,
                reason: "unansweredInitiatorReset")
            clearPreferredSessionIdentity(secretName: peerSecretName, deviceId: peerDeviceId)
            PQSAuditLog.log(.recovery, "pqs.recovery.unansweredInitiatorLaneReset trigger=\(trigger) peer=\(peerSecretName) deviceId=\(peerDeviceId.uuidString) forceAnswered=\(forceRemintEvenIfAnswered)")
        } catch PQSSession.SessionErrors.invalidDeviceIdentity {
            // The device is absent from the peer's current verified config
            // (re-registered install). There is no live lane to heal.
            logger.log(
                level: .debug,
                message: "Skipping unanswered-initiator reset for dead device \(peerSecretName) (\(peerDeviceId))")
        } catch {
            logger.log(
                level: .warning,
                message: "Failed unanswered-initiator reset for \(peerSecretName) (\(peerDeviceId)): \(error)")
        }
    }

    func peerDeviceIdentityPreferenceKey(
        secretName: String,
        deviceId: UUID
    ) -> String {
        "\(secretName)|\(deviceId.uuidString)"
    }

    /// Clears the continuous NACK-episode surgical escape reservation and owned
    /// control lane for a peer device. Called after successful inbound decrypt;
    /// also available for focused episode lifecycle tests.
    func clearSurgicalControlEpisode(secretName: String, deviceId: UUID) {
        let key = peerDeviceIdentityPreferenceKey(
            secretName: secretName,
            deviceId: deviceId)
        surgicalControlEscapeAttemptedPeerDevices.remove(key)
        surgicalControlSessionIdentityIdByPeerDevice.removeValue(forKey: key)
        surgicalControlEpisodeGenerationByPeerDevice[key, default: 0] &+= 1
    }

    /// Drops a stale preferred-lane pointer after automatic session reset so the
    /// next inbound/outbound selection cannot pin a deleted SessionIdentity id.
    func clearPreferredSessionIdentity(secretName: String, deviceId: UUID) {
        preferredSessionIdentityIdByPeerDevice.removeValue(
            forKey: peerDeviceIdentityPreferenceKey(
                secretName: secretName,
                deviceId: deviceId))
    }

    /// After orphan remint, demote MessageRecord's prior SessionID when it differs
    /// from the new recovery row so `bestSessionIdentity` cannot keep the poison.
    private func demotePriorOrphanMessageRecordSession(
        priorSessionId: UUID?,
        newSessionId: UUID,
        secretName: String,
        deviceId: UUID,
        session: PQSSession
    ) async {
        guard let priorSessionId, priorSessionId != newSessionId else { return }
        _ = try? await session.demoteProveFailedActive(
            sessionId: priorSessionId,
            secretName: secretName,
            deviceId: deviceId)
    }

    /// One escape-hatch initiating session (new OTK header) when settled recovery
    /// still fails to prove (peer NACK) — clears the receiver `blankForHeaderExists` trap.
    private func performOrphanEscapeRemint(
        serviceKey: String,
        remintsAfterProveFail: Int,
        priorRecordSessionId: UUID?,
        secretName: String,
        deviceId: UUID,
        sharedId: String,
        session: PQSSession
    ) async throws -> SessionIdentity {
        orphanResendRemintsAfterProveFailByServiceKey[serviceKey] = remintsAfterProveFail + 1
        orphanResendRetransportCountByServiceKey[serviceKey] = 0
        orphanResendTransportByServiceKey.removeValue(forKey: serviceKey)
        await session.clearOrphanResendInitiatingSession(
            secretName: secretName,
            deviceId: deviceId)
        let replayIdentity = try await session.resetSessionIdentityForFreshSession(
            secretName: secretName,
            deviceId: deviceId,
            sendOneTimeIdentities: true,
            reason: "orphanResend")
        await session.markOrphanResendInitiatingSession(
            secretName: secretName,
            deviceId: deviceId,
            sessionId: replayIdentity.id)
        clearPreferredSessionIdentity(secretName: secretName, deviceId: deviceId)
        await demotePriorOrphanMessageRecordSession(
            priorSessionId: priorRecordSessionId,
            newSessionId: replayIdentity.id,
            secretName: secretName,
            deviceId: deviceId,
            session: session)
        PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendRemintAfterProveFail sharedId=\(sharedId) requester=\(secretName) deviceId=\(deviceId.uuidString) newSessionId=\(replayIdentity.id.uuidString)")
        return replayIdentity
    }

    private func bestCandidatePreservingStoreOrder(
        _ candidates: [(identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, index: Int)]
    ) -> (identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, index: Int)? {
        candidates.max(by: { $0.index < $1.index })
    }

    /// Resolves a device bundle for outbound selection from **local** configuration
    /// only. Must not await live `findConfiguration` — that blocked every encrypt on
    /// contact-config REST (dogfood N1 hang / CHILD_DEVICE_2 `-1001`).
    private func currentDeviceConfiguration(
        secretName: String,
        deviceId: UUID,
        session: PQSSession
    ) async -> UserDeviceConfiguration? {
        // Only the local account bundle is available without REST. Peer DMs use the
        // SessionIdentity already chosen in chat fan-out; personal sync can use self.
        let mySecret = await session.sessionContext?.sessionUser.secretName
        guard secretName == mySecret,
              let configuration = await session.sessionContext?.activeUserConfiguration,
              let devices = try? configuration.getVerifiedDevices().map({
                  try configuration.deviceWithCurrentKeyBundle($0)
              })
        else {
            return nil
        }
        return devices.first(where: { $0.deviceId == deviceId })
    }
    
    private func handleWriteMessage(
        outboundTask: OutboundTaskMessage,
        session: PQSSession
    ) async throws {
        self.session = session
        var outboundTask = outboundTask
        
        guard let sessionContext = await session.sessionContext else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        if let pendingTransport = pendingOutboundTransport(sharedId: outboundTask.sharedId) {
            try await sendPendingOutboundTransport(
                pendingTransport,
                outboundTask: outboundTask,
                session: session)
            return
        }
        
        var sessionIdentity = try await resolveSessionIdentityForOutbound(
            embeddedRecipient: outboundTask.recipientIdentity,
            session: session,
            databaseSymmetricKey: databaseSymmetricKey
        )
        
        if await session.keyLoadingState == .rotating {
            if let secretName = await sessionIdentity.props(symmetricKey: databaseSymmetricKey)?.secretName,
               let deviceId = await sessionIdentity.props(symmetricKey: databaseSymmetricKey)?.deviceId {
                let refreshedIdentities = try await session.refreshIdentities(secretName: secretName, forceRefresh: true)
                let preferredDevice = await currentDeviceConfiguration(
                    secretName: secretName,
                    deviceId: deviceId,
                    session: session)
                if let refreshed = refreshedIdentities.first(where: { $0.id == sessionIdentity.id }) {
                    sessionIdentity = refreshed
                } else if let refreshed = await bestSessionIdentity(
                    secretName: secretName,
                    deviceId: deviceId,
                    in: refreshedIdentities,
                    symmetricKey: databaseSymmetricKey,
                    preferredDevice: preferredDevice
                ) {
                    sessionIdentity = refreshed
                }
            }
        }
        
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw PQSSession.SessionErrors.propsError
        }
        
        let results = try await loadKeys(
            props: props,
            sessionContext: sessionContext,
            session: session)
        
        // If we are intially attempting communication with a contact, we need to first send a session identity created message for the contact to delete their one time keys from being used again, the recipient can know what keys via key identities that are sent. This call also needs to send the sender's one time key identities so that the recipient also knows what one times to create their session with. We get the sender's next.
        var transportEvent: TransportEvent?
        if let data = outboundTask.message.transportInfo {
            do {
                let event = try BinaryDecoder().decode(TransportEvent.self, from: data)
                transportEvent = event
                switch event {
                case .sessionReestablishment(let envelope):
                    logger.log(
                        level: .info,
                        message: "Prepared to send session reestablishment: \(envelope.kind.rawValue) intent=\(envelope.intentId?.uuidString ?? "nil") epoch=\(envelope.epoch)")
                case .linkedDeviceReprovisioning(let bundle):
                    logger.log(level: .info, message: "Prepared to send linked-device reprovisioning for target=\(bundle.targetDeviceId.uuidString)")
                case .synchronizeOneTimeKeys(var info):
                    info.senderCurveId = results.localOneTimePrivateKey?.id.uuidString
                    info.senderMLKEMId = results.localMLKEMPrivateKey.id.uuidString
                    transportEvent = .synchronizeOneTimeKeys(info)
                    let encodedData = try BinaryEncoder().encode(info)
                    await session.setAddingContact(encodedData)
                    outboundTask.message.transportInfo = encodedData
                case .refreshOneTimeKeys:
                    logger.log(level: .info, message: "Prepared to send one-time-key refresh request")
                case .publishedOneTimeKeysReplenished:
                    logger.log(level: .info, message: "Prepared to send one-time-key replenish acknowledgement")
                case .requestMessageResend, .messageResendUnavailable:
                    // DEAD LEGACY (strict §4.1): encrypted retry is no longer emitted.
                    // Kept for TransportEvent exhaustiveness; delete after dogfood confirms unused.
                    break
                }
            } catch {}
        }
        let localLTK = (try? Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: sessionContext.sessionUser.deviceKeys.longTermPrivateKey
        ).publicKey.rawRepresentation.base64EncodedString().prefix(10)) ?? "invalidLTK"
        if shouldEmitKeyPayloadLogs {
            logger.log(level: .debug, message: """
                senderInit: recipient=\(props.secretName)\n
                sender=\(await session.sessionContext?.sessionUser.secretName ?? "nil")\n
                localLTK=\(localLTK) localOTK=\(results.localOneTimePrivateKey?.id.uuidString ?? "nil")\n
                localMLKEM=\(results.localMLKEMPrivateKey.id.uuidString)\n
                remoteLTK=\(results.remoteLongTermPublicKey.prefix(10).base64EncodedString())\n
                remoteOTK=\(results.remoteOneTimePublicKey?.id.uuidString ?? "nil")\n
                remoteMLKEM=\(results.remoteMLKEMPublicKey.id.uuidString)
                """)
        }
        
        let outboundSessionIdentityDataBeforeAttempt = sessionIdentity.data
        let persistenceJob = processingOutboundJobBySharedId[outboundTask.sharedId]
        if persistenceJob != nil {
            atomicOutboundPreparationIdentityIds.insert(sessionIdentity.id)
        }
        let signedMessage: SignedRatchetMessage
        do {
            try await ratchetManager.senderInitialization(
                sessionIdentity: sessionIdentity,
                sessionSymmetricKey: databaseSymmetricKey,
                remoteKeys: RemoteKeys(
                    longTerm: .init(results.remoteLongTermPublicKey),
                    oneTime: results.remoteOneTimePublicKey,
                    mlKEM: results.remoteMLKEMPublicKey),
                localKeys: LocalKeys(
                    longTerm: .init(sessionContext.sessionUser.deviceKeys.longTermPrivateKey),
                    oneTime: results.localOneTimePrivateKey,
                    mlKEM: results.localMLKEMPrivateKey))

            if let sessionDelegate = await session.sessionDelegate {
                outboundTask.message = sessionDelegate.updateCryptoMessageMetadata(
                    outboundTask.message,
                    sharedMessageId: outboundTask.sharedId)
            }

            let encodedData = try BinaryEncoder().encode(outboundTask.message)
            let ratchetedMessage = try await ratchetManager.ratchetEncrypt(
                plainText: encodedData,
                sessionId: sessionIdentity.id)
            signedMessage = try await signRatchetMessage(message: ratchetedMessage, session: session)
        } catch {
            atomicOutboundPreparationIdentityIds.remove(sessionIdentity.id)
            // Discard in-place mutations on encrypt failure. Do not remint a
            // new SessionIdentity UUID (`laneReplaced`) — that broke ledger matching.
            try await restoreSessionIdentityData(
                sessionIdentity,
                data: outboundSessionIdentityDataBeforeAttempt,
                session: session,
                reason: "outbound ratchet failed before transport send")
            throw error
        }
        
        // §4.1: mint a unique envelope MessageID per recipient-device encrypt.
        // Logical sharedId stays stable for chat/media/plaintext lookup and resend.
        let envelopeMessageId = EnvelopeMessageIdentityPolicy.mintEnvelopeMessageId()
        let transportMetadata = SignedRatchetMessageMetadata(
            secretName: props.secretName,
            deviceId: props.deviceId,
            recipient: outboundTask.message.recipient,
            transportMetadata: outboundTask.message.transportInfo,
            sharedMessageId: outboundTask.sharedId,
            envelopeMessageId: envelopeMessageId,
            transportEvent: transportEvent,
            requiresServerAck: outboundTask.isPersistedOutbound)
        if let persistenceJob {
            guard let cache = await session.cache,
                  var jobProps = await persistenceJob.props(symmetricKey: databaseSymmetricKey) else {
                atomicOutboundPreparationIdentityIds.remove(sessionIdentity.id)
                try await restoreSessionIdentityData(
                    sessionIdentity,
                    data: outboundSessionIdentityDataBeforeAttempt,
                    session: session,
                    reason: "prepared outbound job unavailable")
                throw PQSSession.SessionErrors.databaseNotInitialized
            }
            let prepared = JobModel.PreparedOutbound(
                signedMessage: signedMessage,
                secretName: transportMetadata.secretName,
                deviceId: transportMetadata.deviceId,
                recipient: transportMetadata.recipient,
                transportMetadata: transportMetadata.transportMetadata,
                sharedMessageId: transportMetadata.sharedMessageId,
                envelopeMessageId: transportMetadata.envelopeMessageId,
                transportEvent: transportMetadata.transportEvent,
                requiresServerAck: transportMetadata.requiresServerAck,
                sessionIdentityId: sessionIdentity.id,
                needsRemoteDeletion: results.needsRemoteDeletion,
                curveOneTimeKeyId: results.localOneTimePrivateKey?.id.uuidString,
                mlKEMOneTimeKeyId: results.localMLKEMPrivateKey.id.uuidString)
            jobProps.preparedOutbound = prepared
            do {
                _ = try await persistenceJob.updateProps(
                    symmetricKey: databaseSymmetricKey,
                    props: jobProps)
                try await cache.commitPreparedOutbound(
                    sessionIdentity: sessionIdentity,
                    job: persistenceJob)
            } catch {
                atomicOutboundPreparationIdentityIds.remove(sessionIdentity.id)
                jobProps.preparedOutbound = nil
                _ = try? await persistenceJob.updateProps(
                    symmetricKey: databaseSymmetricKey,
                    props: jobProps)
                try await restoreSessionIdentityData(
                    sessionIdentity,
                    data: outboundSessionIdentityDataBeforeAttempt,
                    session: session,
                    reason: "atomic prepared outbound commit failed")
                throw error
            }
        }
        atomicOutboundPreparationIdentityIds.remove(sessionIdentity.id)
        let shouldRememberPendingTransport = shouldRememberPendingOutboundTransport(outboundTask.message)
        if shouldRememberPendingTransport {
            rememberPendingOutboundTransport(
                sharedId: outboundTask.sharedId,
                message: signedMessage,
                metadata: transportMetadata,
                sessionIdentityId: sessionIdentity.id,
                needsRemoteDeletion: results.needsRemoteDeletion,
                curveOneTimeKeyId: results.localOneTimePrivateKey?.id.uuidString,
                mlKEMOneTimeKeyId: results.localMLKEMPrivateKey.id.uuidString)
        }
        
        guard let transportDelegate = await session.transportDelegate else {
            PQSAuditLog.log(.send, "pqs.send.transportMissing sharedId=\(outboundTask.sharedId)", level: .error)
            throw PQSSession.SessionErrors.transportNotInitialized
        }
        
        try await transportDelegate.sendMessage(signedMessage, metadata: transportMetadata)
        
        PQSAuditLog.log(.send, "pqs.send.deviceTransportOk sharedId=\(outboundTask.sharedId) envelopeMessageId=\(envelopeMessageId) recipientSecret=\(props.secretName) recipientDeviceId=\(props.deviceId.uuidString) sessionIdentityId=\(sessionIdentity.id.uuidString) recipient=\(outboundTask.message.recipient.auditRecipientTag) persisted=\(outboundTask.isPersistedOutbound)",
            level: .info)
        
        // MessageRecord-lite: envelope id + logical sharedId + encrypting SessionID.
        let priorAttempt = await session.outboundDeviceSendRecord(
            sharedId: outboundTask.sharedId,
            recipientDeviceId: props.deviceId)?.resendAttempt ?? -1
        let isOrphanReplayForAttempt =
            await session.isOrphanResendInitiatingSession(
                secretName: props.secretName,
                deviceId: props.deviceId,
                sessionId: sessionIdentity.id)
            || pendingResendReplayBySharedId[outboundTask.sharedId] != nil
        await session.recordOutboundDeviceSend(
            sharedId: outboundTask.sharedId,
            recipientSecretName: props.secretName,
            recipientDeviceId: props.deviceId,
            sessionIdentityId: sessionIdentity.id,
            envelopeMessageId: envelopeMessageId,
            resendAttempt: isOrphanReplayForAttempt ? max(0, priorAttempt) + 1 : 0)
        let isOrphanReplay = isOrphanReplayForAttempt
        if isOrphanReplay {
            PQSAuditLog.log(.recovery, "pqs.recovery.messageRecordSessionId=\(sessionIdentity.id.uuidString) sharedId=\(outboundTask.sharedId) recipientDeviceId=\(props.deviceId.uuidString)")
            rememberOrphanResendTransport(
                requestingDeviceId: props.deviceId,
                sharedId: outboundTask.sharedId,
                message: signedMessage,
                metadata: transportMetadata,
                sessionIdentityId: sessionIdentity.id,
                needsRemoteDeletion: false,
                curveOneTimeKeyId: nil,
                mlKEMOneTimeKeyId: results.localMLKEMPrivateKey.id.uuidString)
        }
        logRecoveryTransportSendSuccess(transportEvent, sharedId: outboundTask.sharedId)
        // DEAD LEGACY: encrypted TransportEvent.requestMessageResend transport bookkeeping
        // removed. Retry attempt spend is owned by authenticated OOB submit.
        // if case .requestMessageResend(let request) = transportEvent { ... }
        await noteResendReplayTransported(sharedId: outboundTask.sharedId)
        if shouldRememberPendingTransport {
            pendingOutboundTransportBySharedId.removeValue(forKey: outboundTask.sharedId)
        }
        await completeResponderPeerRefreshIfNeeded(
            transportEvent,
            peerSecretName: props.secretName,
            peerDeviceId: props.deviceId,
            session: session)

        await rememberRecentOutboundReplayIfNeeded(outboundTask, session: session)

        if outboundTask.isPersistedOutbound || transportMetadata.requiresServerAck {
            registerUnackedServerAccept(
                pending: PendingOutboundTransport(
                    message: signedMessage,
                    metadata: transportMetadata,
                    sessionIdentityId: sessionIdentity.id,
                    needsRemoteDeletion: results.needsRemoteDeletion,
                    curveOneTimeKeyId: results.localOneTimePrivateKey?.id.uuidString,
                    mlKEMOneTimeKeyId: results.localMLKEMPrivateKey.id.uuidString,
                    createdAt: Date()),
                localId: outboundTask.localId,
                sharedId: outboundTask.sharedId,
                session: session)
        } else {
            await markPersistedOutboundPastSendingIfNeeded(session: session, localMessageId: outboundTask.localId)
        }
        
        // Perform remote key deletion only after a successful send
        if results.needsRemoteDeletion {
            try await removeKeys(
                session: session,
                curveId: results.localOneTimePrivateKey?.id.uuidString,
                mlKEMId: results.localMLKEMPrivateKey.id.uuidString)
        }
    }

    private func completeResponderPeerRefreshIfNeeded(
        _ event: TransportEvent?,
        peerSecretName: String,
        peerDeviceId: UUID,
        session: PQSSession
    ) async {
        guard case .sessionReestablishment(let envelope) = event,
              envelope.kind == .peerRefresh,
              envelope.isResponse
        else {
            return
        }

        let pending = await session.takePendingResendsAfterReestablishment(
            sender: peerSecretName,
            deviceId: peerDeviceId)
        await session.endReestablishmentEpisode(
            sender: peerSecretName,
            deviceId: peerDeviceId)
        await sendDeferredResendRequests(
            pending,
            session: session,
            reason: "peerRefresh response transported")
        logger.log(
            level: .info,
            message: "Completed responder peerRefresh on device lane peer=\(peerSecretName) deviceId=\(peerDeviceId)")
    }
    
    // MARK: - Inbound Message Handling
    
    /// Handles streaming a message and performing the necessary ratchet operations.
    ///
    /// This method implements the recipient side of the Double Ratchet protocol for inbound
    /// messages. It verifies message signatures, initializes ratchet state, decrypts messages,
    /// and processes the decrypted content. The method handles both initial message setup
    /// and subsequent message decryption with proper key management.
    ///
    /// ## Decryption Process
    /// 1. Verifies message signature and extracts ratchet message
    /// 2. Initializes ratchet state for recipient
    /// 3. Decrypts message using ratchet decryption
    /// 4. Processes decrypted message content
    /// 5. Removes used keys and updates session state
    /// 6. Handles message persistence and delivery
    ///
    /// ## Message Processing
    /// - Messages are verified for authenticity before processing
    /// - Decrypted content is validated and routed appropriately
    /// - Session state is updated to reflect new message
    /// - Used keys are cleaned up to maintain forward secrecy
    ///
    /// ## Security Considerations
    /// - Message signatures are verified to prevent impersonation
    /// - Ratchet state prevents replay attacks
    /// - Keys are validated before use to prevent attacks
    /// - Failed decryption attempts are handled gracefully
    ///
    /// - Parameters:
    ///   - inboundTask: The inbound task message to be processed. Contains the
    ///                  encrypted message and sender information.
    ///   - session: The current crypto session providing context and keys.
    /// - Throws: An error if the message handling fails due to invalid signatures,
    ///           missing keys, or cryptographic errors.
    private func handleStreamMessage(
        inboundTask: InboundTaskMessage,
        session: PQSSession
    ) async throws {
        // T13: accepted-envelope ledger covers non-persisted successes (nudgeLocal).
        // Re-emit spool ACK; never re-enter ratchet / NACK / remint.
        if try await session.hasAcceptedEnvelope(
            senderSecretName: inboundTask.senderSecretName,
            senderDeviceId: inboundTask.senderDeviceId,
            envelopeMessageId: inboundTask.sharedMessageId
        ) {
            PQSAuditLog.log(.recovery, "pqs.recovery.redeliveryDropped reason=alreadyAccepted sharedId=\(inboundTask.sharedMessageId) logical=\(inboundTask.resolvedLogicalSharedId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
            let acceptedSharedId = inboundTask.sharedMessageId
            let acceptedDelegate = await session.sessionDelegate
            await session.scheduleTransportProtocolWork {
                await acceptedDelegate?.inboundCiphertextAccepted(sharedMessageId: acceptedSharedId)
            }
            return
        }

        // Redelivery ingress guard: offline queues redeliver un-ACKed frames on
        // every reconnect. Lookup by logical id (chat row) with sender-device match.
        let logicalLookupId = inboundTask.resolvedLogicalSharedId
        if let existing = try await session.cache?.fetchMessageIfExists(sharedId: logicalLookupId) {
            let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
            if let existingProps = await existing.props(symmetricKey: databaseSymmetricKey),
               existingProps.senderSecretName == inboundTask.senderSecretName,
               existingProps.senderDeviceId == inboundTask.senderDeviceId
            {
                PQSAuditLog.log(.recovery, "pqs.recovery.redeliveryDropped reason=alreadyPersisted sharedId=\(inboundTask.sharedMessageId) logical=\(logicalLookupId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
                try await session.markEnvelopeAccepted(
                    senderSecretName: inboundTask.senderSecretName,
                    senderDeviceId: inboundTask.senderDeviceId,
                    envelopeMessageId: inboundTask.sharedMessageId,
                    logicalSharedId: logicalLookupId)
                let acceptedSharedId = inboundTask.sharedMessageId
                let acceptedDelegate = await session.sessionDelegate
                await session.scheduleTransportProtocolWork {
                    await acceptedDelegate?.inboundCiphertextAccepted(sharedMessageId: acceptedSharedId)
                }
                return
            }
        }

        let verificationResult = try await verifyEncryptedMessage(session: session, inboundTask: inboundTask)
        let rollbackSymmetricKey = try await session.getDatabaseSymmetricKey()
        let rollbackPeerIdentities = try await session.cache?.fetchSessionIdentities().asyncFilter { identity in
            guard let props = await identity.props(symmetricKey: rollbackSymmetricKey) else {
                return false
            }
            return props.secretName == inboundTask.senderSecretName
                && props.deviceId == inboundTask.senderDeviceId
        } ?? []
        let rollbackIdentityData = Dictionary(
            uniqueKeysWithValues: rollbackPeerIdentities.map { ($0.id, $0.data) })
        
        do {
            // Inbound decrypt: try the preferred/current session, then other
            // actives, then inactive sessions. Whichever decrypts becomes current
            // (activate = promote inactive / demote sibling actives).
            let preferredSessionIdentity = verificationResult.sessionIdentity
            let preferredSessionIdentityDataBeforeAttempt = preferredSessionIdentity.data
            var decryptionSessionIdentity = preferredSessionIdentity
            var decryptedData: Data
            do {
                try await initializeRecipient(
                    sessionIdentity: preferredSessionIdentity,
                    session: session,
                    ratchetMessage: verificationResult.ratchetMessage)
                
                decryptedData = try await ratchetManager.ratchetDecrypt(
                    verificationResult.ratchetMessage,
                    sessionId: preferredSessionIdentity.id)
            } catch {
                let preferredError = error
                try await restoreSessionIdentityData(
                    preferredSessionIdentity,
                    data: preferredSessionIdentityDataBeforeAttempt,
                    session: session,
                    reason: "preferred inbound decrypt failed before multi-session fallback")
                let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
                let activeIdentities = try await session.getSessionIdentities(
                    with: inboundTask.senderSecretName)
                let alternateActiveIdentities = await activeIdentities.asyncFilter { identity in
                    guard identity.id != preferredSessionIdentity.id,
                          let props = await identity.props(symmetricKey: databaseSymmetricKey)
                    else {
                        return false
                    }
                    return props.deviceId == inboundTask.senderDeviceId
                }
                // Inbound try-all: stateful Active → Archives → state-less Active.
                // Blank PQXDH runs only on state-less rows already in (or ensured into)
                // the device record — not a gated post-failure matching mint.
                //
                // activeFirstInboundPass: try actives + state-less first. Archive walk is
                // deferred to a `.background` job via deferArchivedInboundFallback so
                // fresher `.urgent` ciphertext is not HOL-blocked on the single consumer.
                let statefulAlternates = await alternateActiveIdentities.asyncFilter { identity in
                    (await identity.props(symmetricKey: databaseSymmetricKey))?.state != nil
                }
                let stateLessAlternates = await alternateActiveIdentities.asyncFilter { identity in
                    (await identity.props(symmetricKey: databaseSymmetricKey))?.state == nil
                }
                let archivedIdentities = try await session.fetchArchivedSessionIdentities(
                    secretName: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)
                let archiveToken = ArchivedInboundFallbackToken(
                    senderSecretName: inboundTask.senderSecretName,
                    senderDeviceId: inboundTask.senderDeviceId,
                    envelopeMessageId: inboundTask.sharedMessageId,
                    fingerprint: PQSSession.nackFrameFingerprint(for: inboundTask))
                let includeArchivedFallback =
                    archivedInboundFallbackPasses.contains(archiveToken.storageKey)
                    || archivedInboundFallbackPasses.contains(inboundTask.sharedMessageId)
                if includeArchivedFallback {
                    archivedInboundFallbackPasses.remove(archiveToken.storageKey)
                    archivedInboundFallbackPasses.remove(inboundTask.sharedMessageId)
                }
                // Mark exhausted when this pass actually walks archives (success or
                // total failure). Prevents re-defer on the same ciphertext.
                let shouldMarkArchivePassExhausted = includeArchivedFallback

                var fallbackData: Data?
                // Per-candidate failure classes for the rollback audit; without this the
                // try-all loop swallows every error and only the preferred error surfaces.
                var attemptFailures: [String] = [
                    "preferred:\(preferredSessionIdentity.id.uuidString.prefix(8)):\(preferredError)"
                ]

                func tryDecryptCandidates(
                    _ candidates: [(identity: SessionIdentity, kind: String)]
                ) async {
                    for candidate in candidates {
                        let fallbackIdentity = candidate.identity
                        let fallbackDataBeforeAttempt = fallbackIdentity.data
                        do {
                            try await initializeRecipient(
                                sessionIdentity: fallbackIdentity,
                                session: session,
                                ratchetMessage: verificationResult.ratchetMessage)

                            let data = try await ratchetManager.ratchetDecrypt(
                                verificationResult.ratchetMessage,
                                sessionId: fallbackIdentity.id)
                            logger.log(
                                level: .info,
                                message: "\(candidate.kind) identity fallback succeeded for \(inboundTask.senderSecretName) (\(inboundTask.senderDeviceId))")
                            decryptionSessionIdentity = fallbackIdentity
                            fallbackData = data
                            return
                        } catch {
                            attemptFailures.append(
                                "\(candidate.kind):\(fallbackIdentity.id.uuidString.prefix(8)):\(error)")
                            try? await restoreSessionIdentityData(
                                fallbackIdentity,
                                data: fallbackDataBeforeAttempt,
                                session: session,
                                reason: "inbound identity fallback attempt failed")
                        }
                    }
                }

                let inboundHeader = verificationResult.ratchetMessage.header
                let archivedBlanks = await archivedIdentities.asyncFilter { identity in
                    (await identity.props(symmetricKey: databaseSymmetricKey))?.state == nil
                }
                // Active-first never walks full archives, but blankForHeaderExists
                // counts archived blanks. Include the single header-matched archived
                // blank in the active pass so demoted blanks are not invisible until
                // a (possibly exhausted) archive defer.
                let headerMatchedArchivedBlank = await archivedBlanks.asyncFirst(where: { identity in
                    guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else {
                        return false
                    }
                    return props.longTermPublicKey == inboundHeader.remoteLongTermPublicKey
                        && props.oneTimePublicKey?.id == inboundHeader.remoteOneTimePublicKey?.id
                })

                if includeArchivedFallback {
                    // Background pass: archives only (actives already failed).
                    await tryDecryptCandidates(
                        archivedIdentities.map { (identity: $0, kind: "archived") })
                } else {
                    // activeFirstInboundPass — decryptInboundActiveOnly candidates,
                    // plus header-matched archived blank when policy allows.
                    var activeFirstCandidates =
                        statefulAlternates.map { (identity: $0, kind: "active") }
                        + stateLessAlternates.map { (identity: $0, kind: "stateLess") }
                    if let matched = headerMatchedArchivedBlank,
                       InboundInitiatingSlotPolicy.shouldTryArchivedHeaderMatchBeforeEnsureSkip(
                           blankForHeaderExists: true,
                           matchedIsArchived: true,
                           includeArchivedFallback: false)
                    {
                        activeFirstCandidates.append((identity: matched, kind: "archivedHeaderMatch"))
                    }
                    await tryDecryptCandidates(activeFirstCandidates)
                }

                // Every existing row failed. The receiver must always be able to
                // build the matching session from the initiating frame itself, so
                // ensure a blank from this frame's header even when stale blanks
                // exist — a blank minted from older key material can never PQXDH
                // this frame and must not block recovery. Dedupe on the header's
                // key material (remote LTK + OTK id): if a blank for this exact
                // header already exists (it just failed in try-all above), a fresh
                // one would fail identically, so redelivered copies don't mint storms.
                if fallbackData == nil, !includeArchivedFallback {
                    if let preferredProps = await preferredSessionIdentity.props(
                        symmetricKey: databaseSymmetricKey)
                    {
                        let header = inboundHeader
                        var blankRows = stateLessAlternates
                        if preferredProps.state == nil {
                            blankRows.append(preferredSessionIdentity)
                        }
                        // Archived blanks count too: a prior ensured blank demoted by a
                        // sibling's activation is still in the try-all set above, so a
                        // fresh mint for the same header would fail identically. Without
                        // this, every activate-then-fail cycle mints a new blank whose
                        // archival evicts a real stateful snapshot at the retention cap.
                        blankRows.append(contentsOf: archivedBlanks)
                        let blankForHeaderExists = await blankRows.asyncFirst(where: { identity in
                            guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else {
                                return false
                            }
                            return props.longTermPublicKey == header.remoteLongTermPublicKey
                                && props.oneTimePublicKey?.id == header.remoteOneTimePublicKey?.id
                        }) != nil
                        if !InboundInitiatingSlotPolicy.shouldEnsureInboundBlank(
                            blankForHeaderExists: blankForHeaderExists)
                        {
                            PQSAuditLog.log(.recovery, "pqs.recovery.inboundInitiatingSlotEnsureSkipped reason=blankForHeaderExists peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
                        } else {
                            do {
                                let ensured = try await session.ensureInboundInitiatingSessionIdentity(
                                    secretName: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId,
                                    longTermPublicKey: header.remoteLongTermPublicKey,
                                    signingPublicKey: preferredProps.signingPublicKey,
                                    oneTimePublicKey: header.remoteOneTimePublicKey,
                                    mlKEMPublicKey: header.remoteMLKEMPublicKey,
                                    deviceNameHint: preferredProps.deviceName)
                                PQSAuditLog.log(.recovery, "pqs.recovery.inboundInitiatingSlotEnsured peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) sessionId=\(ensured.id.uuidString)")
                                let ensuredDataBeforeAttempt = ensured.data
                                do {
                                    try await initializeRecipient(
                                        sessionIdentity: ensured,
                                        session: session,
                                        ratchetMessage: verificationResult.ratchetMessage)
                                    let data = try await ratchetManager.ratchetDecrypt(
                                        verificationResult.ratchetMessage,
                                        sessionId: ensured.id)
                                    logger.log(
                                        level: .info,
                                        message: "stateLess identity fallback succeeded for \(inboundTask.senderSecretName) (\(inboundTask.senderDeviceId))")
                                    decryptionSessionIdentity = ensured
                                    fallbackData = data
                                } catch {
                                    attemptFailures.append(
                                        "ensured:\(ensured.id.uuidString.prefix(8)):\(error)")
                                    try? await restoreSessionIdentityData(
                                        ensured,
                                        data: ensuredDataBeforeAttempt,
                                        session: session,
                                        reason: "inbound identity fallback attempt failed")
                                }
                            } catch {
                                logger.log(
                                    level: .warning,
                                    message: "pqs.recovery.inboundInitiatingSlotEnsureFailed peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) error=\(error)")
                                PQSAuditLog.log(.recovery, "pqs.recovery.inboundInitiatingSlotEnsureFailed peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) error=\(error)")
                            }
                        }
                    }
                }

                guard let data = fallbackData else {
                    let frameFingerprint = PQSSession.nackFrameFingerprint(for: inboundTask)
                    if shouldMarkArchivePassExhausted {
                        markArchivedInboundFallbackExhausted(
                            sharedId: inboundTask.sharedMessageId,
                            sender: inboundTask.senderSecretName,
                            deviceId: inboundTask.senderDeviceId,
                            fingerprint: frameFingerprint)
                    }
                    // Active-first miss with archives remaining: defer archive try-all
                    // to a background job so urgent inbound can proceed.
                    if !includeArchivedFallback, !archivedIdentities.isEmpty {
                        await deferArchivedInboundFallback(
                            inboundTask: inboundTask,
                            session: session)
                    }
                    // Inbound decrypt: no session decrypted — discard mutations and abort.
                    try await restoreSessionIdentityData(
                        preferredSessionIdentity,
                        data: preferredSessionIdentityDataBeforeAttempt,
                        session: session,
                        reason: "active and archived inbound decrypt attempts failed")
                    PQSAuditLog.log(.recovery, "pqs.recovery.laneRolledBack reason=active and archived inbound decrypt attempts failed peer=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) attempts=[\(attemptFailures.joined(separator: "; "))]")
                    // Do NOT write the failed try-first id into the preference map here.
                    // Dogfood 2026-07-25: that armed preferredFailedInTryAll on every
                    // poison redelivery → demoteProveFailedActive walked unique session
                    // ids (nudge primary: 92 demotes / 4k blankForHeader skips against
                    // linked). Preference stays success-only; demote remains rearm-gated.
                    throw preferredError
                }
                if shouldMarkArchivePassExhausted {
                    markArchivedInboundFallbackExhausted(
                        sharedId: inboundTask.sharedMessageId,
                        sender: inboundTask.senderSecretName,
                        deviceId: inboundTask.senderDeviceId,
                        fingerprint: PQSSession.nackFrameFingerprint(for: inboundTask))
                }
                decryptedData = data
            }

#if DEBUG
            if let transform = await session._testDecryptedPayloadTransform {
                decryptedData = transform(decryptedData)
            }
#endif
            
            guard !decryptedData.isEmpty else {
                throw PQSSession.SessionErrors.sessionDecryptionError
            }
            let decodedMessage: CryptoMessage
            do {
                decodedMessage = try BinaryDecoder().decode(CryptoMessage.self, from: decryptedData)
            } catch {
                throw PQSSession.SessionErrors.sessionDecryptionError
            }

            var canSaveMessage = true
            
            if let sessionDelegate = await session.sessionDelegate {
                canSaveMessage = await sessionDelegate.processMessage(
                    decodedMessage,
                    senderSecretName: inboundTask.senderSecretName,
                    senderDeviceId: inboundTask.senderDeviceId)
            }

            if let transportInfo = decodedMessage.transportInfo,
               let event = try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo) {
                var processedReestablishment: SessionReestablishmentEnvelope?
                do {
                    switch event {
                    case .sessionReestablishment(let envelope):
                        canSaveMessage = false

                        guard let context = await session.sessionContext else {
                            throw PQSSession.SessionErrors.sessionNotInitialized
                        }
                        if let targetDeviceId = envelope.targetDeviceId,
                           targetDeviceId != context.sessionUser.deviceId {
                            logger.log(
                                level: .info,
                                message: "Ignoring peerRefresh for another local device target=\(targetDeviceId) local=\(context.sessionUser.deviceId)")
                            decryptionSessionIdentity = try await finalizeAcceptedInbound(
                                decryptionSessionIdentity,
                                inboundTask: inboundTask,
                                session: session)
                            return
                        }

                        // Decrypt path already activated the proven session (inbound decrypt).

                        // Receiver-side coalescing: drop duplicates and stale-epoch replays from
                        // an offline mailbox before any expensive work or delegate dispatch.
                        let dedupDecision = await session.recordReceivedSessionReestablishment(
                            envelope: envelope,
                            senderDeviceId: inboundTask.senderDeviceId)

                        switch dedupDecision {
                        case .skipDuplicate:
                            logger.log(
                                level: .info,
                                message: "[control-event] coalesced duplicate kind=\(envelope.kind.rawValue) sender=\(inboundTask.senderDeviceId) intent=\(envelope.intentId?.uuidString ?? "nil") epoch=\(envelope.epoch)"
                            )
                            decryptionSessionIdentity = try await finalizeAcceptedInbound(
                                decryptionSessionIdentity,
                                inboundTask: inboundTask,
                                session: session)
                            return
                        case .skipStale:
                            logger.log(
                                level: .info,
                                message: "[control-event] dropping stale kind=\(envelope.kind.rawValue) sender=\(inboundTask.senderDeviceId) epoch=\(envelope.epoch)"
                            )
                            decryptionSessionIdentity = try await finalizeAcceptedInbound(
                                decryptionSessionIdentity,
                                inboundTask: inboundTask,
                                session: session)
                            return
                        case .process:
                            processedReestablishment = envelope
                            break
                        }

                        let kind = envelope.kind
                        let disposition = try sessionReestablishmentDisposition(
                            for: kind,
                            inboundTask: inboundTask,
                            decodedMessage: decodedMessage,
                            context: context)
                        var shouldSendRefreshResponse = false
                        switch disposition {
                        case .ignore:
                            logger.log(level: .warning, message: "Ignoring unauthorized session reestablishment control event")
                        case .refreshOnly:
                            shouldSendRefreshResponse = kind == .peerRefresh && !envelope.isResponse
                            break
                        case .rotateCurrentDevice:
                            // Sync local activeUserConfiguration before checking signing-key
                            // agreement; the post-disposition refresh below cannot cover this
                            // because the check needs to run on fresh state.
                            if await session.shouldForceIdentityRefresh(secretName: inboundTask.senderSecretName) {
                                _ = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
                            }
                            if await session.localSigningKeyMatchesActiveConfiguration() {
                                try await performPendingLinkedDeviceRepair(session: session)
                            } else {
                                await session.setPendingLinkedDeviceRepair(true)
                                logger.log(level: .info, message: "Linked-device repair requested; waiting for reprovisioning bundle before rotating")
                            }
                        case .compromiseObserved:
                            logger.log(
                                level: .error,
                                message: "Linked device reported possible compromise; notifying delegate (intent=\(envelope.intentId?.uuidString ?? "nil") epoch=\(envelope.epoch))")

                            await session.sessionDelegate?.linkedDeviceReportedPotentialCompromise(
                                deviceId: inboundTask.senderDeviceId,
                                intentId: envelope.intentId)
                        }

                        // Throttled refresh after the disposition. Without this, a 30-message
                        // backlog from the same sender would each force-refresh identities.
                        if await session.shouldForceIdentityRefresh(secretName: inboundTask.senderSecretName) {
                            _ = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
                            logger.log(level: .info, message: "Received Session Reestablishment, refreshed session identities")
                        } else {
                            logger.log(level: .debug, message: "[control-event] coalesced redundant identity refresh for sender=\(inboundTask.senderSecretName)")
                        }

                        if kind == .peerRefresh {
                            if envelope.isResponse {
                                guard await session.isExpectedPeerRefreshResponse(
                                    sender: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId,
                                    intentId: envelope.intentId)
                                else {
                                    logger.log(
                                        level: .info,
                                        message: "Ignoring unmatched peerRefresh response sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) intent=\(envelope.intentId?.uuidString ?? "nil")")
                                    decryptionSessionIdentity = try await finalizeAcceptedInbound(
                                        decryptionSessionIdentity,
                                        inboundTask: inboundTask,
                                        session: session)
                                    return
                                }
                                // Keep the proven lane after a correlated peerRefresh
                                // response. Resetting again would immediately diverge.
                                await session.markReconciliationAttempt(
                                    sender: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId,
                                    flow: .inbound)
                                let pending = await session.takePendingResendsAfterReestablishment(
                                    sender: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId)
                                await session.endReestablishmentEpisode(
                                    sender: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId)
                                await sendDeferredResendRequests(
                                    pending,
                                    session: session,
                                    reason: "peerRefresh response")
                            } else if shouldSendRefreshResponse {
                                // The peer explicitly cannot decrypt our frames. If our
                                // outbound lane toward that device is initialized but
                                // unanswered, its pinned one-time prekey is dead and
                                // every send re-references it — reset before responding
                                // so the resends the peer drains after our response ride
                                // a lane it can actually decrypt.
                                await resetUnansweredInitiatingLane(
                                    peerSecretName: inboundTask.senderSecretName,
                                    peerDeviceId: inboundTask.senderDeviceId,
                                    trigger: "peerRefreshRequest",
                                    session: session)
                                let isSelf = inboundTask.senderSecretName == context.sessionUser.secretName
                                let recipient: MessageRecipient = isSelf ? .personalMessage : .nickname(inboundTask.senderSecretName)
                                do {
                                    _ = try await session.emitSessionReestablishmentResponse(
                                        kind: .peerRefresh,
                                        recipient: recipient,
                                        respondingTo: envelope,
                                        targetDeviceId: inboundTask.senderDeviceId)
                                } catch {
                                    await session.forgetReceivedSessionReestablishment(
                                        envelope: envelope,
                                        senderDeviceId: inboundTask.senderDeviceId)
                                    logger.log(level: .warning, message: "Failed to emit peerRefresh response: \(error)")
                                }
                            }
                        }
                    case .linkedDeviceReprovisioning(let bundle):
                        canSaveMessage = false
                        guard let context = await session.sessionContext else {
                            throw PQSSession.SessionErrors.sessionNotInitialized
                        }
                        guard try shouldAcceptLinkedDeviceReprovisioning(
                            bundle: bundle,
                            inboundTask: inboundTask,
                            decodedMessage: decodedMessage,
                            context: context
                        ) else {
                            logger.log(level: .warning, message: "Ignoring unauthorized linked-device reprovisioning bundle")
                            decryptionSessionIdentity = try await finalizeAcceptedInbound(
                                decryptionSessionIdentity,
                                inboundTask: inboundTask,
                                session: session)
                            return
                        }
                        try await session.installLinkedDeviceReprovisioningBundle(bundle)
                        _ = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
                        if await session.hasPendingLinkedDeviceRepair() {
                            try await performPendingLinkedDeviceRepair(session: session)
                        } else {
                            logger.log(level: .info, message: "Installed linked-device reprovisioning bundle; awaiting repair signal")
                        }
                        
                    case .synchronizeOneTimeKeys(let info):
                        try await removeKeys(
                            session: session,
                            curveId: info.recipientCurveId,
                            mlKEMId: info.recipientMLKEMId)
                        canSaveMessage = false
                    case .refreshOneTimeKeys:
                        canSaveMessage = false
                        logger.log(
                            level: .info,
                            message: "Received refreshOneTimeKeys from \(inboundTask.senderSecretName); replenishing local published OTK batch")
                        async let curveRefresh = session.refreshOneTimeKeysTask(policy: .replenishBatch)
                        async let mlKEMRefresh = session.refreshMLKEMOneTimeKeysTask(policy: .replenishBatch)
                        let (curveReplaced, mlKEMReplaced) = await (curveRefresh, mlKEMRefresh)
                        if !curveReplaced || !mlKEMReplaced {
                            logger.log(
                                level: .warning,
                                message: "refreshOneTimeKeys inbound replenish incomplete for \(inboundTask.senderSecretName) curve=\(curveReplaced) mlkem=\(mlKEMReplaced)")
                        } else {
                            try await session.ackPublishedOneTimeKeysReplenished(to: inboundTask.senderSecretName)
                        }
                    case .publishedOneTimeKeysReplenished:
                        canSaveMessage = false
                        logger.log(
                            level: .info,
                            message: "Received publishedOneTimeKeysReplenished from \(inboundTask.senderSecretName)")
                        await session.completePeerPublishedOneTimeKeysReplenishmentWait(
                            secretName: inboundTask.senderSecretName)
                    case .requestMessageResend, .messageResendUnavailable:
                        // DEAD LEGACY (strict §4.1): encrypted retry controls are not
                        // serviced. Confirm unused in dogfood, then delete these cases /
                        // TransportEvent variants.
                        canSaveMessage = false
                    }
                } catch {
                    if let processedReestablishment {
                        await session.forgetReceivedSessionReestablishment(
                            envelope: processedReestablishment,
                            senderDeviceId: inboundTask.senderDeviceId)
                    }
                    logger.log(level: .error, message: "Error handling transport event from \(inboundTask.senderSecretName): \(error)")
                    throw error
                }
            }

            var didAcceptInbound = false
            if canSaveMessage {
                /// Now we can handle the message
                try await handleDecodedMessage(
                    decodedMessage,
                    inboundTask: inboundTask,
                    session: session,
                    sessionIdentity: decryptionSessionIdentity)
                decryptionSessionIdentity = try await finalizeAcceptedInbound(
                    decryptionSessionIdentity,
                    inboundTask: inboundTask,
                    session: session,
                    acknowledgeTransport: false)
                didAcceptInbound = true
            } else if await shouldAcceptWithoutChatRow(decodedMessage, session: session) {
                // Intentional non-persist (TransportEvent controls / nudgeLocal):
                // still ledger-accept so spool can ACK. Persistable host declines
                // must not accept — redelivery needs another chance at UI persist.
                decryptionSessionIdentity = try await finalizeAcceptedInbound(
                    decryptionSessionIdentity,
                    inboundTask: inboundTask,
                    session: session,
                    acknowledgeTransport: false)
                didAcceptInbound = true
            }

            if canSaveMessage {
                // Recovery bookkeeping is committed only after the accepted
                // envelope is durable and the winning lane is active.
                let recoveredFailureClasses = await session.takeInboundFailureClasses(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    messageId: inboundTask.sharedMessageId)
                if !recoveredFailureClasses.isEmpty {
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.messageDecrypted sharedId=\(inboundTask.sharedMessageId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) priorFailureClasses=\(recoveredFailureClasses.joined(separator: ","))")
                    // Heal event in the same audit file as the failures: bounded to
                    // messages that previously failed, so the audit shows fail-then-heal
                    // per sharedId instead of requiring success to be inferred from quiet.
                    PQSAuditLog.log(.recovery, "pqs.recovery.recovered sharedId=\(inboundTask.sharedMessageId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) priorFailureClasses=\(recoveredFailureClasses.joined(separator: ","))")
                }
                // A late orphan replay can land after the tuple was written off as
                // unrecoverable; the content is back, so lift the terminal mark.
                await session.clearInboundTerminalOutcome(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    sharedId: inboundTask.sharedMessageId)
                // Proven decrypt heals the lane: clear distinct-failure escalate bookkeeping
                // and re-arm archive fallback for this peer-device.
                await session.clearUndecryptableLaneFailures(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)

                let pending = await session.takePendingResendsAfterReestablishment(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    satisfiedSharedMessageId: inboundTask.sharedMessageId)
                // Still waiting for our own peerRefresh response: an ordinary inbound
                // decrypt (e.g. media the peer encrypted after their reset) does not
                // complete the coordinated exchange. Closing here drained resends onto
                // a lane the peer never accepted — Echo transported requests that Nudge
                // never received.
                //
                // Still waiting for our own peerRefresh response: ordinary inbound
                // decrypt (including activate-on-decrypt of an older session) does not
                // complete the coordinated exchange.
                let awaitingPeerRefreshResponse = await session.hasActiveLocalPeerRefreshRequest(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)
                if awaitingPeerRefreshResponse {
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendDrainDeferred reason=awaitingPeerRefreshResponse sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) pendingCount=\(pending.count) sharedId=\(inboundTask.sharedMessageId)")
                    PQSAuditLog.log(.recovery, "pqs.recovery.resendDrainDeferred reason=awaitingPeerRefreshResponse sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString) pendingCount=\(pending.count) sharedId=\(inboundTask.sharedMessageId)")
                    for pendingRequest in pending {
                        await session.deferPeerResendUntilReestablished(
                            sender: pendingRequest.senderName,
                            deviceId: pendingRequest.senderDeviceId,
                            failedMessageId: pendingRequest.failedSharedMessageId,
                            failureClass: pendingRequest.failureClass)
                    }
                } else {
                    // Proven decrypt with no outstanding local peerRefresh request:
                    // close the episode and drain deferred resends.
                    await session.endReestablishmentEpisode(
                        sender: inboundTask.senderSecretName,
                        deviceId: inboundTask.senderDeviceId)
                    await sendDeferredResendRequests(
                        pending,
                        session: session,
                        reason: "successful inbound message")
                }
            }

            if didAcceptInbound {
                await acknowledgeAcceptedInbound(inboundTask, session: session)
            }
            
        } catch {
            if let cache = await session.cache {
                let currentIdentities =
                    (try? await cache.fetchSessionIdentities()) ?? []
                for (identityId, originalData) in rollbackIdentityData {
                    if let identity = currentIdentities.first(where: { $0.id == identityId }) {
                        try? await restoreSessionIdentityData(
                            identity,
                            data: originalData,
                            session: session,
                            reason: "post-decrypt processing failed")
                    } else if let deletedOriginal = rollbackPeerIdentities.first(
                        where: { $0.id == identityId })
                    {
                        deletedOriginal.data = originalData
                        try? await cache.createSessionIdentity(deletedOriginal)
                        await ratchetManager.evictSessionConfiguration(identityId)
                    }
                }
                for identity in currentIdentities
                    where rollbackIdentityData[identity.id] == nil
                {
                    if let props = await identity.props(symmetricKey: rollbackSymmetricKey),
                       props.secretName == inboundTask.senderSecretName,
                       props.deviceId == inboundTask.senderDeviceId
                    {
                        try? await cache.deleteSessionIdentity(identity.id)
                        await ratchetManager.evictSessionConfiguration(identity.id)
                    }
                }
                await session.invalidateSessionIdentityCache(
                    secretName: inboundTask.senderSecretName)
            }
#if DEBUG
            logger.log(
                level: .debug,
                message: "pqs.recovery.decryptAttemptFailed sharedId=\(inboundTask.sharedMessageId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) action=handOffToRecoveryPolicy error=\(error)")
#endif
            throw error
        }
    }

    /// True when decrypt succeeded but no chat row is expected — TransportEvent
    /// controls or host `shouldPersist == false` (nudgeLocal). Persistable host
    /// declines (`processMessage == false` with persistable transport) must return
    /// false so the envelope stays retryable.
    private func shouldAcceptWithoutChatRow(
        _ message: CryptoMessage,
        session: PQSSession
    ) async -> Bool {
        guard let transportInfo = message.transportInfo, !transportInfo.isEmpty else {
            return false
        }
        if (try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo)) != nil {
            return true
        }
        return await session.sessionDelegate?.shouldPersist(transportInfo: transportInfo) == false
    }

    /// Commits the winning receive lane only after decrypt, decode, and all host
    /// handling have completed. Durable accepted-ledger write precedes spool ACK.
    private func finalizeAcceptedInbound(
        _ decryptionSessionIdentity: SessionIdentity,
        inboundTask: InboundTaskMessage,
        session: PQSSession,
        acknowledgeTransport: Bool = true
    ) async throws -> SessionIdentity {
        let activated = try await session.activateSessionIdentityAfterInboundDecrypt(
            decryptionSessionIdentity)
        // Do not publish preference / clear recovery state until the durable
        // accepted ledger write succeeds. The outer catch restores identity
        // inventory if persistence fails.
        try await session.markEnvelopeAccepted(
            senderSecretName: inboundTask.senderSecretName,
            senderDeviceId: inboundTask.senderDeviceId,
            envelopeMessageId: inboundTask.sharedMessageId,
            logicalSharedId: inboundTask.resolvedLogicalSharedId)
        preferredSessionIdentityIdByPeerDevice[
            peerDeviceIdentityPreferenceKey(
                secretName: inboundTask.senderSecretName,
                deviceId: inboundTask.senderDeviceId)
        ] = activated.id
        clearSurgicalControlEpisode(
            secretName: inboundTask.senderSecretName,
            deviceId: inboundTask.senderDeviceId)
        if acknowledgeTransport {
            await acknowledgeAcceptedInbound(inboundTask, session: session)
        }
        logger.log(
            level: .info,
            message: "pqs.recovery.laneSelectedAfterInboundDecrypt sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) sessionId=\(activated.id)")
        return activated
    }

    private func acknowledgeAcceptedInbound(
        _ inboundTask: InboundTaskMessage,
        session: PQSSession
    ) async {
        let acceptedSharedId = inboundTask.sharedMessageId
        let acceptedDelegate = await session.sessionDelegate
        await session.scheduleTransportProtocolWork {
            await acceptedDelegate?.inboundCiphertextAccepted(sharedMessageId: acceptedSharedId)
        }
    }

    /// Enqueues a `.background` re-process of `inboundTask` that includes archived
    /// SessionIdentity rows. Pass ownership is tokenized by
    /// `(sender, device, envelope, fingerprint)` so a fresh orphan fingerprint
    /// cannot consume an older archive-only pass (T17).
    private func deferArchivedInboundFallback(
        inboundTask: InboundTaskMessage,
        session: PQSSession
    ) async {
        let sharedId = inboundTask.sharedMessageId
        let currentFingerprint = PQSSession.nackFrameFingerprint(for: inboundTask)
        let token = ArchivedInboundFallbackToken(
            senderSecretName: inboundTask.senderSecretName,
            senderDeviceId: inboundTask.senderDeviceId,
            envelopeMessageId: sharedId,
            fingerprint: currentFingerprint)
        guard InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
            token: token,
            exhausted: archivedInboundFallbackExhausted,
            pendingPass: archivedInboundFallbackPasses
        ) else {
            return
        }
        guard archivedInboundFallbackPasses.insert(token.storageKey).inserted else {
            return
        }
        PQSAuditLog.log(.recovery, "pqs.recovery.deferArchivedInboundFallback sharedId=\(sharedId) token=\(token.storageKey.prefix(64)) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
        do {
            try await feedTask(
                EncryptableTask(
                    task: .streamMessage(inboundTask),
                    priority: .background),
                session: session)
        } catch {
            archivedInboundFallbackPasses.remove(token.storageKey)
            logger.log(
                level: .warning,
                message: "pqs.recovery.deferArchivedInboundFallbackFailed sharedId=\(sharedId) error=\(error)")
        }
    }

    private func markArchivedInboundFallbackExhausted(
        sharedId: String,
        sender: String,
        deviceId: UUID,
        fingerprint: Data
    ) {
        let token = ArchivedInboundFallbackToken(
            senderSecretName: sender,
            senderDeviceId: deviceId,
            envelopeMessageId: sharedId,
            fingerprint: fingerprint)
        archivedInboundFallbackExhausted = InboundRecoveryStormPolicy.exhaustedAfterArchivePassCompleted(
            current: archivedInboundFallbackExhausted,
            token: token)
        archivedInboundFallbackExhaustedPeerKey[token.storageKey] = token.peerKey
        archivedInboundFallbackPasses.remove(token.storageKey)
    }

    func clearArchivedInboundFallbackExhausted(sender: String, deviceId: UUID) {
        let peerKey = "\(sender)|\(deviceId.uuidString)"
        let keys = archivedInboundFallbackExhaustedPeerKey
            .compactMap { $0.value == peerKey ? $0.key : nil }
        for key in keys {
            archivedInboundFallbackExhausted.remove(key)
            archivedInboundFallbackExhaustedPeerKey.removeValue(forKey: key)
        }
    }

    private func restoreSessionIdentityData(
        _ identity: SessionIdentity,
        data: Data,
        session: PQSSession,
        reason: String
    ) async throws {
        identity.data = data
        // The ratchet manager persists working mutations during an attempt, so its
        // in-memory configuration now diverges from the restored row. Evict it so the
        // next attempt rebuilds from the committed row (blank rows re-run the PQXDH
        // bootstrap from the incoming header instead of reusing poisoned state).
        await ratchetManager.evictSessionConfiguration(identity.id)
        guard let cache = await session.cache else { return }

        do {
            try await cache.updateSessionIdentity(identity)
        } catch SessionCache.CacheErrors.sessionIdentityNotFound {
            logger.log(
                level: .info,
                message: "Skipped restoring SessionIdentity after \(reason); identity no longer exists in cache")
        }
    }

    private func pendingOutboundTransport(
        sharedId: String,
        now: Date = Date()
    ) -> PendingOutboundTransport? {
        cleanupPendingOutboundTransport(now: now)
        return pendingOutboundTransportBySharedId[sharedId]
    }

    private func logRecoveryTransportSendSuccess(_ event: TransportEvent?, sharedId: String) {
        guard let event else { return }

        switch event {
        case .sessionReestablishment(let envelope):
            logger.log(
                level: .info,
                message: "pqs.recovery.reestablishmentSent sharedId=\(sharedId) kind=\(envelope.kind.rawValue) response=\(envelope.isResponse) epoch=\(envelope.epoch) intent=\(envelope.intentId?.uuidString ?? "nil")")
        case .requestMessageResend:
            // DEAD LEGACY: encrypted resend-request send log; OOB path uses distinct audits.
            break
        case .linkedDeviceReprovisioning(let bundle):
            logger.log(
                level: .info,
                message: "pqs.recovery.linkedDeviceReprovisioningSent sharedId=\(sharedId) targetDeviceId=\(bundle.targetDeviceId)")
        case .messageResendUnavailable:
            // DEAD LEGACY: encrypted unavailable send log; OOB path uses distinct audits.
            break
        case .synchronizeOneTimeKeys, .refreshOneTimeKeys, .publishedOneTimeKeysReplenished:
            break
        }
    }

    private func shouldRememberPendingOutboundTransport(_ message: CryptoMessage) -> Bool {
        guard let transportInfo = message.transportInfo,
              let event = try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo)
        else {
            return true
        }

        switch event {
        case .sessionReestablishment,
             .linkedDeviceReprovisioning,
             .synchronizeOneTimeKeys,
             .refreshOneTimeKeys,
             .publishedOneTimeKeysReplenished,
             .requestMessageResend,
             .messageResendUnavailable:
            // DEAD LEGACY arms (.requestMessageResend / .messageResendUnavailable) retained
            // only so pending encrypted frames still flush if already queued.
            return true
        }
    }

    private func rememberPendingOutboundTransport(
        sharedId: String,
        message: SignedRatchetMessage,
        metadata: SignedRatchetMessageMetadata,
        sessionIdentityId: UUID,
        needsRemoteDeletion: Bool,
        curveOneTimeKeyId: String?,
        mlKEMOneTimeKeyId: String,
        now: Date = Date()
    ) {
        cleanupPendingOutboundTransport(now: now)
        pendingOutboundTransportBySharedId[sharedId] = PendingOutboundTransport(
            message: message,
            metadata: metadata,
            sessionIdentityId: sessionIdentityId,
            needsRemoteDeletion: needsRemoteDeletion,
            curveOneTimeKeyId: curveOneTimeKeyId,
            mlKEMOneTimeKeyId: mlKEMOneTimeKeyId,
            createdAt: now)

        guard pendingOutboundTransportBySharedId.count > pendingOutboundTransportLimit else { return }
        let overflow = pendingOutboundTransportBySharedId.count - pendingOutboundTransportLimit
        let oldestKeys = pendingOutboundTransportBySharedId
            .sorted { $0.value.createdAt < $1.value.createdAt }
            .prefix(overflow)
            .map(\.key)
        for key in oldestKeys {
            pendingOutboundTransportBySharedId.removeValue(forKey: key)
        }
    }

    private func orphanResendServiceKey(requestingDeviceId: UUID, sharedId: String) -> String {
        "\(requestingDeviceId.uuidString)|\(sharedId)"
    }

    private func cleanupOrphanResendTransport(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-orphanResendTransportTTL)
        orphanResendTransportByServiceKey = orphanResendTransportByServiceKey.filter { _, pending in
            pending.createdAt > cutoff
        }
    }

    private func orphanResendTransport(forServiceKey serviceKey: String, now: Date = Date()) -> PendingOutboundTransport? {
        cleanupOrphanResendTransport(now: now)
        return orphanResendTransportByServiceKey[serviceKey]
    }

    private func rememberOrphanResendTransport(
        requestingDeviceId: UUID,
        sharedId: String,
        message: SignedRatchetMessage,
        metadata: SignedRatchetMessageMetadata,
        sessionIdentityId: UUID,
        needsRemoteDeletion: Bool,
        curveOneTimeKeyId: String?,
        mlKEMOneTimeKeyId: String,
        now: Date = Date()
    ) {
        cleanupOrphanResendTransport(now: now)
        let key = orphanResendServiceKey(requestingDeviceId: requestingDeviceId, sharedId: sharedId)
        orphanResendTransportByServiceKey[key] = PendingOutboundTransport(
            message: message,
            metadata: metadata,
            sessionIdentityId: sessionIdentityId,
            needsRemoteDeletion: needsRemoteDeletion,
            curveOneTimeKeyId: curveOneTimeKeyId,
            mlKEMOneTimeKeyId: mlKEMOneTimeKeyId,
            createdAt: now)
        guard orphanResendTransportByServiceKey.count > orphanResendTransportLimit else { return }
        let overflow = orphanResendTransportByServiceKey.count - orphanResendTransportLimit
        let oldestKeys = orphanResendTransportByServiceKey
            .sorted { $0.value.createdAt < $1.value.createdAt }
            .prefix(overflow)
            .map(\.key)
        for oldKey in oldestKeys {
            orphanResendTransportByServiceKey.removeValue(forKey: oldKey)
        }
    }

    func sendPreparedOutbound(
        _ prepared: JobModel.PreparedOutbound,
        outboundTask: OutboundTaskMessage,
        session: PQSSession
    ) async throws {
        let metadata = SignedRatchetMessageMetadata(
            secretName: prepared.secretName,
            deviceId: prepared.deviceId,
            recipient: prepared.recipient,
            transportMetadata: prepared.transportMetadata,
            sharedMessageId: prepared.sharedMessageId,
            envelopeMessageId: prepared.envelopeMessageId,
            transportEvent: prepared.transportEvent,
            requiresServerAck: prepared.requiresServerAck)
        let pending = PendingOutboundTransport(
            message: prepared.signedMessage,
            metadata: metadata,
            sessionIdentityId: prepared.sessionIdentityId,
            needsRemoteDeletion: prepared.needsRemoteDeletion,
            curveOneTimeKeyId: prepared.curveOneTimeKeyId,
            mlKEMOneTimeKeyId: prepared.mlKEMOneTimeKeyId,
            createdAt: prepared.createdAt)
        try await sendPendingOutboundTransport(
            pending,
            outboundTask: outboundTask,
            session: session)
    }

    private func sendPendingOutboundTransport(
        _ pendingTransport: PendingOutboundTransport,
        outboundTask: OutboundTaskMessage,
        session: PQSSession
    ) async throws {
        try await session.transportDelegate?.sendMessage(
            pendingTransport.message,
            metadata: pendingTransport.metadata)
        logRecoveryTransportSendSuccess(
            pendingTransport.metadata.transportEvent,
            sharedId: outboundTask.sharedId)
        // DEAD LEGACY: encrypted TransportEvent.requestMessageResend transport bookkeeping.
        // if case .requestMessageResend(let request) = pendingTransport.metadata.transportEvent { ... }
        await noteResendReplayTransported(sharedId: outboundTask.sharedId)
        await session.recordOutboundDeviceSend(
            sharedId: outboundTask.sharedId,
            recipientSecretName: pendingTransport.metadata.secretName,
            recipientDeviceId: pendingTransport.metadata.deviceId,
            sessionIdentityId: pendingTransport.sessionIdentityId,
            envelopeMessageId: pendingTransport.metadata.envelopeMessageId)
        pendingOutboundTransportBySharedId.removeValue(forKey: outboundTask.sharedId)
        await completeResponderPeerRefreshIfNeeded(
            pendingTransport.metadata.transportEvent,
            peerSecretName: pendingTransport.metadata.secretName,
            peerDeviceId: pendingTransport.metadata.deviceId,
            session: session)

        await rememberRecentOutboundReplayIfNeeded(outboundTask, session: session)

        if outboundTask.isPersistedOutbound || pendingTransport.metadata.requiresServerAck {
            registerUnackedServerAccept(
                pending: pendingTransport,
                localId: outboundTask.localId,
                sharedId: outboundTask.sharedId,
                session: session)
        } else {
            await markPersistedOutboundPastSendingIfNeeded(session: session, localMessageId: outboundTask.localId)
        }

        if pendingTransport.needsRemoteDeletion {
            try await removeKeys(
                session: session,
                curveId: pendingTransport.curveOneTimeKeyId,
                mlKEMId: pendingTransport.mlKEMOneTimeKeyId)
        }
    }

    private func cleanupPendingOutboundTransport(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-pendingOutboundTransportTTL)
        pendingOutboundTransportBySharedId = pendingOutboundTransportBySharedId.filter { _, pendingTransport in
            pendingTransport.createdAt > cutoff
        }
    }

    private func rememberRecentOutboundReplayIfNeeded(
        _ outboundTask: OutboundTaskMessage,
        session: PQSSession,
        now: Date = Date()
    ) async {
        guard !outboundTask.isPersistedOutbound else { return }
        guard await isReplayableNonPersistentControl(outboundTask.message, session: session) else { return }
        recentOutboundReplayStore.remember(
            outboundTask.message,
            sharedId: outboundTask.sharedId,
            now: now)
    }

    private func hasRecentOutboundReplay(
        sharedId: String,
        now: Date = Date()
    ) -> Bool {
        recentOutboundReplayStore.contains(sharedId: sharedId, now: now)
    }

    private func recentOutboundReplayMessage(
        sharedId: String,
        now: Date = Date()
    ) -> (message: CryptoMessage, replayCount: Int)? {
        recentOutboundReplayStore.consume(sharedId: sharedId, now: now)
    }

    /// Friendship packets must never be replayed from the recovery ring; peers
    /// converge via fresh `friendshipStateRequest` or sibling `synchronizeContacts`.
    private func isFriendshipStateControlMessage(_ message: CryptoMessage) -> Bool {
        (try? BinaryDecoder().decode(FriendshipMetadata.self, from: message.metadata)) != nil
    }

    /// Records that a replay job for a peer's resend request was queued, so its
    /// terminal outcome (transported or dropped) is audited. Without this, a replay
    /// that dies before transport is invisible to both sides.
    /// `servicedFromPersistedStore` controls whether transport hand-off arms the
    /// responder servicing cooldown.
    func rememberResendReplayQueued(
        sharedId: String,
        requesterName: String,
        requesterDeviceId: UUID,
        servicedFromPersistedStore: Bool,
        now: Date = Date()
    ) {
        let cutoff = now.addingTimeInterval(-pendingResendReplayTTL)
        pendingResendReplayBySharedId = pendingResendReplayBySharedId.filter { _, replay in
            replay.queuedAt > cutoff
        }
        if pendingResendReplayBySharedId.count >= pendingResendReplayLimit {
            let overflowKeys = pendingResendReplayBySharedId
                .sorted { $0.value.queuedAt < $1.value.queuedAt }
                .prefix(pendingResendReplayBySharedId.count - pendingResendReplayLimit + 1)
                .map(\.key)
            for key in overflowKeys {
                pendingResendReplayBySharedId.removeValue(forKey: key)
            }
        }
        pendingResendReplayBySharedId[sharedId] = PendingResendReplay(
            requesterName: requesterName,
            requesterDeviceId: requesterDeviceId,
            servicedFromPersistedStore: servicedFromPersistedStore,
            queuedAt: now)
        PQSAuditLog.log(.recovery, "pqs.recovery.resendReplayQueued sharedId=\(sharedId) requester=\(requesterName) requesterDeviceId=\(requesterDeviceId.uuidString)")
    }

    /// Audits that a tracked resend replay actually reached the transport, and only
    /// then arms the persisted-store servicing cooldown. Arming at queue time let a
    /// replay that died before the wire coalesce the requester's next ask into
    /// silence — request loops with no reply and no audit trail.
    func noteResendReplayTransported(sharedId: String) async {
        guard let replay = pendingResendReplayBySharedId.removeValue(forKey: sharedId) else { return }
        PQSAuditLog.log(.recovery, "pqs.recovery.resendReplayTransported sharedId=\(sharedId) requester=\(replay.requesterName) requesterDeviceId=\(replay.requesterDeviceId.uuidString)")
        await clearOrphanResendWaveIfDrained(
            requesterName: replay.requesterName,
            requesterDeviceId: replay.requesterDeviceId)
        guard replay.servicedFromPersistedStore, let session else { return }
        await session.markPeerResendRequestServiced(
            requestingDeviceId: replay.requesterDeviceId,
            sharedId: sharedId)
    }

    /// Audits that a tracked resend replay job died before transport. The requester
    /// re-requests after its cooldown (bounded by the transported-attempt cap), so
    /// this is observability, not retry machinery. The servicing cooldown is
    /// intentionally not armed — a dropped replay must not silence the next ask.
    func noteResendReplayDropped(sharedId: String, reason: String) async {
        guard let replay = pendingResendReplayBySharedId.removeValue(forKey: sharedId) else { return }
        PQSAuditLog.log(.recovery, "pqs.recovery.resendReplayDropped sharedId=\(sharedId) requester=\(replay.requesterName) requesterDeviceId=\(replay.requesterDeviceId.uuidString) reason=\(reason)")
        await clearOrphanResendWaveIfDrained(
            requesterName: replay.requesterName,
            requesterDeviceId: replay.requesterDeviceId)
    }

    func hasPendingResendReplay(requesterName: String, requesterDeviceId: UUID) -> Bool {
        pendingResendReplayBySharedId.values.contains {
            $0.requesterName == requesterName && $0.requesterDeviceId == requesterDeviceId
        }
    }

    /// Serial recovery wave end audit: local replay jobs for this requester drained.
    /// Does **not** clear the orphan initiating mark — mark clears on wipe /
    /// non-orphan reset only, not queue emptiness or generic inbound activate.
    private func clearOrphanResendWaveIfDrained(
        requesterName: String,
        requesterDeviceId: UUID
    ) async {
        guard !hasPendingResendReplay(
            requesterName: requesterName,
            requesterDeviceId: requesterDeviceId
        ) else {
            return
        }
        PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendWaveDrained requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString)")
    }

    /// Tells the requesting device that these ids have no replay source anywhere so it
    /// stops re-requesting them. Delivered on the requester device's existing active
    /// lane — an unanswerable retry request must never reset session state. An
    /// initiating row is minted only when no active session exists for that device.
    /// Send failures are non-fatal: the requester-side attempt
    /// cap (`PQSSessionConstants.peerResendRequestMaxSubmissions`) still bounds the loop
    /// when the notice is lost.
    private func emitResendUnavailableNotice(
        to fallbackIdentity: SessionIdentity,
        requesterName: String,
        requesterDeviceId: UUID,
        unavailableIds: [String],
        session: PQSSession
    ) async {
        guard !unavailableIds.isEmpty else { return }
        guard let context = await session.sessionContext else { return }
        _ = fallbackIdentity

        // Strict §4.1: unavailable notices are out-of-band — no DR encrypt /
        // surgical lane selection (closes S7 for the response leg).
        do {
            try await session.transportDelegate?.sendOutOfBandResendUnavailable(
                unavailableEnvelopeMessageIds: unavailableIds,
                to: requesterName,
                deviceId: requesterDeviceId,
                respondingDeviceId: context.sessionUser.deviceId)
            logger.log(
                level: .info,
                message: "pqs.recovery.resendUnavailableSentOutOfBand requester=\(requesterName) unavailableCount=\(unavailableIds.count) ids=\(unavailableIds.joined(separator: ","))")
            PQSAuditLog.log(.recovery, "pqs.recovery.resendUnavailableSentOutOfBand requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) unavailableCount=\(unavailableIds.count) ids=\(unavailableIds.joined(separator: ","))")
            PQSAuditLog.log(.recovery, "pqs.recovery.resendUnavailableSameAccountNoRemint requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) sessionId=\(fallbackIdentity.id.uuidString) unavailableCount=\(unavailableIds.count)")
        } catch {
            logger.log(
                level: .warning,
                message: "pqs.recovery.resendUnavailableEmitFailed requester=\(requesterName) unavailableCount=\(unavailableIds.count) error=\(error)")
            PQSAuditLog.log(.recovery, "pqs.recovery.resendUnavailableEmitFailed requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) unavailableCount=\(unavailableIds.count) error=\(error)")
        }
    }

    /// Delivery identity for unavailable NACKs. A retry request we cannot service
    /// must never tear down session state (discard, don't reset): deliver the notice
    /// on the requester device's existing active lane. Mint an initiating row only
    /// when that peer device has no active session at all — with no actives the
    /// reset demotes nothing (`laneReset ... demotedActive=0`). Never stamp a
    /// preferred lane here; general outbound must not be captured by a NACK row.
    private func resolveResendUnavailableDeliveryIdentity(
        fallback: SessionIdentity,
        requesterName: String,
        requesterDeviceId: UUID,
        session: PQSSession
    ) async -> SessionIdentity {
        do {
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            let identities = try await session.cache?.fetchSessionIdentities() ?? []
            let preferredDevice = await currentDeviceConfiguration(
                secretName: requesterName,
                deviceId: requesterDeviceId,
                session: session)
            if let active = await outboundSessionIdentity(
                secretName: requesterName,
                deviceId: requesterDeviceId,
                in: identities,
                symmetricKey: symmetricKey,
                session: session,
                preferredDevice: preferredDevice
            ) {
                PQSAuditLog.log(.recovery, "pqs.recovery.resendUnavailableUsingActive requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) sessionId=\(active.id.uuidString)")
                return active
            }
            let identity = try await session.resetSessionIdentityForFreshSession(
                secretName: requesterName,
                deviceId: requesterDeviceId,
                sendOneTimeIdentities: false,
                reason: "resendUnavailable")
            PQSAuditLog.log(.recovery, "pqs.recovery.resendUnavailableInitiating requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) newSessionId=\(identity.id.uuidString)")
            return identity
        } catch {
            logger.log(
                level: .warning,
                message: "pqs.recovery.resendUnavailableInitiatingFailed requester=\(requesterName) deviceId=\(requesterDeviceId) error=\(error)")
            PQSAuditLog.log(.recovery, "pqs.recovery.resendUnavailableInitiatingFailed requester=\(requesterName) deviceId=\(requesterDeviceId.uuidString) error=\(error)")
            return fallback
        }
    }

    private func cleanupRecentUnavailableNotices(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-recentUnavailableNoticeTTL)
        recentUnavailableNoticeByRequesterDevice = recentUnavailableNoticeByRequesterDevice.filter {
            $0.value.createdAt > cutoff
        }
    }

    /// §4.1 sender-side servicing for authenticated OOB retry ingress.
    /// Owns MessageRecord lookup, orphan remint/retransport, and bounded
    /// unavailable notices.
    @discardableResult
    func serviceAuthenticatedResendRequest(
        requesterSecretName: String,
        requesterWireDeviceId: UUID,
        request: FailedMessageResendRequest,
        session: PQSSession
    ) async throws -> PQSSession.OutOfBandResendResult {
        let symmetricKey = try await session.getDatabaseSymmetricKey()
        var queuedIds: [String] = []
        let identities = try await session.cache?.fetchSessionIdentities() ?? []
        logger.log(
            level: .info,
            message: "pqs.recovery.resendRequestReceived sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) requestingDeviceId=\(request.requestingDeviceId) requestedCount=\(request.failedSharedMessageIds.count) ids=\(request.failedSharedMessageIds.joined(separator: ","))")
        // Production console logs filter info; the audit file must show
        // the request arrived so a silent servicing path is attributable.
        PQSAuditLog.log(.recovery, "pqs.recovery.resendRequestReceived requester=\(requesterSecretName) requestingDeviceId=\(request.requestingDeviceId.uuidString) ids=\(request.failedSharedMessageIds.joined(separator: ","))")
        let requestedDevice = await currentDeviceConfiguration(
            secretName: requesterSecretName,
            deviceId: request.requestingDeviceId,
            session: session)
        let senderDevice = await currentDeviceConfiguration(
            secretName: requesterSecretName,
            deviceId: requesterWireDeviceId,
            session: session)
        let requestedIdentity = await outboundSessionIdentity(
            secretName: requesterSecretName,
            deviceId: request.requestingDeviceId,
            in: identities,
            symmetricKey: symmetricKey,
            session: session,
            preferredDevice: requestedDevice
        )
        let senderIdentity = await outboundSessionIdentity(
            secretName: requesterSecretName,
            deviceId: requesterWireDeviceId,
            in: identities,
            symmetricKey: symmetricKey,
            session: session,
            preferredDevice: senderDevice
        )
        guard var identity = requestedIdentity ?? senderIdentity else {
            // No outbound lane to the requester yet: still resolve local
            // missing/unavailable without reminting or throwing.
            logger.log(
                level: .warning,
                message: "pqs.recovery.resendReplayFailed reason=missingIdentity sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) requestingDeviceId=\(request.requestingDeviceId) requestedCount=\(request.failedSharedMessageIds.count)")
            var permanentlyUnavailableIds: [String] = []
            let symmetricKeyForLookup = try? await session.getDatabaseSymmetricKey()
            for requestedEnvelopeMessageId in request.failedSharedMessageIds {
                let messageRecord = await session.outboundDeviceSendRecord(
                    envelopeMessageId: requestedEnvelopeMessageId)
                let logicalSharedId = messageRecord?.sharedId ?? requestedEnvelopeMessageId
                if await session.isKnownUnavailableResend(
                    requestingDeviceId: request.requestingDeviceId,
                    sharedId: requestedEnvelopeMessageId)
                {
                    permanentlyUnavailableIds.append(requestedEnvelopeMessageId)
                    continue
                }
                if recentOutboundReplayMessage(sharedId: logicalSharedId) != nil {
                    continue
                }
                let foundMessage: EncryptedMessage?
                do {
                    foundMessage = try await session.cache?.fetchMessageIfExists(
                        sharedId: logicalSharedId)
                } catch {
                    foundMessage = nil
                }
                var readable = false
                if let foundMessage, let symmetricKeyForLookup {
                    readable = await foundMessage.props(symmetricKey: symmetricKeyForLookup)?.message != nil
                }
                if !readable {
                    permanentlyUnavailableIds.append(requestedEnvelopeMessageId)
                    await session.markResendUnavailable(
                        requestingDeviceId: request.requestingDeviceId,
                        sharedId: requestedEnvelopeMessageId)
                }
            }
            return PQSSession.OutOfBandResendResult(
                queuedIds: [],
                permanentlyUnavailableIds: permanentlyUnavailableIds)
        }

        var replayQueuedCount = 0
        var replayMissingCount = 0
        var replayCoalescedCount = 0
        var unavailableIds: [String] = []
        var knownUnavailableCount = 0
        var missingByReason: [String: Int] = [:]
        var pendingOrphanEncrypts: [(
            sharedId: String,
            requestedEnvelopeMessageId: String,
            message: CryptoMessage,
            identity: SessionIdentity,
            retransportCached: Bool
        )] = []
        let localSecretName = await session.sessionContext?.sessionUser.secretName
        let isSameAccountRequester =
            localSecretName == requesterSecretName
        // Process escape-remint candidates first so a settled prove-fail
        // remints before sibling reuseRecoveryWave advances the old row.
        // Classify only — remint still happens in the per-id switch.
        var orderedFailedSharedMessageIds = request.failedSharedMessageIds
        if let recoveryForOrder = await session.orphanResendRecoverySessionId(
            secretName: requesterSecretName,
            deviceId: request.requestingDeviceId)
        {
            var escapeFirst: [String] = []
            var remainder: [String] = []
            for candidateId in request.failedSharedMessageIds {
                let candidateRecord = await session.outboundDeviceSendRecord(
                    envelopeMessageId: candidateId)
                let candidateLogicalId = candidateRecord?.sharedId ?? candidateId
                let candidateKey = orphanResendServiceKey(
                    requestingDeviceId: request.requestingDeviceId,
                    sharedId: candidateLogicalId)
                if OrphanResendRemintPolicy.needsEscapeRemintAfterRetransportProveFail(
                    messageRecordSessionId: candidateRecord?.sessionIdentityId,
                    recoverySessionId: recoveryForOrder,
                    priorRetransportCount:
                        orphanResendRetransportCountByServiceKey[candidateKey] ?? 0,
                    remintsAfterRetransportProveFail:
                        orphanResendRemintsAfterProveFailByServiceKey[candidateKey] ?? 0)
                {
                    escapeFirst.append(candidateId)
                } else {
                    remainder.append(candidateId)
                }
            }
            orderedFailedSharedMessageIds = escapeFirst + remainder
        }
        for failedEnvelopeMessageId in orderedFailedSharedMessageIds {
            // Strict §4.1 retry requests identify the failed encrypted
            // envelope. Resolve its MessageRecord before looking up plaintext,
            // whose durable content key remains the logical shared id.
            let requestedMessageRecord = await session.outboundDeviceSendRecord(
                envelopeMessageId: failedEnvelopeMessageId)
            let failedSharedMessageId =
                requestedMessageRecord?.sharedId ?? failedEnvelopeMessageId
            // A previous lookup already proved this id unreplayable; skip the
            // DB pass and just re-notify the requester below.
            if await session.isKnownUnavailableResend(
                requestingDeviceId: request.requestingDeviceId,
                sharedId: failedEnvelopeMessageId
            ) {
                unavailableIds.append(failedEnvelopeMessageId)
                knownUnavailableCount += 1
                continue
            }

            let cryptoMessage: CryptoMessage
            // Recent non-persistent recovery controls are intentionally replayable
            // multiple times while a peer repairs; they are already bounded by
            // `recentOutboundReplayMaxReplays`, so they bypass the servicing cooldown.
            var servicedFromPersistedStore = false
            let hasRecentReplay =
                hasRecentOutboundReplay(sharedId: failedSharedMessageId)
            if let replay = recentOutboundReplayMessage(sharedId: failedSharedMessageId) {
                cryptoMessage = replay.message
                logger.log(
                    level: .info,
                    message: "pqs.recovery.resendReplayUsingRecentControl sharedId=\(failedSharedMessageId) replayCount=\(replay.replayCount)")
            } else {
                let hasMessageRecord = requestedMessageRecord != nil
                // Persisted-message replays are otherwise unbounded: a peer stuck in a
                // decrypt-failure loop could force us to re-ratchet and re-consume OTKs
                // for the same message on every request. Coalesce repeats per requester.
                guard await session.canServicePeerResendRequest(
                    requestingDeviceId: request.requestingDeviceId,
                    sharedId: failedEnvelopeMessageId)
                else {
                    replayCoalescedCount += 1
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendReplayCoalesced reason=servicingCooldown sharedId=\(failedSharedMessageId) requestingDeviceId=\(request.requestingDeviceId)")
                    continue
                }

                let foundMessage: EncryptedMessage?
                do {
                    foundMessage = try await session.cache?.fetchMessageIfExists(sharedId: failedSharedMessageId)
                } catch {
                    replayMissingCount += 1
                    unavailableIds.append(failedEnvelopeMessageId)
                    missingByReason["messageLookupFailed", default: 0] += 1
                    await session.markResendUnavailable(
                        requestingDeviceId: request.requestingDeviceId,
                        sharedId: failedEnvelopeMessageId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendReplaySkipped reason=messageLookupFailed sharedId=\(failedSharedMessageId) error=\(error)")
                    continue
                }
                let ownership = OrphanResendOwnershipPolicy.decision(
                    isSameAccount: isSameAccountRequester,
                    hasRecentOutboundReplay: hasRecentReplay,
                    hasLocalMessage: foundMessage != nil,
                    hasOutboundDeviceSendRecord: hasMessageRecord)
                if ownership == .deferNotContentOwner {
                    PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendDeferredNotContentOwner sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString)")
                    continue
                }
                guard let foundMessage else {
                    // MessageRecord owner without plaintext: consult remint
                    // counters (cross- or same-account). Dogfood: gating on
                    // isSameAccount skipped escape remint → missingLocalMessage.
                    if hasMessageRecord {
                        let serviceKey = orphanResendServiceKey(
                            requestingDeviceId: request.requestingDeviceId,
                            sharedId: failedSharedMessageId)
                        let messageRecord = await session.outboundDeviceSendRecord(
                            envelopeMessageId: failedEnvelopeMessageId)
                        let recoverySessionId = await session.orphanResendRecoverySessionId(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId)
                        let priorRetransportCount =
                            orphanResendRetransportCountByServiceKey[serviceKey] ?? 0
                        let remintsAfterProveFail =
                            orphanResendRemintsAfterProveFailByServiceKey[serviceKey] ?? 0
                        let ownerDecision = OrphanResendRemintPolicy.decision(
                            messageRecordSessionId: messageRecord?.sessionIdentityId,
                            recoverySessionId: recoverySessionId,
                            initiatingMarkSessionId: nil,
                            markIsStateLess: false,
                            priorRetransportCount: priorRetransportCount,
                            remintsAfterRetransportProveFail: remintsAfterProveFail)
                        if ownerDecision == .retransportAlreadyServiced,
                           orphanResendTransport(forServiceKey: serviceKey) != nil,
                           let recoverySessionId,
                           let recovered = ((try? await session.cache?.fetchSessionIdentities())
                            ?? identities).first(where: { $0.id == recoverySessionId })
                        {
                            orphanResendRetransportCountByServiceKey[serviceKey] =
                                priorRetransportCount + 1
                            rememberResendReplayQueued(
                                sharedId: failedSharedMessageId,
                                requesterName: requesterSecretName,
                                requesterDeviceId: request.requestingDeviceId,
                                servicedFromPersistedStore: false)
                            pendingOrphanEncrypts.append((
                                sharedId: failedSharedMessageId,
                                requestedEnvelopeMessageId: failedEnvelopeMessageId,
                                message: CryptoMessage(
                                    text: "",
                                    metadata: .init(),
                                    recipient: .personalMessage,
                                    sentDate: Date(),
                                    destructionTime: nil),
                                identity: recovered,
                                retransportCached: true
                            ))
                            PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendRetransport sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) sessionId=\(recoverySessionId.uuidString)")
                            continue
                        }
                        if ownerDecision == .mintFreshAfterRetransportProveFailed {
                            // Remint lane for later siblings; this id stays
                            // unavailable without plaintext to re-encrypt.
                            do {
                                identity = try await performOrphanEscapeRemint(
                                    serviceKey: serviceKey,
                                    remintsAfterProveFail: remintsAfterProveFail,
                                    priorRecordSessionId: messageRecord?.sessionIdentityId,
                                    secretName: requesterSecretName,
                                    deviceId: request.requestingDeviceId,
                                    sharedId: failedSharedMessageId,
                                    session: session)
                            } catch {
                                logger.log(
                                    level: .warning,
                                    message: "pqs.recovery.orphanResendFailed sharedId=\(failedSharedMessageId) error=\(error)")
                            }
                        } else if ownerDecision == .exhaustedUnrecoverable {
                            PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendHealExhausted sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString)")
                            replayMissingCount += 1
                            unavailableIds.append(failedEnvelopeMessageId)
                            missingByReason["healExhausted", default: 0] += 1
                            await session.markResendUnavailable(
                                requestingDeviceId: request.requestingDeviceId,
                                sharedId: failedEnvelopeMessageId)
                            continue
                        }
                        PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendOwnerMissingPlaintext sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString)")
                        replayMissingCount += 1
                        unavailableIds.append(failedEnvelopeMessageId)
                        missingByReason["ownerMissingPlaintext", default: 0] += 1
                        await session.markResendUnavailable(
                            requestingDeviceId: request.requestingDeviceId,
                            sharedId: failedEnvelopeMessageId)
                        continue
                    }
                    replayMissingCount += 1
                    unavailableIds.append(failedEnvelopeMessageId)
                    missingByReason["missingLocalMessage", default: 0] += 1
                    await session.markResendUnavailable(
                        requestingDeviceId: request.requestingDeviceId,
                        sharedId: failedEnvelopeMessageId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendReplaySkipped reason=missingLocalMessage sharedId=\(failedSharedMessageId)")
                    continue
                }

                guard let fetchedCryptoMessage = await foundMessage.props(symmetricKey: symmetricKey)?.message else {
                    replayMissingCount += 1
                    unavailableIds.append(failedEnvelopeMessageId)
                    missingByReason["unreadableLocalMessage", default: 0] += 1
                    await session.markResendUnavailable(
                        requestingDeviceId: request.requestingDeviceId,
                        sharedId: failedEnvelopeMessageId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendReplaySkipped reason=unreadableLocalMessage sharedId=\(failedSharedMessageId)")
                    continue
                }
                cryptoMessage = fetchedCryptoMessage
                servicedFromPersistedStore = true
            }

            // Orphan-resend: first mint for a sharedId must be initiating
            // (msg0). After MessageRecord names the recovery SessionID,
            // rearmNack retransports that ciphertext — do not remint
            // (dogfood C3 / 2FA48892 triple newSessionId thrash).
            var replayIdentity = identity
            var retransportCached = false
            let messageRecord = await session.outboundDeviceSendRecord(
                envelopeMessageId: failedEnvelopeMessageId)
            let recoverySessionId = await session.orphanResendRecoverySessionId(
                secretName: requesterSecretName,
                deviceId: request.requestingDeviceId)
            let protectedId = await session.orphanResendInitiatingSessionId(
                secretName: requesterSecretName,
                deviceId: request.requestingDeviceId)
            var markIsStateLess = false
            var protectedIdentity: SessionIdentity?
            if let protectedId {
                let latestIdentities =
                    (try? await session.cache?.fetchSessionIdentities()) ?? identities
                if let protected = latestIdentities.first(where: { $0.id == protectedId }),
                   let protectedProps = await protected.props(symmetricKey: symmetricKey),
                   protectedProps.secretName == requesterSecretName,
                   protectedProps.deviceId == request.requestingDeviceId,
                   !protectedProps.deviceName.hasPrefix(
                    PQSSessionConstants.inactiveSessionDeviceNamePrefix)
                {
                    markIsStateLess = protectedProps.state == nil
                    if markIsStateLess {
                        protectedIdentity = protected
                    }
                }
            }

            let serviceKeyForPolicy = orphanResendServiceKey(
                requestingDeviceId: request.requestingDeviceId,
                sharedId: failedSharedMessageId)
            let priorRetransportCount =
                orphanResendRetransportCountByServiceKey[serviceKeyForPolicy] ?? 0
            let remintsAfterProveFail =
                orphanResendRemintsAfterProveFailByServiceKey[serviceKeyForPolicy] ?? 0
            var recoverySessionIsLiveActive = false
            var recoveryLiveIdentity: SessionIdentity?
            if let recoverySessionId {
                let latestIdentities =
                    (try? await session.cache?.fetchSessionIdentities()) ?? identities
                if let recovered = latestIdentities.first(where: { $0.id == recoverySessionId }),
                   let recoveredProps = await recovered.props(symmetricKey: symmetricKey),
                   recoveredProps.secretName == requesterSecretName,
                   recoveredProps.deviceId == request.requestingDeviceId,
                   !recoveredProps.deviceName.hasPrefix(
                    PQSSessionConstants.inactiveSessionDeviceNamePrefix)
                {
                    recoverySessionIsLiveActive = true
                    recoveryLiveIdentity = recovered
                }
            }
            let remintDecision = OrphanResendRemintPolicy.decision(
                messageRecordSessionId: messageRecord?.sessionIdentityId,
                recoverySessionId: recoverySessionId,
                initiatingMarkSessionId: protectedId,
                markIsStateLess: markIsStateLess,
                recoverySessionIsLiveActive: recoverySessionIsLiveActive,
                priorRetransportCount: priorRetransportCount,
                remintsAfterRetransportProveFail: remintsAfterProveFail)

            switch remintDecision {
            case .retransportAlreadyServiced:
                let serviceKey = serviceKeyForPolicy
                if orphanResendTransport(forServiceKey: serviceKey) != nil {
                    retransportCached = true
                    if let recoverySessionId,
                       let recovered = ((try? await session.cache?.fetchSessionIdentities())
                        ?? identities).first(where: { $0.id == recoverySessionId })
                    {
                        replayIdentity = recovered
                    }
                    orphanResendRetransportCountByServiceKey[serviceKey] =
                        priorRetransportCount + 1
                    PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendRetransport sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) sessionId=\(recoverySessionId?.uuidString ?? "nil")")
                } else {
                    // Process restart / cache eviction: mint once more.
                    PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendRetransportCacheMiss sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString)")
                    do {
                        let priorRecordSessionId = messageRecord?.sessionIdentityId
                        replayIdentity = try await session.resetSessionIdentityForFreshSession(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            sendOneTimeIdentities: true,
                            reason: "orphanResend")
                        await session.markOrphanResendInitiatingSession(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            sessionId: replayIdentity.id)
                        identity = replayIdentity
                        clearPreferredSessionIdentity(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId)
                        await demotePriorOrphanMessageRecordSession(
                            priorSessionId: priorRecordSessionId,
                            newSessionId: replayIdentity.id,
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            session: session)
                        PQSAuditLog.log(.recovery, "pqs.recovery.orphanResend sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) newSessionId=\(replayIdentity.id.uuidString)")
                    } catch {
                        logger.log(
                            level: .warning,
                            message: "pqs.recovery.orphanResendFailed sharedId=\(failedSharedMessageId) error=\(error)")
                    }
                }

            case .mintFreshAfterRetransportProveFailed:
                // Escape blankForHeaderExists trap: new OTK header on settled
                // recovery NACK (identical-CT retransport cannot rearm). Cap per serviceKey (P3).
                do {
                    replayIdentity = try await performOrphanEscapeRemint(
                        serviceKey: serviceKeyForPolicy,
                        remintsAfterProveFail: remintsAfterProveFail,
                        priorRecordSessionId: messageRecord?.sessionIdentityId,
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId,
                        sharedId: failedSharedMessageId,
                        session: session)
                    identity = replayIdentity
                } catch {
                    logger.log(
                        level: .warning,
                        message: "pqs.recovery.orphanResendFailed sharedId=\(failedSharedMessageId) error=\(error)")
                }

            case .reuseStateLessMark:
                if let protected = protectedIdentity {
                    replayIdentity = protected
                    identity = protected
                    clearPreferredSessionIdentity(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.orphanResendReused sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId) sessionId=\(protected.id)")
                    PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendReused sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) sessionId=\(protected.id.uuidString)")
                } else if let protectedId {
                    await session.clearOrphanResendInitiatingSession(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendStickyAdvancedRemint sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) priorSessionId=\(protectedId.uuidString)")
                }

            case .reuseRecoveryWave:
                // Continue the same recovery ratchet for unrecovered
                // sharedIds (msg1+). Do not mint a competing blank.
                if let recovered = recoveryLiveIdentity {
                    replayIdentity = recovered
                    identity = recovered
                    clearPreferredSessionIdentity(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendReused sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) sessionId=\(recovered.id.uuidString) reason=reuseRecoveryWave")
                }

            case .exhaustedUnrecoverable:
                // Heal sequence done (retransport → remint → retransport
                // prove-fail). Terminal unavailable — no further remint
                // or retransport; keep recovery lane for other sharedIds.
                PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendHealExhausted sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString)")
                replayMissingCount += 1
                unavailableIds.append(failedEnvelopeMessageId)
                missingByReason["healExhausted", default: 0] += 1
                await session.markResendUnavailable(
                    requestingDeviceId: request.requestingDeviceId,
                    sharedId: failedEnvelopeMessageId)
                continue

            case .mintFresh:
                if let protectedId, !markIsStateLess {
                    await session.clearOrphanResendInitiatingSession(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    if protectedId != replayIdentity.id {
                        PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendStickyAdvancedRemint sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) priorSessionId=\(protectedId.uuidString)")
                    }
                }
                let replayProps = await replayIdentity.props(symmetricKey: symmetricKey)
                if replayProps?.state == nil,
                   let record = messageRecord,
                   record.sessionIdentityId == replayIdentity.id
                {
                    await session.markOrphanResendInitiatingSession(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId,
                        sessionId: replayIdentity.id)
                    clearPreferredSessionIdentity(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.orphanResendRearmed sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId) sessionId=\(replayIdentity.id) reason=stateLess")
                    PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendRearmed sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) sessionId=\(replayIdentity.id.uuidString) reason=stateLess")
                } else {
                    do {
                        let priorRecordSessionId = messageRecord?.sessionIdentityId
                        replayIdentity = try await session.resetSessionIdentityForFreshSession(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            sendOneTimeIdentities: true,
                            reason: "orphanResend")
                        await session.markOrphanResendInitiatingSession(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            sessionId: replayIdentity.id)
                        identity = replayIdentity
                        clearPreferredSessionIdentity(
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId)
                        await demotePriorOrphanMessageRecordSession(
                            priorSessionId: priorRecordSessionId,
                            newSessionId: replayIdentity.id,
                            secretName: requesterSecretName,
                            deviceId: request.requestingDeviceId,
                            session: session)
                        logger.log(
                            level: .info,
                            message: "pqs.recovery.orphanResend sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId) newSessionId=\(replayIdentity.id)")
                        PQSAuditLog.log(.recovery, "pqs.recovery.orphanResend sharedId=\(failedSharedMessageId) requester=\(requesterSecretName) deviceId=\(request.requestingDeviceId.uuidString) newSessionId=\(replayIdentity.id.uuidString)")
                    } catch {
                        logger.log(
                            level: .warning,
                            message: "pqs.recovery.orphanResendFailed sharedId=\(failedSharedMessageId) error=\(error)")
                    }
                }
            }

            // Track pending for the whole wave before any encrypt so
            // MessageRecord/ledger updates and wave-drain stay serial
            // within this mailbox item (no interleaved inbound jobs).
            rememberResendReplayQueued(
                sharedId: failedSharedMessageId,
                requesterName: requesterSecretName,
                requesterDeviceId: request.requestingDeviceId,
                servicedFromPersistedStore: servicedFromPersistedStore)
            pendingOrphanEncrypts.append((
                sharedId: failedSharedMessageId,
                requestedEnvelopeMessageId: failedEnvelopeMessageId,
                message: cryptoMessage,
                identity: replayIdentity,
                retransportCached: retransportCached
            ))
        }

        // Serial recovery mailbox: encrypt+send each orphan replay inline.
        // One recovery ratchet per peer-device wave — continue msg1+ when
        // an earlier sharedId already advanced the row (no PerSharedId remint).
        for pending in pendingOrphanEncrypts {
            let serviceKey = orphanResendServiceKey(
                requestingDeviceId: request.requestingDeviceId,
                sharedId: pending.sharedId)
            do {
                if pending.retransportCached,
                   let cached = orphanResendTransport(forServiceKey: serviceKey)
                {
                    try await session.transportDelegate?.sendMessage(
                        cached.message,
                        metadata: cached.metadata)
                    await noteResendReplayTransported(sharedId: pending.sharedId)
                    PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendRetransport sharedId=\(pending.sharedId) sessionId=\(pending.identity.id.uuidString) requesterDeviceId=\(request.requestingDeviceId.uuidString)")
                    replayQueuedCount += 1
                    queuedIds.append(pending.requestedEnvelopeMessageId)
                    continue
                }

                // Mid-wave: if MessageRecord already settled on recovery for
                // this sharedId and we have cached ciphertext, retransport.
                let encryptIdentity = pending.identity
                let encryptProps = await encryptIdentity.props(symmetricKey: symmetricKey)
                if encryptProps?.state != nil {
                    let record = await session.outboundDeviceSendRecord(
                        sharedId: pending.sharedId,
                        recipientDeviceId: request.requestingDeviceId)
                    let recoveryId = await session.orphanResendRecoverySessionId(
                        secretName: requesterSecretName,
                        deviceId: request.requestingDeviceId)
                    let midWave = OrphanResendRemintPolicy.decision(
                        messageRecordSessionId: record?.sessionIdentityId,
                        recoverySessionId: recoveryId,
                        initiatingMarkSessionId: encryptIdentity.id,
                        markIsStateLess: false,
                        recoverySessionIsLiveActive: true)
                    if midWave == .retransportAlreadyServiced,
                       let cached = orphanResendTransport(forServiceKey: serviceKey)
                    {
                        try await session.transportDelegate?.sendMessage(
                            cached.message,
                            metadata: cached.metadata)
                        await noteResendReplayTransported(sharedId: pending.sharedId)
                        PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendRetransport sharedId=\(pending.sharedId) sessionId=\(encryptIdentity.id.uuidString) requesterDeviceId=\(request.requestingDeviceId.uuidString)")
                        replayQueuedCount += 1
                        queuedIds.append(pending.requestedEnvelopeMessageId)
                        continue
                    }
                    // Else continue encrypt on the same recovery identity.
                }
                try await handleWriteMessage(
                    outboundTask: OutboundTaskMessage(
                        message: pending.message,
                        recipientIdentity: encryptIdentity,
                        localId: UUID(),
                        sharedId: pending.sharedId,
                        isPersistedOutbound: false
                    ),
                    session: session)
                PQSAuditLog.log(.recovery, "pqs.recovery.orphanResendMessageRecordUpdated sharedId=\(pending.sharedId) sessionId=\(encryptIdentity.id.uuidString) requesterDeviceId=\(request.requestingDeviceId.uuidString)")
                replayQueuedCount += 1
                queuedIds.append(pending.requestedEnvelopeMessageId)
            } catch {
                logger.log(
                    level: .warning,
                    message: "pqs.recovery.orphanResendEncryptFailed sharedId=\(pending.sharedId) error=\(error)")
                await noteResendReplayDropped(
                    sharedId: pending.sharedId,
                    reason: "orphanResendEncryptFailed")
            }
        }
        if replayQueuedCount > 0 {
            logger.log(
                level: .info,
                message: "pqs.recovery.resendReplayQueued sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) queuedCount=\(replayQueuedCount) skippedCount=\(replayMissingCount) coalescedCount=\(replayCoalescedCount) requestedCount=\(request.failedSharedMessageIds.count)")
        } else if replayCoalescedCount > 0 {
            logger.log(
                level: .info,
                message: "pqs.recovery.resendReplayCoalescedAll sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) coalescedCount=\(replayCoalescedCount) skippedCount=\(replayMissingCount) requestedCount=\(request.failedSharedMessageIds.count)")
            // Fully coalesced servicing sends nothing back; without this
            // audit the requester's retries look unanswered for no reason.
            PQSAuditLog.log(.recovery, "pqs.recovery.resendReplayCoalescedAll requester=\(requesterSecretName) requestingDeviceId=\(request.requestingDeviceId.uuidString) coalescedCount=\(replayCoalescedCount) requestedCount=\(request.failedSharedMessageIds.count)")
        } else if replayMissingCount == 0, knownUnavailableCount > 0 {
            // Every requested id was already proven unreplayable in a
            // previous pass: re-send the notice below without re-running
            // lookups or re-auditing a full resendReplayFailed.
            logger.log(
                level: .info,
                message: "pqs.recovery.resendReplayShortCircuited reason=knownUnavailable sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) knownUnavailableCount=\(knownUnavailableCount) requestedCount=\(request.failedSharedMessageIds.count)")
        } else {
            // Terminal for the requested content: we have nothing to
            // replay. The messageResendUnavailable notice below tells the
            // requester to stop asking. Content the sender never persisted
            // is unrecoverable by design — the requester's lane still
            // heals via peerRefresh and *new* messages flow; only the
            // original frames stay lost. Audit which ids hit this so
            // production logs show whether they were ephemeral/control
            // frames (expected) or persisted chat (a replay-lookup bug).
            let reasonsSummary = missingByReason
                .sorted { $0.key < $1.key }
                .map { "\($0.key):\($0.value)" }
                .joined(separator: ",")
            logger.log(
                level: .warning,
                message: "pqs.recovery.resendReplayFailed reason=noReplayableMessages sender=\(requesterSecretName) senderDeviceId=\(requesterWireDeviceId) skippedCount=\(replayMissingCount) requestedCount=\(request.failedSharedMessageIds.count) reasons=\(reasonsSummary)")
            PQSAuditLog.log(.recovery, "pqs.recovery.resendReplayFailed reason=noReplayableMessages requester=\(requesterSecretName) requesterDeviceId=\(requesterWireDeviceId.uuidString) requestedCount=\(request.failedSharedMessageIds.count) reasons=\(reasonsSummary) sharedIds=\(request.failedSharedMessageIds.joined(separator: ","))")
        }

        await emitResendUnavailableNotice(
            to: identity,
            requesterName: requesterSecretName,
            requesterDeviceId: request.requestingDeviceId,
            unavailableIds: unavailableIds,
            session: session)
        // Local honesty: if we told the peer these ids are gone, any
        // matching outbound rows on this device must not keep a
        // delivered/read glyph.
        if let sessionDelegate = await session.sessionDelegate {
            for envelopeMessageId in unavailableIds {
                let sharedId =
                    await session.outboundDeviceSendRecord(
                        envelopeMessageId: envelopeMessageId)?.sharedId
                    ?? envelopeMessageId
                await sessionDelegate.outboundMessageUnrecoverable(
                    sharedMessageId: sharedId,
                    reason: "noReplay")
            }
        }

        return PQSSession.OutOfBandResendResult(
            queuedIds: queuedIds,
            permanentlyUnavailableIds: unavailableIds)
    }

    func handleOutOfBandResendRequest(
        from senderName: String,
        deviceId senderDeviceId: UUID,
        failedSharedMessageIds: [String],
        session: PQSSession
    ) async throws -> PQSSession.OutOfBandResendResult {
        let requestedIds = failedSharedMessageIds
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !requestedIds.isEmpty else {
            return PQSSession.OutOfBandResendResult(queuedIds: [], permanentlyUnavailableIds: [])
        }
        let request = FailedMessageResendRequest(
            failedSharedMessageIds: requestedIds,
            requestingDeviceId: senderDeviceId)
        return try await serviceAuthenticatedResendRequest(
            requesterSecretName: senderName,
            requesterWireDeviceId: senderDeviceId,
            request: request,
            session: session)
    }

    private func isReplayableNonPersistentControl(
        _ message: CryptoMessage,
        session: PQSSession
    ) async -> Bool {
        guard let transportInfo = message.transportInfo,
              let event = try? BinaryDecoder().decode(TransportEvent.self, from: transportInfo)
        else {
            return await session.sessionDelegate?
                .shouldReplayNonPersistentOutbound(transportInfo: message.transportInfo) == true
        }

        switch event {
        case .sessionReestablishment(let envelope):
            return envelope.isResponse
        case .linkedDeviceReprovisioning:
            return true
        case .messageResendUnavailable, .requestMessageResend:
            // DEAD LEGACY: encrypted retry controls are not replayed. Confirm unused, then delete.
            return false
        case .synchronizeOneTimeKeys, .refreshOneTimeKeys, .publishedOneTimeKeysReplenished:
            return false
        }
    }

    private func removeKeys(session: PQSSession, curveId: String?, mlKEMId: String) async throws {
        
        guard let cache = await session.cache else { return }
        let data = try await cache.fetchLocalSessionContext()
        
        // Decrypt the session context data using the app's symmetric key
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: session.getAppSymmetricKey()) else {
            return
        }
        
        // Decode the session context from the decrypted data
        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)
        
        if let curveId {
            try await delegate?.deleteOneTimeKeys(for: sessionContext.sessionUser.secretName, with: curveId, type: .curve)
        }
        try await delegate?.deleteOneTimeKeys(for: sessionContext.sessionUser.secretName, with: mlKEMId, type: .mlKEM)
        logger.log(level: .info, message: "Requested to Remove Remote Public Curve and MLKEM One Time Keys")
        
        sessionContext.activeUserConfiguration.signedOneTimePublicKeys.removeAll(where: { $0.id.uuidString == curveId })
        sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.removeAll(where: { $0.id.uuidString == mlKEMId })
        sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.removeAll(where: { $0.id.uuidString == curveId })
        sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.removeAll(where: { $0.id.uuidString == mlKEMId })
        
        await session.setSessionContext(sessionContext)
        
        let encodedData = try BinaryEncoder().encode(sessionContext)
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: session.getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encryptedConfig)
        logger.log(level: .info, message: "Removed Local Curve and MLKEM One Time Keys")
    }

    private func sendDeferredResendRequests(
        _ pendingRequests: [PQSSession.PendingResendAfterReestablishment],
        session: PQSSession,
        reason: String
    ) async {
        guard !pendingRequests.isEmpty else { return }

        struct ResendGroupKey: Hashable {
            let senderName: String
            let senderDeviceId: UUID
        }

        let grouped = Dictionary(grouping: pendingRequests) {
            ResendGroupKey(senderName: $0.senderName, senderDeviceId: $0.senderDeviceId)
        }

        for (key, groupedRequests) in grouped {
            var ready: [PQSSession.PendingResendAfterReestablishment] = []
            for pending in groupedRequests {
                // Terminal cap: if the peer's unavailable notice never arrived, stop
                // after a bounded number of submissions instead of looping until the
                // pending TTL. Dropped ids are not re-deferred.
                let attempts = await session.resendRequestSubmissionCount(
                    sender: pending.senderName,
                    deviceId: pending.senderDeviceId,
                    failedMessageId: pending.failedSharedMessageId)
                if attempts >= PQSSessionConstants.peerResendRequestMaxSubmissions {
                    logger.log(
                        level: .warning,
                        message: "pqs.recovery.pendingResendExhausted sharedId=\(pending.failedSharedMessageId) sender=\(pending.senderName) deviceId=\(pending.senderDeviceId) failureClass=\(pending.failureClass) attempts=\(attempts)")
                    PQSAuditLog.log(.recovery, "pqs.recovery.pendingResendExhausted sharedId=\(pending.failedSharedMessageId) sender=\(pending.senderName) deviceId=\(pending.senderDeviceId.uuidString) failureClass=\(pending.failureClass) attempts=\(attempts)")
                    // Terminal on the requester: stop asking and quarantine so poison
                    // redelivery cannot reopen recovery for this sharedId.
                    await session.clearPendingResends(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        messageIds: [pending.failedSharedMessageId])
                    let newlyTerminal = await session.markInboundContentUnrecoverable(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        sharedId: pending.failedSharedMessageId)
                    if newlyTerminal {
                        PQSAuditLog.log(.recovery, "pqs.recovery.contentUnrecoverable sharedId=\(pending.failedSharedMessageId) sender=\(pending.senderName) deviceId=\(pending.senderDeviceId.uuidString) reason=resendSubmissionCap attempts=\(attempts)")
                        await session.sessionDelegate?.inboundContentUnrecoverable(
                            senderSecretName: pending.senderName,
                            senderDeviceId: pending.senderDeviceId,
                            sharedMessageId: pending.failedSharedMessageId)
                    }
                    continue
                }

                guard await session.canSendPeerResendRequest(
                    sender: pending.senderName,
                    deviceId: pending.senderDeviceId,
                    failedMessageId: pending.failedSharedMessageId
                ) else {
                    await session.deferPeerResendUntilReestablished(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        failedMessageId: pending.failedSharedMessageId,
                        failureClass: pending.failureClass)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.resendDeferredStillWaiting reason=cooldown sharedId=\(pending.failedSharedMessageId) sender=\(pending.senderName) deviceId=\(pending.senderDeviceId) failureClass=\(pending.failureClass)")
                    continue
                }
                ready.append(pending)
            }

            guard !ready.isEmpty else { continue }

            do {
                let sharedIds = ready.map(\.failedSharedMessageId)
                logger.log(
                    level: .info,
                    message: "pqs.recovery.resendDrainStarted reason=\(reason) count=\(sharedIds.count) sender=\(key.senderName) deviceId=\(key.senderDeviceId) ids=\(sharedIds.joined(separator: ","))")
                for pending in ready {
                    await session.deferPeerResendUntilReestablished(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        failedMessageId: pending.failedSharedMessageId,
                        failureClass: pending.failureClass,
                        notifyDelegate: false)
                }
                try await session.requestMessageResend(
                    sharedMessageIds: sharedIds,
                    senderName: key.senderName,
                    senderDeviceId: key.senderDeviceId)
                for pending in ready {
                    await session.markPeerResendRequestSent(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        failedMessageId: pending.failedSharedMessageId)
                    await session.markInboundFailure(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        messageId: pending.failedSharedMessageId,
                        failureClass: pending.failureClass)
                }
                logger.log(
                    level: .info,
                    message: "pqs.recovery.resendDrainSubmitted reason=\(reason) count=\(sharedIds.count) sender=\(key.senderName) deviceId=\(key.senderDeviceId) ids=\(sharedIds.joined(separator: ","))")
                PQSAuditLog.log(.recovery, "pqs.recovery.resendDrainSubmitted reason=\(reason) count=\(sharedIds.count) sender=\(key.senderName) deviceId=\(key.senderDeviceId.uuidString) ids=\(sharedIds.joined(separator: ","))")
            } catch {
                for pending in ready {
                    await session.deferPeerResendUntilReestablished(
                        sender: pending.senderName,
                        deviceId: pending.senderDeviceId,
                        failedMessageId: pending.failedSharedMessageId,
                        failureClass: pending.failureClass)
                }
                logger.log(
                    level: .warning,
                    message: "pqs.recovery.resendDrainFailed reason=\(reason) count=\(ready.count) sender=\(key.senderName) deviceId=\(key.senderDeviceId) error=\(error)")
                PQSAuditLog.log(.recovery, "pqs.recovery.resendDrainFailed reason=\(reason) count=\(ready.count) sender=\(key.senderName) deviceId=\(key.senderDeviceId.uuidString) error=\(error)")
            }
        }
    }
    
    /// Initializes the recipient for a session based on the provided ratchet message.
    ///
    /// This method sets up the recipient side of the Double Ratchet protocol by
    /// selecting appropriate keys and initializing the ratchet state. It handles
    /// both initial session setup and subsequent message processing.
    ///
    /// ## Initialization Process
    /// 1. Validates session context and identity
    /// 2. Selects appropriate local keys based on ratchet message
    /// 3. Initializes ratchet state with remote and local keys
    /// 4. Removes used keys to maintain forward secrecy
    /// 5. Updates session state for future messages
    ///
    /// ## Key Selection
    /// - One-time keys are selected based on message header
    /// - PQ-KEM keys are selected for post-quantum security
    /// - Long-term keys are used for session establishment
    /// - Key rotation is handled automatically
    ///
    /// ## Security Considerations
    /// - Keys are validated before use to prevent attacks
    /// - Used keys are immediately removed to maintain forward secrecy
    /// - Session state is updated atomically
    /// - Failed initialization is handled gracefully
    ///
    /// - Parameters:
    ///   - sessionIdentity: The session identity of the recipient. Contains
    ///                      the cryptographic state and key information.
    ///   - session: The current crypto session providing context and keys.
    ///   - ratchetMessage: The ratchet message to initialize with. Contains
    ///                     the remote keys and initialization data.
    /// - Throws: An error if the initialization fails due to missing keys,
    ///           cryptographic errors, or invalid state.
    private func initializeRecipient(
        sessionIdentity: SessionIdentity,
        session: PQSSession,
        ratchetMessage: RatchetMessage
    ) async throws {
        self.session = session
        guard let sessionContext = await session.sessionContext else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        
        var localOneTimePrivateKey: CurvePrivateKey?
        var localMLKEMPrivateKey: MLKEMPrivateKey
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw DoubleRatchetKit.CryptoError.propsError
        }
        
        let localPrivateKeys = sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys
        let localMLKEMPrivateKeys = sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys
        
        if let oneTimeKeyId = ratchetMessage.header.oneTimeKeyId {
            if let privateOneTimeKey = localPrivateKeys.first(where: { $0.id == oneTimeKeyId }) {
                localOneTimePrivateKey = privateOneTimeKey
            } else if let state = props.state, state.localOneTimePrivateKey?.id == oneTimeKeyId {
                localOneTimePrivateKey = state.localOneTimePrivateKey
            } else {
                if shouldEmitKeyPayloadLogs {
                    logger.log(level: .debug, message: """
                        OTK mismatch: headerOTK=\(oneTimeKeyId.uuidString) \
                        localPoolSize=\(localPrivateKeys.count) \
                        localPoolIDs=\(localPrivateKeys.prefix(5).map(\.id.uuidString)) \
                        hasState=\(props.state != nil) \
                        stateOTK=\(props.state?.localOneTimePrivateKey?.id.uuidString ?? "nil") \
                        sender=\(props.secretName) deviceId=\(props.deviceId)
                        """)
                }
                throw RatchetError.missingOneTimeKey
            }
        } else {
            localOneTimePrivateKey = nil
        }
        
        if let mlKEMOneTimeKeyId = ratchetMessage.header.mlKEMOneTimeKeyId {
            if let privateMLKEMOneTimeKey = localMLKEMPrivateKeys.first(where: { $0.id == mlKEMOneTimeKeyId }) {
                localMLKEMPrivateKey = privateMLKEMOneTimeKey
            } else if sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey.id == mlKEMOneTimeKeyId {
                localMLKEMPrivateKey = sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
            } else if let state = props.state, state.localMLKEMPrivateKey.id == mlKEMOneTimeKeyId {
                localMLKEMPrivateKey = state.localMLKEMPrivateKey
            } else {
                if shouldEmitKeyPayloadLogs {
                    logger.log(level: .debug, message: """
                        MLKEM OTK mismatch: headerMLKEM=\(mlKEMOneTimeKeyId.uuidString) \
                        localPoolSize=\(localMLKEMPrivateKeys.count) \
                        finalMLKEM=\(sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey.id.uuidString) \
                        hasState=\(props.state != nil) \
                        sender=\(props.secretName) deviceId=\(props.deviceId)
                        """)
                }
                throw RatchetError.missingOneTimeKey
            }
        } else {
            localMLKEMPrivateKey = sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
        }
        
        
        if shouldEmitKeyPayloadLogs {
            logger.log(level: .debug, message: """
                recipientInit: sender=\(props.secretName)\n
                headerOTK=\(ratchetMessage.header.oneTimeKeyId?.uuidString ?? "nil")\n
                headerMLKEM=\(ratchetMessage.header.mlKEMOneTimeKeyId?.uuidString ?? "nil")\n
                selectedLocalOTK=\(localOneTimePrivateKey?.id.uuidString ?? "nil")\n
                selectedLocalMLKEM=\(localMLKEMPrivateKey.id.uuidString)\n
                headerRemoteLTK=\(ratchetMessage.header.remoteLongTermPublicKey.prefix(10).base64EncodedString())
                """)
        }
        try await ratchetManager.recipientInitialization(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: databaseSymmetricKey,
            header: ratchetMessage.header,
            localKeys: .init(
                longTerm: .init(sessionContext.sessionUser.deviceKeys.longTermPrivateKey),
                oneTime: localOneTimePrivateKey,
                mlKEM: localMLKEMPrivateKey))
    }
    
    /// Handles the processing of a decoded message, specifically for private messages,
    /// regardless of their communication type. This method utilizes the recipient information
    /// for reference when looking up communication models, but the recipient itself is not persisted.
    ///
    /// On the initial creation of the communication model, necessary metadata must be provided.
    /// If the required metadata is not present in the decoded recipient and the communication model
    /// does not already exist, it should be included in the message metadata (e.g., members, admin, organizers).
    ///
    /// ## Message Processing Flow
    /// 1. Determines message recipient type (nickname, personal, channel, broadcast)
    /// 2. Looks up or creates appropriate communication model
    /// 3. Updates communication metadata and message count
    /// 4. Creates encrypted message model
    /// 5. Persists message and notifies delegates
    ///
    /// ## Communication Types
    /// - **Nickname**: Direct messages between two users with nickname routing
    /// - **Personal**: Direct messages between two users
    /// - **Channel**: Group messages with multiple participants
    /// - **Broadcast**: System-wide messages (not persisted)
    ///
    /// ## Security Considerations
    /// - All message content is encrypted before persistence
    /// - Communication metadata is validated and sanitized
    /// - Message sequence numbers prevent replay attacks
    /// - Sender identity is verified before processing
    ///
    /// - Parameters:
    ///   - decodedMessage: The decoded `CryptoMessage` that needs to be processed.
    ///                     Contains the actual message content and recipient information.
    ///   - inboundTask: The `InboundTaskMessage` associated with the incoming message.
    ///                  Contains sender information and transport metadata.
    ///   - session: The current `PQSSession` in which the message is being processed.
    ///              Provides context and cryptographic keys.
    ///   - sessionIdentity: The `SessionIdentity` associated with the recipient of the message.
    ///                      Contains sender's cryptographic identity.
    /// After the transport accepts an outbound ratchet payload, move the local persisted copy off `.sending`
    /// so clients can show a stable "sent" state without waiting for a peer receipt.
    func markPersistedOutboundPastSendingIfNeeded(session: PQSSession, localMessageId: UUID) async {
        guard let cache = await session.cache else { return }
        let persisted: EncryptedMessage
        do {
            persisted = try await cache.fetchMessage(id: localMessageId)
        } catch {
            return
        }
        do {
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            guard var props = await persisted.props(symmetricKey: symmetricKey) else { return }
            guard case .sending = props.deliveryState else { return }
            props.deliveryState = .waitingDelivery
            let updated = try await persisted.updateMessage(with: props, symmetricKey: symmetricKey)
            try await cache.updateMessage(updated, symmetricKey: symmetricKey)
            await session.receiverDelegate?.updatedMessage(updated)
        } catch {
            logger.log(level: .debug, message: "markPersistedOutboundPastSendingIfNeeded failed: \(error)")
        }
    }
    
    /// Lets the original sender advance their outbound delivery glyph once we've decrypted and stored the message.
    /// Skips channels (noise) and self-sent / multidevice echoes.
    private func sendAutomaticDeliveredReceiptIfNeeded(
        session: PQSSession,
        inboundTask: InboundTaskMessage,
        sharedId: String,
        conversationRecipient: MessageRecipient
    ) async {
        switch conversationRecipient {
        case .nickname, .personalMessage:
            break
        default:
            return
        }
        guard let mySecretName = await session.sessionContext?.sessionUser.secretName else { return }
        guard inboundTask.senderSecretName != mySecretName else { return }
        guard let sessionDelegate = await session.sessionDelegate else { return }
        guard await sessionDelegate.shouldSendAutomaticDeliveryReceipts() else { return }
        
        let metadata = DeliveryStateMetadata(state: .delivered, sharedId: sharedId)
        let encoded: Data
        do {
            encoded = try BinaryEncoder().encode(metadata)
        } catch {
            return
        }
        let receiptRecipient = MessageRecipient.nickname(inboundTask.senderSecretName)
        do {
            try await sessionDelegate.deliveryStateChanged(recipient: receiptRecipient, metadata: encoded)
        } catch {
            logger.log(level: .debug, message: "Automatic delivered receipt failed for sharedId=\(sharedId): \(error)")
        }
    }
    
    /// - Throws: An error if the message processing fails due to issues such as missing metadata,
    ///           session errors, or communication model errors.
    private func handleDecodedMessage(_ decodedMessage: CryptoMessage,
                                      
                                      inboundTask: InboundTaskMessage,
                                      session: PQSSession,
                                      sessionIdentity: SessionIdentity) async throws
    {
        guard let cache = await session.cache else { throw PQSSession.SessionErrors.databaseNotInitialized }
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()

        // Duplicate-persist guard: the same logical message can decrypt twice
        // (an orphan replay landing after the original, or a redelivery racing
        // the ingress guard). One sharedId from one sender tuple is one chat
        // row — persisting again would mint a second row with a fresh UUID and
        // notify the host twice. The sender-tuple match keeps this from ever
        // colliding with a *different* sender's frame or with our own outbound
        // record for the same conversation.
        if let existing = try await cache.fetchMessageIfExists(
            sharedId: inboundTask.resolvedLogicalSharedId),
           let existingProps = await existing.props(symmetricKey: databaseSymmetricKey),
           existingProps.senderSecretName == inboundTask.senderSecretName,
           existingProps.senderDeviceId == inboundTask.senderDeviceId
        {
            PQSAuditLog.log(.recovery, "pqs.recovery.duplicateInboundPersistSkipped envelope=\(inboundTask.sharedMessageId) logical=\(inboundTask.resolvedLogicalSharedId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId.uuidString)")
            return
        }
        
        switch decodedMessage.recipient {
        case let .nickname(recipient):
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            // This can happen on multidevice support when a sender is also sending a message to it's master/child device.
            let isMe = await inboundTask.senderSecretName == session.sessionContext?.sessionUser.secretName
            do {
                // Need to flip recipient
                communicationModel = try await findCommunicationType(
                    cache: cache,
                    communicationType: .nickname(isMe ? recipient : inboundTask.senderSecretName),
                    session: session
                )
                
                var communication = try await communicationModel.makeDecryptedModel(of: Communication.self, symmetricKey: databaseSymmetricKey)
                communication.messageCount += 1
                
                _ = try await communicationModel.updateProps(
                    symmetricKey: databaseSymmetricKey,
                    props: BaseCommunication.UnwrappedProps(
                        sharedId: communication.sharedId,
                        messageCount: communication.messageCount,
                        administrator: communication.administrator,
                        operators: communication.operators,
                        members: communication.members,
                        metadata: communication.metadata,
                        blockedMembers: communication.blockedMembers,
                        communicationType: communication.communicationType
                    )
                )
                
                shouldUpdateCommunication = true
            } catch {
                // Need to flip recipient
                communicationModel = try await createCommunicationModel(
                    recipients: [recipient, inboundTask.senderSecretName],
                    communicationType: .nickname(isMe ? recipient : inboundTask.senderSecretName),
                    metadata: decodedMessage.metadata,
                    symmetricKey: databaseSymmetricKey
                )
                try await cache.createCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: [recipient, inboundTask.senderSecretName])
            }
            
            let messageModel = try await createInboundMessageModel(
                decodedMessage: decodedMessage,
                inboundTask: inboundTask,
                senderSecretName: inboundTask.senderSecretName,
                senderDeviceId: inboundTask.senderDeviceId,
                session: session,
                communication: communicationModel,
                sessionIdentity: sessionIdentity
            )
            
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
                if let members = await communicationModel.props(symmetricKey: databaseSymmetricKey)?.members {
                    await session.receiverDelegate?.updatedCommunication(communicationModel, members: members)
                }
            }
            
            try await cache.createMessage(messageModel, symmetricKey: databaseSymmetricKey)
            logger.log(level: .info, message: "Inbound message persisted with sharedId=\(messageModel.sharedId), recipient=\(decodedMessage.recipient), flag=\(decodedMessage.transportInfo != nil ? "hasTransportInfo" : "noTransportInfo")")
            PQSAuditLog.log(.recv, "pqs.recv.persisted sharedId=\(messageModel.sharedId) sender=\(inboundTask.senderSecretName) senderDeviceId=\(inboundTask.senderDeviceId.uuidString) recipient=\(decodedMessage.recipient.auditRecipientTag) sessionIdentityId=\(sessionIdentity.id.uuidString)",
                level: .info)
            
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
            await sendAutomaticDeliveredReceiptIfNeeded(
                session: session,
                inboundTask: inboundTask,
                sharedId: messageModel.sharedId,
                conversationRecipient: decodedMessage.recipient)
        case .personalMessage:
            let sender = inboundTask.senderSecretName
            guard let mySecretName = await session.sessionContext?.sessionUser.secretName else { return }
            
            let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            do {
                communicationModel = try await findCommunicationType(
                    cache: cache,
                    communicationType: decodedMessage.recipient,
                    session: session
                )
                
                var communication = try await communicationModel.makeDecryptedModel(of: Communication.self, symmetricKey: databaseSymmetricKey)
                communication.messageCount += 1
                
                _ = try await communicationModel.updateProps(
                    symmetricKey: databaseSymmetricKey,
                    props: BaseCommunication.UnwrappedProps(
                        sharedId: communication.sharedId,
                        messageCount: communication.messageCount,
                        administrator: communication.administrator,
                        operators: communication.operators,
                        members: communication.members,
                        metadata: communication.metadata,
                        blockedMembers: communication.blockedMembers,
                        communicationType: communication.communicationType
                    )
                )
                
                shouldUpdateCommunication = true
            } catch {
                communicationModel = try await createCommunicationModel(
                    recipients: [sender],
                    communicationType: decodedMessage.recipient,
                    metadata: decodedMessage.metadata,
                    symmetricKey: databaseSymmetricKey
                )
                
                try await cache.createCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: [mySecretName])
            }
            
            let messageModel = try await createInboundMessageModel(
                decodedMessage: decodedMessage,
                inboundTask: inboundTask,
                senderSecretName: sender,
                senderDeviceId: inboundTask.senderDeviceId,
                session: session,
                communication: communicationModel,
                sessionIdentity: sessionIdentity
            )
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: [mySecretName])
            }
            
            try await cache.createMessage(messageModel, symmetricKey: databaseSymmetricKey)
            logger.log(level: .info, message: "Inbound message persisted with sharedId=\(messageModel.sharedId), recipient=\(decodedMessage.recipient), flag=\(decodedMessage.transportInfo != nil ? "hasTransportInfo" : "noTransportInfo")")
            PQSAuditLog.log(.recv, "pqs.recv.persisted sharedId=\(messageModel.sharedId) sender=\(inboundTask.senderSecretName) senderDeviceId=\(inboundTask.senderDeviceId.uuidString) recipient=\(decodedMessage.recipient.auditRecipientTag) sessionIdentityId=\(sessionIdentity.id.uuidString)",
                level: .info)
            
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
            await sendAutomaticDeliveredReceiptIfNeeded(
                session: session,
                inboundTask: inboundTask,
                sharedId: messageModel.sharedId,
                conversationRecipient: decodedMessage.recipient)
        case .channel:
            let sender = inboundTask.senderSecretName
            var communicationModel: BaseCommunication
            var shouldUpdateCommunication = false
            
            // Channel Models need to be created before a message is sent or received
            do {
                communicationModel = try await findCommunicationType(
                    cache: cache,
                    communicationType: decodedMessage.recipient,
                    session: session
                )
                
                guard var newProps = await communicationModel.props(symmetricKey: databaseSymmetricKey) else { return }
                newProps.messageCount += 1
                _ = try await communicationModel.updateProps(symmetricKey: databaseSymmetricKey, props: newProps)
                shouldUpdateCommunication = true
            } catch {
                // Create the communication if it doesn't exist for channel (only when metadata contains ChannelInfo)
                guard case let .channel(channelName) = decodedMessage.recipient else {
                    throw error
                }
                guard !decodedMessage.metadata.isEmpty else {
                    throw error
                }
                let info: ChannelInfo
                do {
                    info = try BinaryDecoder().decode(ChannelInfo.self, from: decodedMessage.metadata)
                } catch {
                    throw error
                }
                
                communicationModel = try await createCommunicationModel(
                    administrator: info.administrator,
                    operators: info.operators,
                    recipients: info.members,
                    communicationType: .channel(channelName),
                    metadata: decodedMessage.metadata,
                    symmetricKey: databaseSymmetricKey
                )
                try await cache.createCommunication(communicationModel)
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: info.members)
                await session.receiverDelegate?.createdChannel(communicationModel)
            }
            
            let messageModel = try await createInboundMessageModel(
                decodedMessage: decodedMessage,
                inboundTask: inboundTask,
                senderSecretName: sender,
                senderDeviceId: inboundTask.senderDeviceId,
                session: session,
                communication: communicationModel,
                sessionIdentity: sessionIdentity
            )
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
            }
            try await cache.createMessage(messageModel, symmetricKey: databaseSymmetricKey)
            if shouldUpdateCommunication,
               let members = await communicationModel.props(symmetricKey: databaseSymmetricKey)?.members {
                await session.receiverDelegate?.updatedCommunication(communicationModel, members: members)
            }
            logger.log(level: .info, message: "Inbound message persisted with sharedId=\(messageModel.sharedId), recipient=\(decodedMessage.recipient), flag=\(decodedMessage.transportInfo != nil ? "hasTransportInfo" : "noTransportInfo")")
            PQSAuditLog.log(.recv, "pqs.recv.persisted sharedId=\(messageModel.sharedId) sender=\(sender) senderDeviceId=\(inboundTask.senderDeviceId.uuidString) recipient=\(decodedMessage.recipient.auditRecipientTag) sessionIdentityId=\(sessionIdentity.id.uuidString)",
                level: .info)
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
        case .broadcast:
            // Outbound broadcast is fanned out as per-peer `.nickname` ciphertext; legacy `.broadcast` payloads are not used.
            break
        }
    }
    
    /// Verifies and decrypts an encrypted message received in an inbound task.
    ///
    /// This method extracts the ratchet message and the associated session identity
    /// from the inbound task, ensuring that the message is valid and can be processed.
    /// It performs signature verification to authenticate the sender and prevent
    /// impersonation attacks.
    ///
    /// ## Verification Process
    /// 1. Refreshes sender identities from the session
    /// 2. Finds the matching session identity for the sender
    /// 3. Extracts the signing public key from the identity
    /// 4. Verifies the message signature using the public key
    /// 5. Falls back to rotated keys if verification fails
    /// 6. Decodes the ratchet message for further processing
    ///
    /// ## Signature Verification
    /// - Primary verification uses the sender's current signing key
    /// - Fallback verification uses rotated keys if available
    /// - Invalid signatures result in authentication failure
    /// - Missing signatures are treated as security violations
    ///
    /// ## Security Considerations
    /// - Message signatures prevent impersonation and tampering
    /// - Key rotation is handled gracefully with fallback verification
    /// - Invalid messages are rejected to prevent attacks
    /// - Session identity validation ensures proper routing
    ///
    /// - Parameters:
    ///   - session: The current `PQSSession` in which the message verification is taking place.
    ///              Provides access to identity management and cryptographic keys.
    ///   - inboundTask: The `InboundTaskMessage` containing the encrypted message to be verified.
    ///                  Includes sender information and the signed message data.
    /// - Returns: A tuple containing the verified `RatchetMessage` and the associated `SessionIdentity`.
    /// - Throws: An error if the verification or decryption fails due to issues such as invalid message format,
    ///           session errors, or decryption errors.
    private func verifyEncryptedMessage(
        session: PQSSession,
        inboundTask: InboundTaskMessage
    ) async throws -> VerificationResult {
        var identities = try await session.refreshIdentities(secretName: inboundTask.senderSecretName)
        let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
        
        let preferredDevice = await currentDeviceConfiguration(
            secretName: inboundTask.senderSecretName,
            deviceId: inboundTask.senderDeviceId,
            session: session)
        var sessionIdentity = await bestSessionIdentity(
            secretName: inboundTask.senderSecretName,
            deviceId: inboundTask.senderDeviceId,
            in: identities,
            symmetricKey: databaseSymmetricKey,
            preferredDevice: preferredDevice)
        
        if sessionIdentity == nil { // SessionIdentity shouldn't be nil, but in case refresh never occured force it.
            identities = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
            sessionIdentity = await bestSessionIdentity(
                secretName: inboundTask.senderSecretName,
                deviceId: inboundTask.senderDeviceId,
                in: identities,
                symmetricKey: databaseSymmetricKey,
                preferredDevice: preferredDevice)
        }
        
        guard let sessionIdentity else {
            throw JobProcessorErrors.missingIdentity
        }
        
        // Unwrap properties and retrieve the public signing key
        guard let props = await sessionIdentity.props(symmetricKey: databaseSymmetricKey) else {
            throw JobProcessorErrors.missingIdentity
        }
        let currentKey = try Curve25519.Signing.PublicKey(rawRepresentation: props.signingPublicKey)
        
        // Verify the signature
        guard let signedMessage = inboundTask.message.signed else {
            throw PQSSession.SessionErrors.missingSignature
        }
        
        if try signedMessage.verifySignature(using: currentKey) {
            return try decode(signedMessage)
        } else {
            // Signature verification failed with current key, likely due to key rotation
            let refreshedIdentities = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
            
            // Find the refreshed identity with updated keys
            guard let refreshed = await bestSessionIdentity(
                secretName: inboundTask.senderSecretName,
                deviceId: inboundTask.senderDeviceId,
                in: refreshedIdentities,
                symmetricKey: databaseSymmetricKey,
                preferredDevice: preferredDevice)
            else {
                throw PQSSession.SessionErrors.invalidSignature
            }
            
            guard let refreshedProps = await refreshed.props(symmetricKey: databaseSymmetricKey) else {
                throw JobProcessorErrors.missingIdentity
            }
            let refreshedKey = try Curve25519.Signing.PublicKey(rawRepresentation: refreshedProps.signingPublicKey)
            
            guard try signedMessage.verifySignature(using: refreshedKey) else {
                let archivedIdentities = try await session.fetchArchivedSessionIdentities(
                    secretName: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)
                for archived in archivedIdentities {
                    guard let archivedProps = await archived.props(symmetricKey: databaseSymmetricKey) else {
                        continue
                    }
                    guard let archivedKey = try? Curve25519.Signing.PublicKey(rawRepresentation: archivedProps.signingPublicKey) else {
                        continue
                    }
                    if try signedMessage.verifySignature(using: archivedKey) {
                        logger.log(
                            level: .info,
                            message: "Verified inbound message from archived SessionIdentity for \(inboundTask.senderSecretName) (\(inboundTask.senderDeviceId))")
                        return try decode(signedMessage, identity: archived)
                    }
                }
                throw PQSSession.SessionErrors.invalidSignature
            }
            
            return try decode(signedMessage, identity: refreshed)
        }
        func decode(_
                    signedMessage: SignedRatchetMessage.Signed,
                    identity: SessionIdentity? = nil
        ) throws -> VerificationResult {
            let message = try BinaryDecoder().decode(RatchetMessage.self, from: signedMessage.data)
            return VerificationResult(
                ratchetMessage: message,
                sessionIdentity: identity ?? sessionIdentity)
        }
    }
    
    /// The data need to result in from a message verification
    private struct VerificationResult: Sendable {
        let ratchetMessage: RatchetMessage
        let sessionIdentity: SessionIdentity //Still will be the old session identity, this will get updated in the Double Ratchet.
    }
    
    private enum SessionReestablishmentDisposition {
        case ignore
        case refreshOnly
        case rotateCurrentDevice
        case compromiseObserved
    }
    
    private func sessionReestablishmentDisposition(
        for kind: SessionReestablishmentKind,
        inboundTask: InboundTaskMessage,
        decodedMessage: CryptoMessage,
        context: SessionContext
    ) throws -> SessionReestablishmentDisposition {
        switch kind {
        case .peerRefresh:
            return .refreshOnly
        case .linkedDeviceRepair, .linkedDeviceCompromiseObserved:
            guard decodedMessage.recipient == .personalMessage else { return .ignore }
            guard inboundTask.senderSecretName == context.sessionUser.secretName else { return .ignore }
            guard inboundTask.senderDeviceId != context.sessionUser.deviceId else { return .ignore }
            
            let verifiedDevices = try context.activeUserConfiguration.getVerifiedDevices()
            guard verifiedDevices.contains(where: { $0.deviceId == inboundTask.senderDeviceId }) else {
                return .ignore
            }
            
            switch kind {
            case .linkedDeviceRepair:
                return .rotateCurrentDevice
            case .linkedDeviceCompromiseObserved:
                return .compromiseObserved
            case .peerRefresh:
                return .refreshOnly
            }
        }
    }

    private func shouldAcceptLinkedDeviceReprovisioning(
        bundle: LinkedDeviceReprovisioningBundle,
        inboundTask: InboundTaskMessage,
        decodedMessage: CryptoMessage,
        context: SessionContext
    ) throws -> Bool {
        guard decodedMessage.recipient == .personalMessage else { return false }
        guard inboundTask.senderSecretName == context.sessionUser.secretName else { return false }
        guard inboundTask.senderDeviceId == bundle.issuedByDeviceId else { return false }
        guard bundle.targetDeviceId == context.sessionUser.deviceId else { return false }

        let verifiedDevices = try context.activeUserConfiguration.getVerifiedDevices()
        guard let senderDevice = verifiedDevices.first(where: { $0.deviceId == inboundTask.senderDeviceId }) else {
            return false
        }
        return senderDevice.isMasterDevice
    }

    private func performPendingLinkedDeviceRepair(session: PQSSession) async throws {
        guard let refreshedContext = await session.sessionContext else { return }
        guard let currentDevice = try refreshedContext.activeUserConfiguration
            .getVerifiedDevices()
            .first(where: { $0.deviceId == refreshedContext.sessionUser.deviceId }) else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }
        if currentDevice.isMasterDevice {
            logger.log(level: .info, message: "Master device received linked-device repair request; refreshing identities only")
            await session.setPendingLinkedDeviceRepair(false)
        } else {
            try await session.rotateCurrentDeviceKeys()
            await session.setPendingLinkedDeviceRepair(false)
        }
    }
    
    /// Signs a ratchet message using the cryptographic session's signing capabilities.
    ///
    /// This method ensures the integrity and authenticity of the ratchet message by applying
    /// a digital signature using the device's signing private key. The signature prevents
    /// tampering and impersonation attacks during message transmission.
    ///
    /// ## Signing Process
    /// 1. Extracts the device's signing private key from session context
    /// 2. Creates a `SignedRatchetMessage` containing the original message and signature
    /// 3. Returns the signed message ready for transmission
    ///
    /// ## Security Considerations
    /// - Signing keys are stored encrypted in session context
    /// - Signatures use Curve25519 for strong cryptographic security
    /// - Message integrity is preserved through the signing process
    /// - Signing failures indicate serious cryptographic issues
    ///
    /// ## Usage Context
    /// Called during outbound message processing to ensure message authenticity
    /// before transmission through the transport layer.
    ///
    /// - Parameters:
    ///   - message: The `RatchetMessage` that needs to be signed. Contains the
    ///              encrypted message data and ratchet headers.
    ///   - session: The current `PQSSession` used to access the signing keys and
    ///              perform the signing operation.
    /// - Returns: A `SignedRatchetMessage` that contains the original ratchet message
    ///            along with its digital signature.
    /// - Throws: An error if the signing process fails due to issues such as missing signing keys,
    ///           session errors, or cryptographic errors.
    func signRatchetMessage(message: RatchetMessage, session: PQSSession) async throws -> SignedRatchetMessage {
        guard let deviceKeys = await session.sessionContext?.sessionUser.deviceKeys else {
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        return try SignedRatchetMessage(
            message: message,
            signingPrivateKey: deviceKeys.signingPrivateKey
        )
    }
}

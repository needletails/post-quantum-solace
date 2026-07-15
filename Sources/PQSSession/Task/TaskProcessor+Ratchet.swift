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
        if let match = await bestSessionIdentity(
            secretName: lookupProps.secretName,
            deviceId: lookupProps.deviceId,
            in: stored,
            symmetricKey: databaseSymmetricKey,
            preferredDevice: preferredDevice
        ) {
            return try await prepareStateLessPersonalSessionIdentityForOutbound(
                match,
                session: session,
                databaseSymmetricKey: databaseSymmetricKey)
        }
        _ = try await session.refreshIdentities(secretName: lookupProps.secretName, forceRefresh: true)
        let refreshed = try await cache.fetchSessionIdentities()
        if let match = await bestSessionIdentity(
            secretName: lookupProps.secretName,
            deviceId: lookupProps.deviceId,
            in: refreshed,
            symmetricKey: databaseSymmetricKey,
            preferredDevice: preferredDevice
        ) {
            return try await prepareStateLessPersonalSessionIdentityForOutbound(
                match,
                session: session,
                databaseSymmetricKey: databaseSymmetricKey)
        }
        throw PQSSession.SessionErrors.missingSessionIdentity
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

        logger.log(
            level: .info,
            message: "Refreshing state-less personal SessionIdentity for \(props.secretName) (\(props.deviceId)) before outbound establishment")

        return try await session.resetSessionIdentityForFreshSession(
            secretName: props.secretName,
            deviceId: props.deviceId,
            sendOneTimeIdentities: true)
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

    private func peerDeviceIdentityPreferenceKey(
        secretName: String,
        deviceId: UUID
    ) -> String {
        "\(secretName)|\(deviceId.uuidString)"
    }

    private func bestCandidatePreservingStoreOrder(
        _ candidates: [(identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, index: Int)]
    ) -> (identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, index: Int)? {
        candidates.max(by: { $0.index < $1.index })
    }

    private func currentDeviceConfiguration(
        secretName: String,
        deviceId: UUID,
        session: PQSSession
    ) async -> UserDeviceConfiguration? {
        guard let transportDelegate = await session.transportDelegate else { return nil }
        do {
            let configuration = try await transportDelegate.findConfiguration(for: secretName)
            let devices = try configuration.getVerifiedDevices().map {
                try configuration.deviceWithCurrentKeyBundle($0)
            }
            return devices.first(where: { $0.deviceId == deviceId })
        } catch {
            logger.log(
                level: .debug,
                message: "Unable to load current device bundle for \(secretName) (\(deviceId)): \(error)")
            return nil
        }
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
                case .requestMessageResend(let request):
                    logger.log(level: .info, message: "Prepared to request resend for sharedMessageId=\(request.failedSharedMessageId)")
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
            try await replaceRestoredSessionIdentityObject(
                sessionIdentity,
                data: outboundSessionIdentityDataBeforeAttempt,
                session: session,
                reason: "outbound ratchet failed before transport send")
            throw error
        }
        
        let transportMetadata = SignedRatchetMessageMetadata(
            secretName: props.secretName,
            deviceId: props.deviceId,
            recipient: outboundTask.message.recipient,
            transportMetadata: outboundTask.message.transportInfo,
            sharedMessageId: outboundTask.sharedId,
            transportEvent: transportEvent)
        let shouldRememberPendingTransport = shouldRememberPendingOutboundTransport(outboundTask.message)
        if shouldRememberPendingTransport {
            rememberPendingOutboundTransport(
                sharedId: outboundTask.sharedId,
                message: signedMessage,
                metadata: transportMetadata,
                needsRemoteDeletion: results.needsRemoteDeletion,
                curveOneTimeKeyId: results.localOneTimePrivateKey?.id.uuidString,
                mlKEMOneTimeKeyId: results.localMLKEMPrivateKey.id.uuidString)
        }
        try await session.transportDelegate?.sendMessage(signedMessage, metadata: transportMetadata)
        logRecoveryTransportSendSuccess(transportEvent, sharedId: outboundTask.sharedId)
        if shouldRememberPendingTransport {
            pendingOutboundTransportBySharedId.removeValue(forKey: outboundTask.sharedId)
        }
        await completeResponderPeerRefreshIfNeeded(
            transportEvent,
            peerSecretName: props.secretName,
            peerDeviceId: props.deviceId,
            session: session)

        await rememberRecentOutboundReplayIfNeeded(outboundTask, session: session)

        if outboundTask.isPersistedOutbound {
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
            message: "Completed responder peerRefresh on bootstrapped device lane peer=\(peerSecretName) deviceId=\(peerDeviceId)")
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
        
        let verificationResult = try await verifyEncryptedMessage(session: session, inboundTask: inboundTask)
        
        do {
            // Attempt decryption with the preferred active identity first. Legacy
            // persistence races may have left alternate active rows for the same
            // peer device, so try those before archived previous-state snapshots.
            let activeSessionIdentity = verificationResult.sessionIdentity
            let activeSessionIdentityDataBeforeAttempt = activeSessionIdentity.data
            var decryptedFromArchivedIdentity = false
            var decryptionSessionIdentity = activeSessionIdentity
            var decryptedData: Data
            do {
                try await initializeRecipient(
                    sessionIdentity: activeSessionIdentity,
                    session: session,
                    ratchetMessage: verificationResult.ratchetMessage)
                
                decryptedData = try await ratchetManager.ratchetDecrypt(
                    verificationResult.ratchetMessage,
                    sessionId: activeSessionIdentity.id)
            } catch {
                let activeError = error
                try await restoreSessionIdentityData(
                    activeSessionIdentity,
                    data: activeSessionIdentityDataBeforeAttempt,
                    session: session,
                    reason: "active inbound decrypt failed before archived fallback")
                let databaseSymmetricKey = try await session.getDatabaseSymmetricKey()
                let activeIdentities = try await session.getSessionIdentities(
                    with: inboundTask.senderSecretName)
                let alternateActiveIdentities = await activeIdentities.asyncFilter { identity in
                    guard identity.id != activeSessionIdentity.id,
                          let props = await identity.props(symmetricKey: databaseSymmetricKey)
                    else {
                        return false
                    }
                    return props.deviceId == inboundTask.senderDeviceId
                }
                let archivedIdentities = try await session.fetchArchivedSessionIdentities(
                    secretName: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)

                var fallbackData: Data?
                let fallbackIdentities = alternateActiveIdentities.map {
                    (identity: $0, isArchived: false)
                } + archivedIdentities.map {
                    (identity: $0, isArchived: true)
                }
                for candidate in fallbackIdentities {
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
                            message: "\(candidate.isArchived ? "Archived" : "Alternate active") identity fallback succeeded for \(inboundTask.senderSecretName) (\(inboundTask.senderDeviceId))")
                        decryptedFromArchivedIdentity = candidate.isArchived
                        decryptionSessionIdentity = fallbackIdentity
                        fallbackData = data
                        break
                    } catch {
                        try? await restoreSessionIdentityData(
                            fallbackIdentity,
                            data: fallbackDataBeforeAttempt,
                            session: session,
                            reason: "inbound identity fallback attempt failed")
                        continue
                    }
                }

                guard let data = fallbackData else {
                    try await replaceRestoredSessionIdentityObject(
                        activeSessionIdentity,
                        data: activeSessionIdentityDataBeforeAttempt,
                        session: session,
                        reason: "active and archived inbound decrypt attempts failed")
                    throw activeError
                }
                try await replaceRestoredSessionIdentityObject(
                    activeSessionIdentity,
                    data: activeSessionIdentityDataBeforeAttempt,
                    session: session,
                    reason: "archived inbound fallback succeeded after active decrypt failure")
                decryptedData = data
            }

            preferredSessionIdentityIdByPeerDevice[
                peerDeviceIdentityPreferenceKey(
                    secretName: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId)
            ] = decryptionSessionIdentity.id

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

                        guard let context = await session.sessionContext else { return }
                        if let targetDeviceId = envelope.targetDeviceId,
                           targetDeviceId != context.sessionUser.deviceId {
                            logger.log(
                                level: .info,
                                message: "Ignoring peerRefresh for another local device target=\(targetDeviceId) local=\(context.sessionUser.deviceId)")
                            return
                        }

                        if decryptedFromArchivedIdentity,
                           envelope.kind == .peerRefresh {
                            let promoted = try await session.promoteArchivedSessionIdentityToActive(
                                decryptionSessionIdentity)
                            decryptionSessionIdentity = promoted
                            decryptedFromArchivedIdentity = false
                            preferredSessionIdentityIdByPeerDevice[
                                peerDeviceIdentityPreferenceKey(
                                    secretName: inboundTask.senderSecretName,
                                    deviceId: inboundTask.senderDeviceId)
                            ] = promoted.id
                        }

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
                            return
                        case .skipStale:
                            logger.log(
                                level: .info,
                                message: "[control-event] dropping stale kind=\(envelope.kind.rawValue) sender=\(inboundTask.senderDeviceId) epoch=\(envelope.epoch)"
                            )
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
                                    return
                                }
                                // The request established a fresh exact-device lane before
                                // encryption and the transport bootstrap prepared the peer
                                // before decryption. Keep that proven lane; resetting again
                                // after the response would immediately diverge both devices.
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
                        guard let context = await session.sessionContext else { return }
                        guard try shouldAcceptLinkedDeviceReprovisioning(
                            bundle: bundle,
                            inboundTask: inboundTask,
                            decodedMessage: decodedMessage,
                            context: context
                        ) else {
                            logger.log(level: .warning, message: "Ignoring unauthorized linked-device reprovisioning bundle")
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
                    case .requestMessageResend(let request):
                        canSaveMessage = false

                        let symmetricKey = try await session.getDatabaseSymmetricKey()
                        let identities = try await session.cache?.fetchSessionIdentities() ?? []
                        logger.log(
                            level: .info,
                            message: "pqs.recovery.resendRequestReceived sender=\(inboundTask.senderSecretName) senderDeviceId=\(inboundTask.senderDeviceId) requestingDeviceId=\(request.requestingDeviceId) requestedCount=\(request.failedSharedMessageIds.count) ids=\(request.failedSharedMessageIds.joined(separator: ","))")
                        let requestedDevice = await currentDeviceConfiguration(
                            secretName: inboundTask.senderSecretName,
                            deviceId: request.requestingDeviceId,
                            session: session)
                        let senderDevice = await currentDeviceConfiguration(
                            secretName: inboundTask.senderSecretName,
                            deviceId: inboundTask.senderDeviceId,
                            session: session)
                        let requestedIdentity = await bestSessionIdentity(
                            secretName: inboundTask.senderSecretName,
                            deviceId: request.requestingDeviceId,
                            in: identities,
                            symmetricKey: symmetricKey,
                            preferredDevice: requestedDevice
                        )
                        let senderIdentity = await bestSessionIdentity(
                            secretName: inboundTask.senderSecretName,
                            deviceId: inboundTask.senderDeviceId,
                            in: identities,
                            symmetricKey: symmetricKey,
                            preferredDevice: senderDevice
                        )
                        guard let identity = requestedIdentity ?? senderIdentity else {
                            logger.log(
                                level: .warning,
                                message: "pqs.recovery.resendReplayFailed reason=missingIdentity sender=\(inboundTask.senderSecretName) senderDeviceId=\(inboundTask.senderDeviceId) requestingDeviceId=\(request.requestingDeviceId) requestedCount=\(request.failedSharedMessageIds.count)")
                            throw PQSSession.SessionErrors.missingSessionIdentity
                        }

                        var replayQueuedCount = 0
                        var replayMissingCount = 0
                        var replayCoalescedCount = 0
                        for failedSharedMessageId in request.failedSharedMessageIds {
                            let cryptoMessage: CryptoMessage
                            // Recent non-persistent recovery controls are intentionally replayable
                            // multiple times while a peer repairs; they are already bounded by
                            // `recentOutboundReplayMaxReplays`, so they bypass the servicing cooldown.
                            var servicedFromPersistedStore = false
                            if let replay = recentOutboundReplayMessage(sharedId: failedSharedMessageId) {
                                cryptoMessage = replay.message
                                logger.log(
                                    level: .info,
                                    message: "pqs.recovery.resendReplayUsingRecentControl sharedId=\(failedSharedMessageId) replayCount=\(replay.replayCount)")
                            } else {
                                // Persisted-message replays are otherwise unbounded: a peer stuck in a
                                // decrypt-failure loop could force us to re-ratchet and re-consume OTKs
                                // for the same message on every request. Coalesce repeats per requester.
                                guard await session.canServicePeerResendRequest(
                                    requestingDeviceId: request.requestingDeviceId,
                                    sharedId: failedSharedMessageId)
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
                                    logger.log(
                                        level: .info,
                                        message: "pqs.recovery.resendReplaySkipped reason=messageLookupFailed sharedId=\(failedSharedMessageId) error=\(error)")
                                    continue
                                }
                                guard let foundMessage else {
                                    replayMissingCount += 1
                                    logger.log(
                                        level: .info,
                                        message: "pqs.recovery.resendReplaySkipped reason=missingLocalMessage sharedId=\(failedSharedMessageId)")
                                    continue
                                }

                                guard let fetchedCryptoMessage = await foundMessage.props(symmetricKey: symmetricKey)?.message else {
                                    replayMissingCount += 1
                                    logger.log(
                                        level: .info,
                                        message: "pqs.recovery.resendReplaySkipped reason=unreadableLocalMessage sharedId=\(failedSharedMessageId)")
                                    continue
                                }
                                cryptoMessage = fetchedCryptoMessage
                                servicedFromPersistedStore = true
                            }

                            let task = EncryptableTask(
                                task: .writeMessage(OutboundTaskMessage(
                                    message: cryptoMessage,
                                    recipientIdentity: identity,
                                    localId: UUID(),
                                    sharedId: failedSharedMessageId,
                                    isPersistedOutbound: false
                                ))
                            )

                            try await feedTask(task, session: session)
                            if servicedFromPersistedStore {
                                await session.markPeerResendRequestServiced(
                                    requestingDeviceId: request.requestingDeviceId,
                                    sharedId: failedSharedMessageId)
                            }
                            replayQueuedCount += 1
                        }
                        if replayQueuedCount > 0 {
                            logger.log(
                                level: .info,
                                message: "pqs.recovery.resendReplayQueued sender=\(inboundTask.senderSecretName) senderDeviceId=\(inboundTask.senderDeviceId) queuedCount=\(replayQueuedCount) skippedCount=\(replayMissingCount) coalescedCount=\(replayCoalescedCount) requestedCount=\(request.failedSharedMessageIds.count)")
                        } else if replayCoalescedCount > 0 {
                            logger.log(
                                level: .info,
                                message: "pqs.recovery.resendReplayCoalescedAll sender=\(inboundTask.senderSecretName) senderDeviceId=\(inboundTask.senderDeviceId) coalescedCount=\(replayCoalescedCount) skippedCount=\(replayMissingCount) requestedCount=\(request.failedSharedMessageIds.count)")
                        } else {
                            logger.log(
                                level: .warning,
                                message: "pqs.recovery.resendReplayFailed reason=noReplayableMessages sender=\(inboundTask.senderSecretName) senderDeviceId=\(inboundTask.senderDeviceId) skippedCount=\(replayMissingCount) requestedCount=\(request.failedSharedMessageIds.count)")
                        }
                        
                    }
                } catch {
                    if let processedReestablishment {
                        await session.forgetReceivedSessionReestablishment(
                            envelope: processedReestablishment,
                            senderDeviceId: inboundTask.senderDeviceId)
                    }
                    logger.log(level: .error, message: "Error handling transport event from \(inboundTask.senderSecretName): \(error)")
                }
            }
            
            if canSaveMessage {
                /// Now we can handle the message
                try await handleDecodedMessage(
                    decodedMessage,
                    inboundTask: inboundTask,
                    session: session,
                    sessionIdentity: decryptionSessionIdentity)

                let recoveredFailureClasses = await session.takeInboundFailureClasses(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    messageId: inboundTask.sharedMessageId)
                if !recoveredFailureClasses.isEmpty {
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.messageDecrypted sharedId=\(inboundTask.sharedMessageId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) priorFailureClasses=\(recoveredFailureClasses.joined(separator: ","))")
                }

                let pending = await session.takePendingResendsAfterReestablishment(
                    sender: inboundTask.senderSecretName,
                    deviceId: inboundTask.senderDeviceId,
                    satisfiedSharedMessageId: inboundTask.sharedMessageId)
                if decryptedFromArchivedIdentity {
                    logger.log(
                        level: .debug,
                        message: "Keeping deferred resend requests pending after archived fallback for \(inboundTask.senderSecretName) (\(inboundTask.senderDeviceId))")
                    for pendingRequest in pending {
                        await session.deferPeerResendUntilReestablished(
                            sender: pendingRequest.senderName,
                            deviceId: pendingRequest.senderDeviceId,
                            failedMessageId: pendingRequest.failedSharedMessageId,
                            failureClass: pendingRequest.failureClass)
                    }
                } else {
                    // Active-session decrypt proves the peer device session is usable;
                    // close the single-flight episode before draining deferred resends.
                    await session.endReestablishmentEpisode(
                        sender: inboundTask.senderSecretName,
                        deviceId: inboundTask.senderDeviceId)
                    await sendDeferredResendRequests(
                        pending,
                        session: session,
                        reason: "successful inbound message")
                }
            }
            
        } catch {
#if DEBUG
            logger.log(
                level: .debug,
                message: "pqs.recovery.decryptAttemptFailed sharedId=\(inboundTask.sharedMessageId) sender=\(inboundTask.senderSecretName) deviceId=\(inboundTask.senderDeviceId) action=handOffToRecoveryPolicy error=\(error)")
#endif
            throw error
        }
    }

    private func restoreSessionIdentityData(
        _ identity: SessionIdentity,
        data: Data,
        session: PQSSession,
        reason: String
    ) async throws {
        identity.data = data
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
        case .requestMessageResend(let request):
            logger.log(
                level: .info,
                message: "pqs.recovery.resendRequestSent sharedId=\(sharedId) requestingDeviceId=\(request.requestingDeviceId) requestedCount=\(request.failedSharedMessageIds.count) ids=\(request.failedSharedMessageIds.joined(separator: ","))")
        case .linkedDeviceReprovisioning(let bundle):
            logger.log(
                level: .info,
                message: "pqs.recovery.linkedDeviceReprovisioningSent sharedId=\(sharedId) targetDeviceId=\(bundle.targetDeviceId)")
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
        case .requestMessageResend,
             .sessionReestablishment,
             .linkedDeviceReprovisioning,
             .synchronizeOneTimeKeys,
             .refreshOneTimeKeys,
             .publishedOneTimeKeysReplenished:
            return true
        }
    }

    private func rememberPendingOutboundTransport(
        sharedId: String,
        message: SignedRatchetMessage,
        metadata: SignedRatchetMessageMetadata,
        needsRemoteDeletion: Bool,
        curveOneTimeKeyId: String?,
        mlKEMOneTimeKeyId: String,
        now: Date = Date()
    ) {
        cleanupPendingOutboundTransport(now: now)
        pendingOutboundTransportBySharedId[sharedId] = PendingOutboundTransport(
            message: message,
            metadata: metadata,
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
        pendingOutboundTransportBySharedId.removeValue(forKey: outboundTask.sharedId)
        await completeResponderPeerRefreshIfNeeded(
            pendingTransport.metadata.transportEvent,
            peerSecretName: pendingTransport.metadata.secretName,
            peerDeviceId: pendingTransport.metadata.deviceId,
            session: session)

        await rememberRecentOutboundReplayIfNeeded(outboundTask, session: session)

        if outboundTask.isPersistedOutbound {
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
        cleanupRecentOutboundReplay(now: now)
        guard !outboundTask.isPersistedOutbound else { return }
        guard await isReplayableNonPersistentControl(outboundTask.message, session: session) else { return }
        guard recentOutboundReplayBySharedId[outboundTask.sharedId] == nil else { return }

        recentOutboundReplayBySharedId[outboundTask.sharedId] = RecentOutboundReplay(
            message: outboundTask.message,
            createdAt: now,
            replayCount: 0)

        guard recentOutboundReplayBySharedId.count > recentOutboundReplayLimit else { return }
        let overflow = recentOutboundReplayBySharedId.count - recentOutboundReplayLimit
        let oldestKeys = recentOutboundReplayBySharedId
            .sorted { $0.value.createdAt < $1.value.createdAt }
            .prefix(overflow)
            .map(\.key)
        for key in oldestKeys {
            recentOutboundReplayBySharedId.removeValue(forKey: key)
        }
    }

    private func recentOutboundReplayMessage(
        sharedId: String,
        now: Date = Date()
    ) -> (message: CryptoMessage, replayCount: Int)? {
        cleanupRecentOutboundReplay(now: now)
        guard var replay = recentOutboundReplayBySharedId[sharedId] else {
            return nil
        }
        guard replay.replayCount < recentOutboundReplayMaxReplays else {
            recentOutboundReplayBySharedId.removeValue(forKey: sharedId)
            return nil
        }
        replay.replayCount += 1
        recentOutboundReplayBySharedId[sharedId] = replay
        return (replay.message, replay.replayCount)
    }

    private func cleanupRecentOutboundReplay(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-recentOutboundReplayTTL)
        recentOutboundReplayBySharedId = recentOutboundReplayBySharedId.filter { _, replay in
            replay.createdAt > cutoff
        }
    }

    /// Friendship packets must never be replayed from the recovery ring; peers
    /// converge via fresh `friendshipStateRequest` or sibling `synchronizeContacts`.
    private func isFriendshipStateControlMessage(_ message: CryptoMessage) -> Bool {
        (try? BinaryDecoder().decode(FriendshipMetadata.self, from: message.metadata)) != nil
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

        let symmetricKey = try await session.getDatabaseSymmetricKey()
        var replayableMessages: [(sharedId: String, message: CryptoMessage, servicedFromPersistedStore: Bool)] = []
        var missingCount = 0
        var coalescedCount = 0
        var permanentlyUnavailableIds: [String] = []

        for sharedId in requestedIds {
            // Recent non-persistent recovery controls are already bounded by
            // `recentOutboundReplayMaxReplays`; let them replay while a peer repairs.
            if let replay = recentOutboundReplayMessage(sharedId: sharedId) {
                if isFriendshipStateControlMessage(replay.message) {
                    permanentlyUnavailableIds.append(sharedId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.outOfBandResendSkipped reason=staleFriendshipControl sharedId=\(sharedId)")
                    continue
                }
                replayableMessages.append((sharedId, replay.message, false))
                logger.log(
                    level: .info,
                    message: "pqs.recovery.outOfBandResendUsingRecentControl sharedId=\(sharedId) replayCount=\(replay.replayCount)")
                continue
            }

            // Persisted-message replays are otherwise unbounded; coalesce repeated
            // requests for the same message from the same requester.
            guard await session.canServicePeerResendRequest(
                requestingDeviceId: senderDeviceId,
                sharedId: sharedId)
            else {
                coalescedCount += 1
                logger.log(
                    level: .info,
                    message: "pqs.recovery.outOfBandResendCoalesced reason=servicingCooldown sharedId=\(sharedId) requestingDeviceId=\(senderDeviceId)")
                continue
            }

            do {
                guard let foundMessage = try await session.cache?.fetchMessageIfExists(sharedId: sharedId) else {
                    missingCount += 1
                    permanentlyUnavailableIds.append(sharedId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.outOfBandResendSkipped reason=missingLocalMessage sharedId=\(sharedId)")
                    continue
                }
                guard let cryptoMessage = await foundMessage.props(symmetricKey: symmetricKey)?.message else {
                    missingCount += 1
                    permanentlyUnavailableIds.append(sharedId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.outOfBandResendSkipped reason=unreadableLocalMessage sharedId=\(sharedId)")
                    continue
                }
                if isFriendshipStateControlMessage(cryptoMessage) {
                    permanentlyUnavailableIds.append(sharedId)
                    logger.log(
                        level: .info,
                        message: "pqs.recovery.outOfBandResendSkipped reason=staleFriendshipControl sharedId=\(sharedId)")
                    continue
                }
                replayableMessages.append((sharedId, cryptoMessage, true))
            } catch {
                missingCount += 1
                permanentlyUnavailableIds.append(sharedId)
                logger.log(
                    level: .info,
                    message: "pqs.recovery.outOfBandResendSkipped reason=messageLookupFailed sharedId=\(sharedId) error=\(error)")
            }
        }

        guard !replayableMessages.isEmpty else {
            logger.log(
                level: .info,
                message: "pqs.recovery.outOfBandResendUnavailable sender=\(senderName) deviceId=\(senderDeviceId) requestedCount=\(requestedIds.count) missingCount=\(missingCount) coalescedCount=\(coalescedCount)")
            return PQSSession.OutOfBandResendResult(
                queuedIds: [],
                permanentlyUnavailableIds: permanentlyUnavailableIds)
        }

        let onlyRecentControls = replayableMessages.allSatisfy { !$0.servicedFromPersistedStore }
        // A persisted replay request arrives only after peerRefresh request/response
        // transport has completed and both exact-device lanes have reset. Resetting
        // again here would put the responder one epoch ahead of the requester.
        let identity = try await session.activeSessionIdentityForPeer(
            secretName: senderName,
            deviceId: senderDeviceId)
        logger.log(
            level: .info,
            message: "pqs.recovery.outOfBandResendReusingCoordinatedIdentity sender=\(senderName) deviceId=\(senderDeviceId) controlsOnly=\(onlyRecentControls) replayCount=\(replayableMessages.count)")

        var queuedIds: [String] = []
        for replayable in replayableMessages {
            let task = EncryptableTask(
                task: .writeMessage(OutboundTaskMessage(
                    message: replayable.message,
                    recipientIdentity: identity,
                    localId: UUID(),
                    sharedId: replayable.sharedId,
                    isPersistedOutbound: false
                )),
                priority: .urgent
            )
            try await feedTask(task, session: session)
            if replayable.servicedFromPersistedStore {
                await session.markPeerResendRequestServiced(
                    requestingDeviceId: senderDeviceId,
                    sharedId: replayable.sharedId)
            }
            queuedIds.append(replayable.sharedId)
        }

        logger.log(
            level: .info,
            message: "pqs.recovery.outOfBandResendQueued sender=\(senderName) deviceId=\(senderDeviceId) queuedCount=\(queuedIds.count) missingCount=\(missingCount) coalescedCount=\(coalescedCount) requestedCount=\(requestedIds.count)")
        return PQSSession.OutOfBandResendResult(
            queuedIds: queuedIds,
            permanentlyUnavailableIds: permanentlyUnavailableIds)
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
        case .synchronizeOneTimeKeys, .refreshOneTimeKeys, .publishedOneTimeKeysReplenished, .requestMessageResend:
            return false
        }
    }

    private func replaceRestoredSessionIdentityObject(
        _ identity: SessionIdentity,
        data: Data,
        session: PQSSession,
        reason: String
    ) async throws {
        guard let cache = await session.cache else { return }

        let symmetricKey = try await session.getDatabaseSymmetricKey()
        guard let props = await identity.props(symmetricKey: symmetricKey) else { return }
        guard !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { return }

        let replacement = SessionIdentity(id: UUID(), data: data)
        try await cache.createSessionIdentity(replacement)

        do {
            try await cache.deleteSessionIdentity(identity.id)
            await session.removeIdentity(with: props.secretName)
            logger.log(
                level: .info,
                message: "Replaced restored active SessionIdentity for \(props.secretName) (\(props.deviceId)) after \(reason)")
        } catch {
            try? await cache.deleteSessionIdentity(replacement.id)
            throw error
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
    private func markPersistedOutboundPastSendingIfNeeded(session: PQSSession, localMessageId: UUID) async {
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

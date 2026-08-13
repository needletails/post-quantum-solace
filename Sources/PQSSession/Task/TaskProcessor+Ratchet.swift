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
import NeedleTailLogger

/// Extension of `MessagePipeline` conforming to `SessionIdentityDelegate`.
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
extension MessagePipeline: SessionIdentityDelegate, TaskSequenceDelegate {
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
    func updateSessionIdentity(_ identity: DoubleRatchetKit.SessionIdentity) async throws {
        guard let session else {
            throw PQSError.sessionNotInitialized
        }
        // Outbound encryption mutates the in-memory identity first. Persistence is
        // intentionally deferred until the exact signed frame is ready, so the
        // identity and prepared JobModel can be committed atomically.
        if atomicOutboundPreparationIdentityIds.contains(identity.id) {
            return
        }
        guard let cache = await session.cache else {
            throw PQSError.databaseNotInitialized
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
    /// - Throws: `PQSError.sessionNotInitialized` if the session is not initialized.
    func fetchOneTimePrivateKey(_ id: UUID?) async throws -> DoubleRatchetKit.X25519PrivateKey? {
        guard let sessionContext = await session?.sessionContext else {
            throw PQSError.sessionNotInitialized
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
    func updateOneTimeKey(remove id: UUID) async {
        // If we do not detach then the ratchet encrypt takes too long due to the network
        updateKeyTasks.append(Task(executorPreference: keyTransportExecutor) { [weak self] in
            guard let self else { return }
            do {
                guard let session = await session else {
                    throw PQSError.sessionNotInitialized
                }
                guard var sessionContext = await session.sessionContext else {
                    throw PQSError.sessionNotInitialized
                }
                
                let newID = UUID()
                let keypair = crypto.generateCurve25519PrivateKey()
                let privateKeyRep = try X25519PrivateKey(id: newID, keypair.rawRepresentation)
                let publicKey = try X25519PublicKey(id: newID, keypair.publicKey.rawRepresentation)
                
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
                    throw PQSError.sessionEncryptionError
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
        // Strict OTK enforcement stays OFF in 4.0: PQS recovery replays the first
        // encrypted outbound frame (transport failure / lane repair), which requires
        // the initial one-time key to remain resolvable until the reverse handshake
        // confirms. Enforcement consumes the OTK on first decrypt and fails fast on
        // replays, stalling rotation/repair flows.
        //
        // Deferred consumption is designed (not yet implemented) in
        // Documentation.docc/DeferredOTKConsumption.md: consume on the
        // reverse-handshake-confirmed event (first inbound header-chain frame),
        // via the existing SessionIdentityDelegate.updateOneTimeKey(remove:) hook.
        // Enabling it later is additive — this flag is runtime and the delegate
        // surface already exists — so it is scheduled for a 4.1 minor, not this break.
        //
        // Until then the private OTK is retained longer than the Double Ratchet
        // specification's ideal, which slightly extends the window in which a later
        // device compromise could decrypt a recorded initial handshake frame. Wire
        // confidentiality is unaffected and server-side single-use of published
        // OTKs still holds.
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
        var localOneTimePrivateKey: X25519PrivateKey?
        var localMLKEMPrivateKey: MLKEMPrivateKey
        var remoteLongTermPublicKey: Data
        var remoteOneTimePublicKey: X25519PublicKey?
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
        
        var localOneTimePrivateKey: X25519PrivateKey?
        var localMLKEMPrivateKey: MLKEMPrivateKey
        var remoteLongTermPublicKey: Data
        var remoteOneTimePublicKey: X25519PublicKey?
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
            if props.hasRatchetState {
                localOneTimePrivateKey = props.ratchetOneTimePrivateKey
                localMLKEMPrivateKey = props.ratchetMLKEMPrivateKey
                    ?? effectiveSessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
            } else {
                localOneTimePrivateKey = effectiveSessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.last
                localMLKEMPrivateKey = effectiveSessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.last
                ?? effectiveSessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
            }
        case .complete:
            if props.hasRatchetState {
                localOneTimePrivateKey = props.ratchetOneTimePrivateKey
                localMLKEMPrivateKey = props.ratchetMLKEMPrivateKey
                    ?? effectiveSessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
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
                guard props.hasRatchetState else {
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
                localOneTimePrivateKey = props.ratchetOneTimePrivateKey
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
    
}

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
    
    /// Handles a strict-enforcement consumption request for a one-time key.
    ///
    /// Called by DoubleRatchetKit when an inbound PQXDH bootstrap frame decrypts
    /// under `enforceOTKConsistency`. The published key is spent — prune its
    /// signed public entry and publish a freshly minted replacement so the
    /// server pool stays topped up. The local *private* half is deliberately
    /// retained (deferred consumption): recovery legitimately replays the
    /// initiator's first encrypted frame, and the decrypt preflight re-hydrates
    /// the ratchet state from the pool via `fetchOneTimePrivateKey(_:)`. The
    /// private key is deleted only when the reverse handshake confirms — see
    /// `noteAcceptedInboundForDeferredOneTimeKeyConsumption` in
    /// `TaskProcessor+RatchetInbound.swift`.
    ///
    /// ## Idempotency
    /// Bootstrap replays repeat this call for the same id. Only the first call
    /// still finds the id in the signed public list; later calls return without
    /// minting again.
    ///
    /// ## Performance Considerations
    /// - Key generation is performed asynchronously to avoid blocking
    /// - Network operations are detached to prevent delays
    /// - Failed operations are logged but don't block the session
    ///
    /// - Parameter id: The UUID of the spent one-time key.
    func updateOneTimeKey(remove id: UUID) async {
        // If we do not detach then the ratchet encrypt takes too long due to the network
        let taskId = UUID()
        updateKeyTasks[taskId] = Task(executorPreference: keyTransportExecutor) { [weak self] in
            guard let self else { return }
            do {
                guard let session = await session else {
                    throw PQSError.sessionNotInitialized
                }
                guard let sessionContext = await session.sessionContext else {
                    throw PQSError.sessionNotInitialized
                }
                
                // Replay idempotency: only the first consumption request for this
                // id still finds its signed public entry. A reply citing an
                // initiator's handshake ephemeral never finds one: nothing was published.
                guard sessionContext.activeUserConfiguration.signedOneTimePublicKeys.contains(where: { $0.id == id }) else {
                    await retireUpdateKeyTask(taskId)
                    return
                }
                
                let newID = UUID()
                let keypair = crypto.generateCurve25519PrivateKey()
                let privateKeyRep = try X25519PrivateKey(id: newID, keypair.rawRepresentation)
                let publicKey = try X25519PublicKey(id: newID, keypair.publicKey.rawRepresentation)
                
                let sessionUser = sessionContext.sessionUser
                let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: sessionUser.deviceKeys.signingPrivateKey)
                let newSignedKey = try UserConfiguration.SignedOneTimePublicKey(key: publicKey, deviceId: sessionUser.deviceId, signingKey: signingKey)
                
                // Store the replacement's private half first, so the server can only serve
                // a key this device can open. A failed upload leaves one unused private, and
                // the spent public entry stays, so a replay mints again.
                //
                // Both commits apply this task's delta to the *current* context, not the
                // snapshot taken above: a sibling replacement may commit in the meantime,
                // and writing the snapshot back would resurrect its spent public key and
                // drop its new private key (the peer could then pick an OTK we cannot
                // decrypt).
                //
                // Mutation and persistence run as one exclusive commit: persisting
                // re-installs the stored blob as the live context, so an overlapping
                // sibling commit would otherwise roll this delta back.
                guard try await session.commitLiveSessionContextMutation({ context in
                    var deviceKeys = context.sessionUser.deviceKeys
                    // Deferred consumption: retain the spent private key until the
                    // reverse handshake confirms; only append the replacement here.
                    deviceKeys.oneTimePrivateKeys.append(privateKeyRep)
                    var user = context.sessionUser
                    user.deviceKeys = deviceKeys
                    context.updateSessionUser(user)
                }) != nil else {
                    throw PQSError.sessionNotInitialized
                }
                
                try await session.transportDelegate?.updateOneTimeKeys(
                    for: sessionUser.secretName,
                    deviceId: sessionUser.deviceId.uuidString,
                    keys: [newSignedKey]
                )
                
                // The server accepted the replacement.
                guard try await session.commitLiveSessionContextMutation({ context in
                    context.activeUserConfiguration.signedOneTimePublicKeys.removeAll { $0.id == id }
                    context.activeUserConfiguration.signedOneTimePublicKeys.append(newSignedKey)
                }) != nil else {
                    throw PQSError.sessionNotInitialized
                }
                await retireUpdateKeyTask(taskId)
            } catch is CancellationError {
                // Only session shutdown cancels these tasks now; nothing to report.
                await retireUpdateKeyTask(taskId)
            } catch {
                await retireUpdateKeyTask(taskId)
                await logger.log(level: .error, message: "Failed to update one time key: \(error)")
            }
        }
    }

    /// Drops this task's own bookkeeping entry. Never cancels a sibling.
    private func retireUpdateKeyTask(_ taskId: UUID) async {
        updateKeyTasks.removeValue(forKey: taskId)
    }

    /// Cancels all in-flight key transport offload tasks (session shutdown).
    func cancelBackgroundKeyTasks() async {
        let updates = Array(updateKeyTasks.values)
        updateKeyTasks.removeAll()
        for task in updates {
            task.cancel()
        }
        for task in updates {
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
        // Strict OTK enforcement is ON as of 4.1.0, paired with PQS-side deferred
        // consumption (Documentation.docc/DeferredOTKConsumption.md):
        //
        // - DRK consumes on every authenticated decrypt whose header cites an
        //   oneTimeKeyId: it fires updateOneTimeKey(remove:) and clears the state
        //   copy of the OTK.
        // - PQS's delegate treats that as a consumption *request*: it replaces the
        //   published public key but retains the private half in the device-key
        //   pool. The state copy is restored right after commit
        //   (restoreDeferredOneTimeKeyIntoRatchetState) because DRK 4.0.0 lanes
        //   embed and re-use the OTK in every epoch re-key — letting it go nil
        //   desyncs the peer's chains.
        // - The private half is deleted when a committed inbound frame proves the
        //   lane can no longer cite it: the lane re-keyed onto a different OTK id,
        //   or (future DRK) frames stop citing entirely. Tracked in
        //   DeviceKeys.pendingOneTimeKeyConsumptions. After deletion, a bootstrap
        //   replay fails fast in the decrypt preflight.
        await ratchetManager.setEnforceOTKConsistency(true)
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
    }
    
    /// A fresh X3DH ephemeral for one lane's handshake. It lives only in that lane's
    /// ratchet state: never in `DeviceKeys`, never published, so the server cannot
    /// serve it and a reply citing it spends no published key.
    private func mintHandshakeEphemeral() throws -> X25519PrivateKey {
        try X25519PrivateKey(id: UUID(), crypto.generateCurve25519PrivateKey().rawRepresentation)
    }
    
    func loadKeys(
        props: SessionIdentity.UnwrappedProps,
        sessionContext: SessionContext,
        session: PQSSession,
        sessionIdentityId: UUID
    ) async throws -> LoadedKeysResult {
        /// Loads the key material for one outbound encrypt on one lane.
        /// - No ratchet state: a handshake from a minted ephemeral and the final ML-KEM
        ///   key, never a published key.
        /// - Ratchet state: the keys in the lane's own snapshot.
        /// - Routine ML-KEM rotation due: the published bundle and the pool move on;
        ///   an established lane keeps its snapshot keys.
        
        var localOneTimePrivateKey: X25519PrivateKey?
        var localMLKEMPrivateKey: MLKEMPrivateKey
        var remoteLongTermPublicKey: Data
        var remoteOneTimePublicKey: X25519PublicKey?
        var remoteMLKEMPublicKey: MLKEMPublicKey
        
        // Local keys are recipient-scoped: an established lane keeps the keys in its
        // ratchet snapshot, a lane without state starts a handshake. The curve slot is
        // X3DH's ephemeral and the ML-KEM slot the signed-prekey role. A pool key here
        // is shared by every lane this device starts, and a peer's reply spends it
        // while the server still serves it, so the next peer it reaches gets
        // `missingOneTimeKey` (dogfood 2026-10-28: A4FEDB36 cited on two devices' lanes).
        // `keyLoadingState` is session-scoped (the process's first send, a rotation)
        // and says nothing about this lane. Handing an established lane fresh
        // keys reads to the ratchet as a local key change and fires an epoch
        // re-key the peer only mirrors in order: every frame they sent before
        // seeing it fails on this lane (the responder's first reply, or the first
        // send after a relaunch, with the peer's traffic crossing it).
        if props.hasRatchetState {
            localOneTimePrivateKey = props.ratchetOneTimePrivateKey
            localMLKEMPrivateKey = props.ratchetMLKEMPrivateKey
                ?? sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
        } else {
            localOneTimePrivateKey = try mintHandshakeEphemeral()
            localMLKEMPrivateKey = sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
        }
        
        remoteLongTermPublicKey = props.longTermPublicKey
        remoteOneTimePublicKey = props.oneTimePublicKey
        remoteMLKEMPublicKey = props.mlKEMPublicKey

        // Routine ML-KEM rotation is Signal's signed-prekey rotation: it moves the
        // published bundle and the pool for lanes that have not started yet and
        // never touches an established lane. Re-keying an established lane here
        // was a spontaneous epoch the peer could only mirror in order; frames
        // already in flight, or a peer rotating at the same moment, diverged the
        // chains. A device-key rotation in flight (`.rotating`) owns the context
        // and re-keys lanes through reestablishment, so routine rotation waits.
        if await session.keyLoadingState == .complete,
           try await session.rotateMLKEMKeysIfNeeded(),
           !props.hasRatchetState,
           let refreshedContext = await session.sessionContext {
            localMLKEMPrivateKey = refreshedContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
        }
        
        // Strict encrypt throws if a sending handshake still wants a remote OTK
        // but the state copy of our local OTK is gone (cleared on inbound
        // consume, or a reminted lane that kept peer OTK props). Mint one
        // only while the sending handshake is unfinished — doing so after the
        // handshake would look like a sending-key change and trigger a DH ratchet.
        if localOneTimePrivateKey == nil,
           let status = try? await ratchetManager.sessionStatus(sessionId: sessionIdentityId),
           !status.sendingHandshakeFinished {
            localOneTimePrivateKey = try mintHandshakeEphemeral()
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
            remoteMLKEMPublicKey: remoteMLKEMPublicKey)
    }
    
}

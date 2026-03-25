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
        try await session?.cache?.updateSessionIdentity(identity)
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
                
                // Update the user configuration with the new signed keys
                sessionContext.activeUserConfiguration.signedOneTimePublicKeys = signedKeys
                await session.setSessionContext(sessionContext)
                
                // Encrypt and persist
                let encodedData = try BinaryEncoder().encode(sessionContext)
                guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: session.getAppSymmetricKey()) else {
                    throw PQSSession.SessionErrors.sessionEncryptionError
                }
                
                try await session.cache?.updateLocalSessionContext(encryptedConfig)
                
                try await session.transportDelegate?.updateOneTimeKeys(
                    for: sessionContext.sessionUser.secretName,
                    deviceId: sessionContext.sessionUser.deviceId.uuidString,
                    keys: [newSignedKey]
                )
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

        switch await session.keyLoadingState {
        case .initial:
            if let privateOneTimeKey = sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.last {
                localOneTimePrivateKey = privateOneTimeKey
            }
            
            if let mlKEMOneTimePrivateKey = sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.last {
                localMLKEMPrivateKey = mlKEMOneTimePrivateKey
            } else {
                localMLKEMPrivateKey = sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
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
                localOneTimePrivateKey = sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.last
                localMLKEMPrivateKey = sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.last
                    ?? sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
            }
        case .complete:
            if let state = props.state {
                localOneTimePrivateKey = state.localOneTimePrivateKey
                localMLKEMPrivateKey = state.localMLKEMPrivateKey
            } else {
                localOneTimePrivateKey = sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.last
                localMLKEMPrivateKey = sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.last
                    ?? sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
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
                if let privateMLKEMOneTimeKey = sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.last {
                    localMLKEMPrivateKey = privateMLKEMOneTimeKey
                } else {
                    localMLKEMPrivateKey = sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
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
        guard var sessionIdentity = try await session.cache?.fetchSessionIdentities().first(where: { $0.id == outboundTask.recipientIdentity.id }) else {
            throw PQSSession.SessionErrors.missingSessionIdentity
        }

        if await session.keyLoadingState == .rotating {
            if let secretName = await sessionIdentity.props(symmetricKey: databaseSymmetricKey)?.secretName {
                let refreshedIdentities = try await session.refreshIdentities(secretName: secretName, forceRefresh: true)
                if let refreshed = refreshedIdentities.first(where: { $0.id == outboundTask.recipientIdentity.id }) {
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
                case .sessionReestablishment:
                    logger.log(level: .info, message: "Prepared to send session reestablishment")
                case .synchronizeOneTimeKeys(var info):
                    info.senderCurveId = results.localOneTimePrivateKey?.id.uuidString
                    info.senderMLKEMId = results.localMLKEMPrivateKey.id.uuidString
                    let encodedData = try BinaryEncoder().encode(info)
                    await session.setAddingContact(encodedData)
                    outboundTask.message.transportInfo = encodedData
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
        let signedMessage = try await signRatchetMessage(message: ratchetedMessage, session: session)
        
        try await session.transportDelegate?.sendMessage(signedMessage, metadata: SignedRatchetMessageMetadata(
            secretName: props.secretName,
            deviceId: props.deviceId,
            recipient: outboundTask.message.recipient,
            transportMetadata: outboundTask.message.transportInfo,
            sharedMessageId: outboundTask.sharedId,
            transportEvent: transportEvent))

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
            try await initializeRecipient(
                sessionIdentity: verificationResult.sessionIdentity,
                session: session,
                ratchetMessage: verificationResult.ratchetMessage)
            
            let decryptedData = try await ratchetManager.ratchetDecrypt(
                verificationResult.ratchetMessage,
                sessionId: verificationResult.sessionIdentity.id)
            
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
            
            if let transportInfo = decodedMessage.transportInfo {
                do {
                    let event = try BinaryDecoder().decode(TransportEvent.self, from: transportInfo)
                    switch event {
                    case .sessionReestablishment:
                        canSaveMessage = false
                        try await session.createInactiveSessionSnapshot(for: inboundTask.senderSecretName, policy: .archive)
                        _ = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
                        logger.log(level: .info, message: "Received Session Reestablishment, refreshed session identities")
                    case .synchronizeOneTimeKeys(let info):
                        try await removeKeys(
                            session: session,
                            curveId: info.recipientCurveId,
                            mlKEMId: info.recipientMLKEMId)
                        canSaveMessage = false
                    }
                } catch {}
            }
            
            if canSaveMessage {
                /// Now we can handle the message
                try await handleDecodedMessage(
                    decodedMessage,
                    inboundTask: inboundTask,
                    session: session,
                    sessionIdentity: verificationResult.sessionIdentity)
            }
            
        } catch let ratchetError as RatchetError where ratchetError == .stateUninitialized {
            try await attemptInactiveSessionRecovery(
                session: session,
                inboundTask: inboundTask,
                verificationResult: verificationResult)
        } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
            try await attemptInactiveSessionRecovery(
                session: session,
                inboundTask: inboundTask,
                verificationResult: verificationResult)
        } catch {
#if DEBUG
            logger.log(level: .error, message: "RatchetError during ratchet decryption: \(error)")
#endif
            throw error
        }
        
        func attemptInactiveSessionRecovery(
            session: PQSSession,
            inboundTask: InboundTaskMessage,
            verificationResult: VerificationResult
        ) async throws {
            do {
                // Attempt Sesame-style recovery using bounded inactive snapshots.
                if let recovered = try await performInactiveSessionRecovery(
                    session: session,
                    inboundTask: inboundTask,
                    verificationResult: verificationResult
                ) {
                    let decodedMessage = try BinaryDecoder().decode(CryptoMessage.self, from: recovered)
                    var canSaveMessage = true
                    if let sessionDelegate = await session.sessionDelegate {
                        canSaveMessage = await sessionDelegate.processMessage(
                            decodedMessage,
                            senderSecretName: inboundTask.senderSecretName,
                            senderDeviceId: inboundTask.senderDeviceId)
                    }
                    if canSaveMessage {
                        try await handleDecodedMessage(
                            decodedMessage,
                            inboundTask: inboundTask,
                            session: session,
                            sessionIdentity: verificationResult.sessionIdentity)
                    }
                } else {
                    // Recovery failed: archive current state (best-effort) and clear active ratchet state
                    // for this sender device, so subsequent resend can reinitialize from fresh keys.
                    do {
                        try await session.createInactiveSessionSnapshot(
                            for: inboundTask.senderSecretName,
                            policy: .archive)
                        try await clearActiveRatchetState(
                            session: session,
                            senderSecretName: inboundTask.senderSecretName,
                            senderDeviceId: inboundTask.senderDeviceId)
                    } catch {
#if DEBUG
                        logger.log(level: .warning, message: "Failed to archive/clear active ratchet state after maxSkipped: \(error)")
#endif
                    }
                    throw RatchetError.maxSkippedHeadersExceeded
                }
            } catch {
#if DEBUG
                logger.log(level: .error, message: "RatchetError during ratchet decryption: \(error)")
#endif
                throw error
            }
        }
    }

    /// Clears the active (non-inactive-snapshot) ratchet state for a specific sender device.
    /// This forces the next inbound decrypt to reinitialize using current identity keys.
    private func clearActiveRatchetState(
        session: PQSSession,
        senderSecretName: String,
        senderDeviceId: UUID
    ) async throws {
        guard let cache = await session.cache else { return }
        let symmetricKey = try await session.getDatabaseSymmetricKey()

        for identity in try await cache.fetchSessionIdentities() {
            guard var props = await identity.props(symmetricKey: symmetricKey) else { continue }
            guard props.secretName == senderSecretName, props.deviceId == senderDeviceId else { continue }
            // Never mutate inactive snapshots here.
            if props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) { continue }

            if props.state != nil {
                props.state = nil
                try await identity.updateIdentityProps(symmetricKey: symmetricKey, props: props)
                try await cache.updateSessionIdentity(identity)
            }
            return
        }
    }

    /// Attempts to recover from `stateUninitialized` by temporarily restoring ratchet state from
    /// bounded inactive snapshot identities for this sender device.
    ///
    /// This is intentionally best-effort and does not change public APIs or DB schemas.
    private func performInactiveSessionRecovery(
        session: PQSSession,
        inboundTask: InboundTaskMessage,
        verificationResult: VerificationResult
    ) async throws -> Data? {
        guard let cache = await session.cache else { return nil }
        let symmetricKey = try await session.getDatabaseSymmetricKey()

        // Find the "active" identity (non-inactive) for this device. If none exists, we cannot promote.
        let all = try await cache.fetchSessionIdentities()
        let candidates = await all.asyncFilter { identity in
            guard let props = await identity.props(symmetricKey: symmetricKey) else { return false }
            return props.secretName == inboundTask.senderSecretName && props.deviceId == inboundTask.senderDeviceId
        }

        guard let activeIdentity = await candidates.asyncFirst(where: { identity in
            guard let props = await identity.props(symmetricKey: symmetricKey) else { return false }
            return !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
        }) else {
            return nil
        }

        guard var activeProps = await activeIdentity.props(symmetricKey: symmetricKey) else { return nil }
        let originalState = activeProps.state

        // Collect inactive snapshot identities (newest-first by sessionContextId, which we set to epoch seconds).
        var inactive: [(identity: SessionIdentity, ts: Int)] = []
        for identity in candidates {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            guard props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix) else { continue }
            guard props.state != nil else { continue }
            inactive.append((identity, props.sessionContextId))
        }
        inactive.sort { $0.ts > $1.ts }

        guard !inactive.isEmpty else { return nil }

        let now = Date().timeIntervalSince1970

        // Try each snapshot: load its ratchet state into the active identity and retry decrypt.
        for snapshot in inactive {
            guard let snapshotProps = await snapshot.identity.props(symmetricKey: symmetricKey) else { continue }

            // Age expiry (best-effort)
            let archivedAt = TimeInterval(snapshotProps.sessionContextId)
            if now - archivedAt > PQSSessionConstants.inactiveSessionMaxAgeSeconds {
                try await cache.deleteSessionIdentity(snapshot.identity.id)
                continue
            }

            guard let snapshotState = snapshotProps.state else { continue }

            // Restore snapshot state into active identity.
            activeProps.state = snapshotState
            try await activeIdentity.updateIdentityProps(symmetricKey: symmetricKey, props: activeProps)
            try await cache.updateSessionIdentity(activeIdentity)

            do {
                try await initializeRecipient(
                    sessionIdentity: activeIdentity,
                    session: session,
                    ratchetMessage: verificationResult.ratchetMessage
                )

                let decrypted = try await ratchetManager.ratchetDecrypt(
                    verificationResult.ratchetMessage,
                    sessionId: activeIdentity.id
                )

                // Success: delete the used snapshot so we converge onto the recovered state.
                try await cache.deleteSessionIdentity(snapshot.identity.id)

                // Restore-in-place succeeded; keep the activeProps as-is (ratchetManager will advance it).
                return decrypted
            } catch {
                // Revert active identity to its original state before trying the next snapshot.
                activeProps.state = originalState
                try await activeIdentity.updateIdentityProps(symmetricKey: symmetricKey, props: activeProps)
                try await cache.updateSessionIdentity(activeIdentity)
                continue
            }
        }

        return nil
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
        
        // Header key IDs are authoritative for recipient key selection.
        // If a header ID is nil, this message uses "no one-time key" semantics for that algorithm.
        if let oneTimeKeyId = ratchetMessage.header.oneTimeKeyId {
            if let privateOneTimeKey = sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.first(where: { $0.id == oneTimeKeyId }) {
                localOneTimePrivateKey = privateOneTimeKey
            } else if let state = props.state, state.localOneTimePrivateKey?.id == oneTimeKeyId {
                // Backward-compatible fallback only when state key ID exactly matches header key ID.
                localOneTimePrivateKey = state.localOneTimePrivateKey
            } else {
                throw RatchetError.missingOneTimeKey
            }
        } else {
            localOneTimePrivateKey = nil
        }

        if let mlKEMOneTimeKeyId = ratchetMessage.header.mlKEMOneTimeKeyId {
            if let privateMLKEMOneTimeKey = sessionContext.sessionUser.deviceKeys.mlKEMOneTimePrivateKeys.first(where: { $0.id == mlKEMOneTimeKeyId }) {
                localMLKEMPrivateKey = privateMLKEMOneTimeKey
            } else if sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey.id == mlKEMOneTimeKeyId {
                // Header can legitimately reference the recipient's final MLKEM key.
                localMLKEMPrivateKey = sessionContext.sessionUser.deviceKeys.finalMLKEMPrivateKey
            } else if let state = props.state, state.localMLKEMPrivateKey.id == mlKEMOneTimeKeyId {
                // Backward-compatible fallback only when state key ID exactly matches header key ID.
                localMLKEMPrivateKey = state.localMLKEMPrivateKey
            } else {
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
            logger.log(level: .info, message: "Inbound message persisted with sharedId=\(messageModel.sharedId), recipient=\(decodedMessage.recipient), flag=\(decodedMessage.transportInfo != nil ? "hasTransportInfo" : "noTransportInfo")")
            /// Make sure we send the message to our SDK consumer as soon as it becomes available for best user experience
            await session.receiverDelegate?.createdMessage(messageModel)
        case .broadcast:
            // Broadcast messages are not persiseted yet
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
        
        var sessionIdentity = await identities.asyncFirst(where: { identity in
            guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else { return false }
            return props.deviceId == inboundTask.senderDeviceId
        })
        
        if sessionIdentity == nil { // SessionIdentity shouldn't be nil, but in case refresh never occured force it.
            identities = try await session.refreshIdentities(secretName: inboundTask.senderSecretName, forceRefresh: true)
            sessionIdentity = await identities.asyncFirst(where: { identity in
                guard let props = await identity.props(symmetricKey: databaseSymmetricKey) else { return false }
                return props.deviceId == inboundTask.senderDeviceId
            })
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
            guard let refreshed = await refreshedIdentities.asyncFirst(where: { identity in
                guard let refreshedProps = await identity.props(symmetricKey: databaseSymmetricKey) else { return false }
                return refreshedProps.deviceId == inboundTask.senderDeviceId
            }) else {
                throw PQSSession.SessionErrors.invalidSignature
            }
            
            guard let refreshedProps = await refreshed.props(symmetricKey: databaseSymmetricKey) else {
                throw JobProcessorErrors.missingIdentity
            }
            let refreshedKey = try Curve25519.Signing.PublicKey(rawRepresentation: refreshedProps.signingPublicKey)
            
            guard try signedMessage.verifySignature(using: refreshedKey) else {
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

//
//  SessionEvents.swift
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
import BSON
import Foundation
import NeedleTailAsyncSequence
import SessionEvents
import SessionModels
#if os(Android) || os(Linux)
@preconcurrency import Crypto
#else
import Crypto
#endif

/// Extension to `PQSSession` providing all event-driven messaging, contact management, and protocol conformance for session events.
///
/// This extension implements the core logic for sending and receiving messages, managing contacts, updating delivery states, and handling
/// communication synchronization. It also provides the concrete implementation for the `SessionEvents` protocol, allowing the session to
/// interact with the rest of the system in a modular, event-driven fashion.
///
/// - Handles outbound and inbound message flows, including encryption, key refresh, and persistence decisions.
/// - Manages contact creation, updates, and friendship state changes.
/// - Provides hooks for delivery state updates, metadata requests, and message editing.
/// - Ensures all operations are performed securely and asynchronously, leveraging the actor model for thread safety.

// MARK: PQSSession Events

public extension PQSSession {
    /// Sends an encrypted text message to a specified recipient with optional metadata and destruction settings.
    ///
    /// This method handles the complete message lifecycle including automatic key refresh, message encryption,
    /// and delivery through the transport layer. It automatically refreshes one-time keys if the supply is low
    /// (≤10 keys) to ensure continuous communication capability.
    ///
    /// ## Message Flow
    /// 1. **Key Refresh**: Automatically refreshes one-time keys if supply is low
    /// 2. **Message Creation**: Constructs a `CryptoMessage` with provided parameters
    /// 3. **Encryption**: Encrypts the message using Double Ratchet protocol
    /// 4. **Delivery**: Sends the encrypted message through the transport layer
    ///
    /// ## Usage Example
    /// ```swift
    /// try await session.writeTextMessage(
    ///     recipient: .nickname("alice"),
    ///     text: "Hello, how are you?",
    ///     metadata: ["timestamp": Date(), "priority": "high"],
    ///     destructionTime: 3600 // Message self-destructs in 1 hour
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - recipient: The intended recipient of the message. Can be a nickname, group, or other recipient type.
    ///   - text: The text content of the message. Defaults to an empty string.
    ///   - transportInfo: Optional transport-specific data for routing or delivery context.
    ///   - metadata: Additional metadata associated with the message (timestamps, flags, etc.).
    ///   - destructionTime: Optional time interval in seconds after which the message should be automatically destroyed.
    ///     If `nil`, the message persists indefinitely.
    ///
    /// - Throws:
    ///   - `SessionErrors.sessionNotInitialized` if the session is not properly initialized
    ///   - `SessionErrors.databaseNotInitialized` if the database delegate is not set
    ///   - `SessionErrors.transportNotInitialized` if the transport delegate is not set
    ///   - `SessionErrors.invalidSignature` if cryptographic operations fail
    ///   - `SessionErrors.drainedKeys` if key refresh fails due to insufficient keys
    ///
    /// - Important: This method automatically handles key refresh when needed. Ensure your transport delegate
    ///   is properly configured to handle key upload/download operations.
    /// - Note: Messages with `destructionTime` set will be automatically deleted after the specified duration.
    ///   This deletion happens on both sender and recipient devices.
    func writeTextMessage(
        recipient: MessageRecipient,
        text: String = "",
        transportInfo: Data? = nil,
        metadata: Document,
        destructionTime: TimeInterval? = nil
    ) async throws {
        do {
            let message = CryptoMessage(
                text: text,
                metadata: metadata,
                recipient: recipient,
                transportInfo: transportInfo,
                sentDate: Date(),
                destructionTime: destructionTime
            )

            try await processWrite(message: message, session: self)
        } catch {
            logger.log(level: .error, message: "\(error)")
            throw error
        }
    }

    /// Receives and processes an inbound encrypted message from another user.
    ///
    /// This method handles the complete inbound message lifecycle including automatic key refresh,
    /// message decryption, and processing through the task processor. It automatically refreshes
    /// one-time keys if the supply is low (≤10 keys) to ensure continuous communication capability.
    ///
    /// ## Message Processing Flow
    /// 1. **Key Refresh**: Automatically refreshes one-time keys if supply is low
    /// 2. **Message Validation**: Verifies the signed ratchet message authenticity
    /// 3. **Decryption**: Decrypts the message using Double Ratchet protocol
    /// 4. **Processing**: Handles the message through the task processor
    /// 5. **Persistence**: Stores the message if required by the session delegate
    ///
    /// ## Usage Example
    /// ```swift
    /// // Called by your transport layer when receiving a message
    /// try await session.receiveMessage(
    ///     message: signedRatchetMessage,
    ///     sender: "alice",
    ///     deviceId: UUID(),
    ///     messageId: "msg_123"
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - message: The signed ratchet message containing the encrypted payload and cryptographic metadata.
    ///   - sender: The secret name of the message sender for authentication and routing.
    ///   - deviceId: The unique identifier of the sender's device for multi-device support.
    ///   - messageId: A unique identifier for the message used for deduplication and tracking.
    ///
    /// - Throws:
    ///   - `SessionErrors.sessionNotInitialized` if the session is not properly initialized
    ///   - `SessionErrors.databaseNotInitialized` if the database delegate is not set
    ///   - `SessionErrors.invalidSignature` if message signature verification fails
    ///   - `SessionErrors.drainedKeys` if key refresh fails due to insufficient keys
    ///   - `SessionErrors.sessionDecryptionError` if message decryption fails
    ///
    /// - Important: This method should be called by your transport layer implementation when
    ///   receiving messages from the network. It handles all the cryptographic processing automatically.
    /// - Note: The method automatically refreshes keys when needed, ensuring continuous communication
    ///   capability without manual intervention.
    func receiveMessage(
        message: SignedRatchetMessage,
        sender: String,
        deviceId: UUID,
        messageId: String
    ) async throws {
        // We need to make sure that our remote keys are in sync with local keys before proceeding. We do this if we have less that 10 local keys.
        if let sessionContext = await sessionContext, sessionContext.activeUserConfiguration.signedOneTimePublicKeys.count <= 10 {
            async let _ = await refreshOneTimeKeysTask()
        }
        if let sessionContext = await sessionContext, sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.count <= 10 {
            async let _ = await refreshOneTimeKeysTask()
        }

        let message = InboundTaskMessage(
            message: message,
            senderSecretName: sender,
            senderDeviceId: deviceId,
            sharedMessageId: messageId
        )

        try await taskProcessor.inboundTask(
            message,
            session: self)
    }

    // MARK: Outbound

    /// Processes an outbound message by encrypting and sending it to all target devices.
    ///
    /// This internal method handles the outbound message processing pipeline, including session validation,
    /// message encryption using the Double Ratchet protocol, and delivery to all devices associated with
    /// the recipient. It determines whether messages should be persisted based on the session delegate's
    /// `shouldPersist` method.
    ///
    /// ## Processing Flow
    /// 1. **Session Validation**: Ensures session context and cache are available
    /// 2. **Key Retrieval**: Gets the database symmetric key for encryption
    /// 3. **Persistence Decision**: Determines if the message should be stored locally
    /// 4. **Encryption & Delivery**: Encrypts and sends to all recipient devices
    ///
    /// - Parameters:
    ///   - message: The cryptographic message to be processed and sent.
    ///   - session: The current cryptographic session instance.
    ///
    /// - Throws:
    ///   - `SessionErrors.sessionNotInitialized` if the session context is not available
    ///   - `SessionErrors.databaseNotInitialized` if the cache is not available
    ///   - `SessionErrors.invalidSignature` if cryptographic operations fail
    ///   - `SessionErrors.transportNotInitialized` if the transport delegate is not set
    ///
    /// - Important: This method is called internally by `writeTextMessage`. It handles the complex
    ///   logic of multi-device delivery and persistence decisions.
    /// - Note: The method automatically handles device discovery and ensures messages are delivered
    ///   to all devices associated with the recipient.
    internal func processWrite(
        message: CryptoMessage,
        session: PQSSession
    ) async throws {
        guard let sessionContext = await session.sessionContext else {
            throw SessionErrors.sessionNotInitialized
        }
        guard let cache = await session.cache else {
            throw SessionErrors.databaseNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()
        let mySecretName = sessionContext.sessionUser.secretName

        let shouldPersist = sessionDelegate?.shouldPersist(transportInfo: message.transportInfo) == false ? false : true

        try await taskProcessor.outboundTask(
            message: message,
            cache: cache,
            symmetricKey: symmetricKey,
            session: session,
            sender: mySecretName,
            type: message.recipient,
            shouldPersist: shouldPersist,
            logger: logger
        )
    }
}

// MARK: - PQSSession SessionEvents Protocol Conformance

extension PQSSession: SessionEvents {
    /// Requires all necessary session parameters for processing.
    /// - Returns: A tuple containing all required session parameters.
    /// - Throws: An error if any of the required parameters are not initialized.
    private func requireAllSessionParameters() async throws -> (sessionContext: SessionContext,
                                                                cache: PQSSessionStore,
                                                                transportDelegate: SessionTransport,
                                                                receiverDelegate: EventReceiver,
                                                                sessionDelegate: PQSSessionDelegate,
                                                                symmetricKey: SymmetricKey)
    {
        guard let sessionContext = await sessionContext else {
            throw SessionErrors.sessionNotInitialized
        }
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        guard let transportDelegate else {
            throw SessionErrors.transportNotInitialized
        }
        guard let receiverDelegate else {
            throw SessionErrors.receiverDelegateNotSet
        }
        guard let sessionDelegate else {
            throw SessionErrors.sessionNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()

        return (sessionContext, cache, transportDelegate, receiverDelegate, sessionDelegate, symmetricKey)
    }

    /// Requires session parameters excluding the transport delegate.
    /// - Returns: A tuple containing the required session parameters.
    /// - Throws: An error if any of the required parameters are not initialized.
    private func requireSessionParametersWithoutTransportDelegate() async throws -> (sessionContext: SessionContext,
                                                                                     cache: PQSSessionStore,
                                                                                     receiverDelegate: EventReceiver,
                                                                                     sessionDelegate: PQSSessionDelegate,
                                                                                     symmetricKey: SymmetricKey)
    {
        guard let sessionContext = await sessionContext else {
            throw SessionErrors.sessionNotInitialized
        }
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        guard let receiverDelegate else {
            throw SessionErrors.receiverDelegateNotSet
        }
        guard let sessionDelegate else {
            throw SessionErrors.sessionNotInitialized
        }
        let symmetricKey = try await getDatabaseSymmetricKey()

        return (sessionContext, cache, receiverDelegate, sessionDelegate, symmetricKey)
    }

    // MARK: - Contact Management

    /// Adds a list of contacts to the session.
    /// - Parameter infos: An array of shared contact information to be added.
    /// - Throws: An error if the addition of contacts fails.
    public func addContacts(_ infos: [SharedContactInfo]) async throws {
        let params = try await requireAllSessionParameters()

        if let eventDelegate {
            try await eventDelegate.addContacts(
                infos,
                sessionContext: params.sessionContext,
                cache: params.cache,
                transport: params.transportDelegate,
                receiver: params.receiverDelegate,
                sessionDelegate: params.sessionDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger
            )
        } else {
            try await addContacts(
                infos,
                sessionContext: params.sessionContext,
                cache: params.cache,
                transport: params.transportDelegate,
                receiver: params.receiverDelegate,
                sessionDelegate: params.sessionDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger
            )
        }
    }

    /// Updates or creates a contact with the specified secret name and metadata.
    /// - Parameters:
    ///   - secretName: The secret name of the contact to be updated or created.
    ///   - metadata: Additional metadata associated with the contact.
    ///   - requestFriendship: A boolean indicating whether to request friendship.
    /// - Returns: A `ContactModel` representing the updated or created contact.
    /// - Throws: An error if the operation fails.
    public func createContact(
        secretName: String,
        metadata: Document = [:],
        requestFriendship: Bool
    ) async throws -> ContactModel {
        let params = try await requireAllSessionParameters()
        if let eventDelegate {
            return try await eventDelegate.createContact(
                secretName: secretName,
                metadata: metadata,
                requestFriendship: requestFriendship,
                sessionContext: params.sessionContext,
                cache: params.cache,
                transport: params.transportDelegate,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger
            )
        } else {
            return try await createContact(
                secretName: secretName,
                metadata: metadata,
                requestFriendship: requestFriendship,
                sessionContext: params.sessionContext,
                cache: params.cache,
                transport: params.transportDelegate,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger
            )
        }
    }

    /// Sends a communication synchronization request for the specified contact.
    /// - Parameter secretName: The secret name of the contact to synchronize with.
    /// - Throws: An error if the synchronization request fails.
    public func sendCommunicationSynchronization(contact secretName: String) async throws {
        let params = try await requireSessionParametersWithoutTransportDelegate()
        // On Contact Created attempt to create session identities
        _ = try await refreshIdentities(secretName: secretName, forceRefresh: true)
        if let eventDelegate {
            return try await eventDelegate.sendCommunicationSynchronization(
                contact: secretName,
                sessionContext: params.sessionContext,
                sessionDelegate: params.sessionDelegate,
                cache: params.cache,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger
            )
        } else {
            return try await sendCommunicationSynchronization(
                contact: secretName,
                sessionContext: params.sessionContext,
                sessionDelegate: params.sessionDelegate,
                cache: params.cache,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger
            )
        }
    }

    /// Requests a change in the friendship state for a specified contact.
    /// - Parameters:
    ///   - state: The new friendship state to be set.
    ///   - contact: The contact whose friendship state is to be changed.
    /// - Throws: An error if the request fails.
    public func requestFriendshipStateChange(
        state: FriendshipMetadata.State,
        contact: Contact
    ) async throws {
        let params = try await requireSessionParametersWithoutTransportDelegate()

        if let eventDelegate {
            return try await eventDelegate.requestFriendshipStateChange(
                state: state,
                contact: contact,
                cache: params.cache,
                receiver: params.receiverDelegate,
                sessionDelegate: params.sessionDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger
            )
        } else {
            return try await requestFriendshipStateChange(
                state: state,
                contact: contact,
                cache: params.cache,
                receiver: params.receiverDelegate,
                sessionDelegate: params.sessionDelegate,
                symmetricKey: params.symmetricKey,
                logger: logger
            )
        }
    }

    /// Updates the delivery state of a specified message.
    /// - Parameters:
    ///   - message: The encrypted message whose delivery state is to be updated.
    ///   - deliveryState: The new delivery state to be set.
    ///   - messageRecipient: The recipient of the message.
    ///   - allowExternalUpdate: A boolean indicating whether to allow external updates.
    /// - Throws: An error if the update fails.
    public func updateMessageDeliveryState(
        _ message: EncryptedMessage,
        deliveryState: DeliveryState,
        messageRecipient: MessageRecipient,
        allowExternalUpdate: Bool = false
    ) async throws {
        let params = try await requireSessionParametersWithoutTransportDelegate()

        if let eventDelegate {
            return try await eventDelegate.updateMessageDeliveryState(
                message,
                deliveryState: deliveryState,
                messageRecipient: messageRecipient,
                allowExternalUpdate: allowExternalUpdate,
                sessionDelegate: params.sessionDelegate,
                cache: params.cache,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey
            )
        } else {
            return try await updateMessageDeliveryState(
                message,
                deliveryState: deliveryState,
                messageRecipient: messageRecipient,
                allowExternalUpdate: allowExternalUpdate,
                sessionDelegate: params.sessionDelegate,
                cache: params.cache,
                receiver: params.receiverDelegate,
                symmetricKey: params.symmetricKey
            )
        }
    }

    /// Sends an acknowledgment that a contact has been created to the specified recipient.
    /// - Parameter secretName: The secret name of the recipient to acknowledge.
    /// - Throws: An error if the acknowledgment fails.
    public func sendContactCreatedAcknowledgment(recipient secretName: String) async throws {
        guard let sessionDelegate else { throw SessionErrors.sessionNotInitialized }
        if let eventDelegate {
            return try await eventDelegate.sendContactCreatedAcknowledgment(
                recipient: secretName,
                sessionDelegate: sessionDelegate,
                logger: logger
            )
        } else {
            return try await sendContactCreatedAcknowledgment(
                recipient: secretName,
                sessionDelegate: sessionDelegate,
                logger: logger
            )
        }
    }

    /// Requests metadata from a specified contact.
    /// - Parameter secretName: The secret name of the contact to request metadata from.
    /// - Throws: An error if the request fails.
    public func requestMetadata(from secretName: String) async throws {
        guard let sessionDelegate else { throw SessionErrors.sessionNotInitialized }
        if let eventDelegate {
            return try await eventDelegate.requestMetadata(
                from: secretName,
                sessionDelegate: sessionDelegate,
                logger: logger
            )
        } else {
            return try await requestMetadata(
                from: secretName,
                sessionDelegate: sessionDelegate,
                logger: logger
            )
        }
    }

    /// Requests the metadata of the current user.
    /// - Throws: An error if the request fails.
    public func requestMyMetadata() async throws {
        guard let sessionDelegate else { throw SessionErrors.sessionNotInitialized }
        if let eventDelegate {
            return try await eventDelegate.requestMyMetadata(
                sessionDelegate: sessionDelegate,
                logger: logger
            )
        } else {
            return try await requestMyMetadata(
                sessionDelegate: sessionDelegate,
                logger: logger
            )
        }
    }

    /// Edits the current message with new text.
    /// - Parameters:
    ///   - message: The encrypted message to be edited.
    ///   - newText: The new text to replace the current message text.
    /// - Throws: An error if the editing fails.
    public func editCurrentMessage(_ message: EncryptedMessage, newText: String) async throws {
        guard let cache else { throw SessionErrors.databaseNotInitialized }
        guard let receiverDelegate else { throw SessionErrors.receiverDelegateNotSet }
        guard let sessionDelegate else { throw SessionErrors.sessionNotInitialized }
        let symmetricKey = try await getDatabaseSymmetricKey()

        if let eventDelegate {
            return try await eventDelegate.editCurrentMessage(
                message,
                newText: newText,
                sessionDelegate: sessionDelegate,
                cache: cache,
                receiver: receiverDelegate,
                symmetricKey: symmetricKey,
                logger: logger
            )
        } else {
            return try await editCurrentMessage(
                message,
                newText: newText,
                sessionDelegate: sessionDelegate,
                cache: cache,
                receiver: receiverDelegate,
                symmetricKey: symmetricKey,
                logger: logger
            )
        }
    }

    /// Finds the communication associated with a specified message recipient.
    /// - Parameter messageRecipient: The recipient of the message to find communication for.
    /// - Returns: A `BaseCommunication` object representing the found communication.
    /// - Throws: An error if the communication cannot be found.
    public func findCommunication(for messageRecipient: MessageRecipient) async throws -> BaseCommunication {
        guard let cache else { throw SessionErrors.databaseNotInitialized }
        let symmetricKey = try await getDatabaseSymmetricKey()

        if let eventDelegate {
            return try await eventDelegate.findCommunication(
                for: messageRecipient,
                cache: cache,
                symmetricKey: symmetricKey
            )
        } else {
            return try await findCommunication(
                for: messageRecipient,
                cache: cache,
                symmetricKey: symmetricKey
            )
        }
    }
}

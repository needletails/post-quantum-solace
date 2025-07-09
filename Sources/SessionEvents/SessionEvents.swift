//
//  SessionEvents.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-04-19.
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
import Crypto
import Foundation
import NeedleTailLogger
import SessionModels

/// An enumeration representing various errors that can occur in session events.
enum EventErrors: Error {
    /// Indicates that the session has not been initialized.
    case sessionNotInitialized

    /// Indicates that the database has not been initialized.
    case databaseNotInitialized

    /// Indicates that the transport layer has not been initialized.
    case transportNotInitialized

    /// Indicates a generic properties error.
    case propsError

    /// Indicates that the provided secret name is invalid.
    case invalidSecretName

    /// Indicates that required metadata is missing.
    case missingMetadata

    /// Indicates that a communication could not be found.
    case cannotFindCommunication

    /// Indicates that a contact could not be found.
    case cannotFindContact

    /// Indicates that the user is blocked.
    case userIsBlocked
}

/// A protocol that defines methods for handling session events in a post-quantum secure messaging system.
///
/// The `SessionEvents` protocol provides a comprehensive interface for managing session-related operations
/// including contact management, friendship state changes, message delivery tracking, and communication
/// synchronization. This protocol is designed to work with encrypted, secure messaging systems that
/// implement post-quantum cryptography.
///
/// ## Key Features
/// - **Contact Management**: Add, update, and manage contacts with metadata
/// - **Friendship States**: Handle complex friendship state transitions (pending, requested, accepted, blocked, etc.)
/// - **Message Operations**: Edit messages and track delivery states
/// - **Communication Sync**: Synchronize communication channels between contacts
/// - **Metadata Management**: Request and handle contact metadata
///
/// ## Usage
/// ```swift
/// // Example: Adding contacts to a session
/// try await sessionEvents.addContacts(
///     contactInfos,
///     sessionContext: context,
///     cache: store,
///     transport: transport,
///     receiver: receiver,
///     sessionDelegate: delegate,
///     symmetricKey: key,
///     logger: logger
/// )
///
/// // Example: Requesting friendship state change
/// try await sessionEvents.requestFriendshipStateChange(
///     state: .requested,
///     contact: contact,
///     cache: store,
///     receiver: receiver,
///     sessionDelegate: delegate,
///     symmetricKey: key,
///     logger: logger
/// )
/// ```
///
/// ## Thread Safety
/// This protocol is marked as `Sendable`, ensuring thread-safe usage across concurrent contexts.
///
/// ## Error Handling
/// All methods in this protocol can throw errors. Implement proper error handling to manage
/// failures gracefully. Common errors include initialization failures, missing data, and network issues.
public protocol SessionEvents: Sendable {
    /// Adds contacts to the session and establishes communication channels.
    ///
    /// This method processes an array of contact information, filters out existing contacts,
    /// creates new contact records, establishes communication models, and synchronizes
    /// with the network layer.
    ///
    /// ## Process Flow
    /// 1. Filters out contacts that already exist in the cache
    /// 2. Retrieves user configuration for each new contact
    /// 3. Creates `Contact` and `ContactModel` instances
    /// 4. Establishes communication models with shared identifiers
    /// 5. Requests metadata from new contacts
    /// 6. Sends communication synchronization requests
    /// 7. Requests current user's metadata
    ///
    /// - Parameters:
    ///   - contactInfos: An array of `SharedContactInfo` containing contact information to be added.
    ///     Each contact info should include a unique secret name and metadata.
    ///   - sessionContext: The context of the current session, providing user-specific information
    ///     including the current user's secret name and session configuration.
    ///   - cache: The `PQSSessionStore` used for caching contacts and communications.
    ///     This provides persistent storage for contact and communication data.
    ///   - transport: The `SessionTransport` used for communication with other devices.
    ///     This handles network operations and user configuration retrieval.
    ///   - receiver: The `EventReceiver` that will handle events related to contact creation
    ///     and updates. This notifies the UI layer of changes.
    ///   - sessionDelegate: The `PQSSessionDelegate` for managing session-related tasks
    ///     such as metadata requests and communication synchronization.
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///     This ensures all stored data is properly encrypted.
    ///   - logger: The logger for logging events and debugging information.
    ///     This helps with troubleshooting and monitoring.
    ///
    /// - Throws:
    ///   - `EventErrors.propsError` if there is an issue with the properties of the communication model.
    ///   - `EventErrors.invalidSecretName` if any contact has an invalid secret name.
    ///   - Any other error that may occur during the process, such as network issues or database errors.
    ///
    /// - Note: This method automatically requests the current user's metadata after adding new contacts.
    /// - Important: Ensure all dependencies are properly initialized before calling this method.
    func addContacts(
        _ contactInfos: [SharedContactInfo],
        sessionContext: SessionContext,
        cache: PQSSessionStore,
        transport: SessionTransport,
        receiver: EventReceiver,
        sessionDelegate: PQSSessionDelegate,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws

    /// Updates or creates a contact.
    /// - Parameters:
    ///   - secretName: The secret name of the contact.
    ///   - metadata: The metadata associated with the contact.
    ///   - requestFriendship: A boolean indicating whether to request friendship.
    ///   - sessionContext: The context of the current session.
    ///   - cache: The `PQSSessionStore` used for caching.
    ///   - transport: The `SessionTransport` used for communication.
    ///   - receiver: The `EventReceiver` that will handle events.
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - logger: The logger for logging events.
    /// - Returns: A `ContactModel` representing the updated or created contact.
    /// - Throws: An error if the operation fails.
    func createContact(
        secretName: String,
        metadata: Document,
        requestFriendship: Bool,
        sessionContext: SessionContext,
        cache: PQSSessionStore,
        transport: SessionTransport,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws -> ContactModel

    /// Sends a communication synchronization request.
    /// - Parameters:
    ///   - secretName: The secret name of the contact.
    ///   - sessionContext: The context of the current session.
    ///   - sessionDelegate: The `PQSSessionDelegate` for session management.
    ///   - cache: The `PQSSessionStore` used for caching.
    ///   - receiver: The `EventReceiver` that will handle events.
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - logger: The logger for logging events.
    /// - Throws: An error if the operation fails.
    func sendCommunicationSynchronization(
        contact secretName: String,
        sessionContext: SessionContext,
        sessionDelegate: PQSSessionDelegate,
        cache: PQSSessionStore,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws

    /// Requests a change in the friendship state for a specific contact.
    ///
    /// This method manages the complete lifecycle of friendship state changes, including:
    /// 1. Validates the current friendship state and prevents invalid transitions.
    /// 2. Updates the friendship metadata using the appropriate state management methods.
    /// 3. Retrieves the symmetric key for encryption.
    /// 4. Updates the friendship metadata based on the requested state.
    /// 5. Notifies the receiver delegate of the metadata change.
    /// 6. Updates the contact in the local cache.
    /// 7. Sends a message to the recipient regarding the friendship state change.
    ///
    /// ## State Transitions
    /// The method maps each requested state to the appropriate `FriendshipMetadata` method:
    /// - `.pending` → `resetToPendingState()` - Resets the friendship to initial state
    /// - `.requested` → `setRequestedState()` - Initiates a friendship request
    /// - `.accepted` → `setAcceptedState()` - Accepts a friendship request
    /// - `.blocked`/`.blockedByOther` → `setBlockState(isBlocking: false)` - Blocks the contact
    /// - `.unblocked` → `setAcceptedState()` - Unblocks the contact (resets to accepted)
    /// - `.rejected`/`.rejectedByOther`/`.mutuallyRejected` → `rejectRequest()` - Rejects the request
    ///
    /// - Parameters:
    ///   - state: The desired friendship state to be set for the contact. This can be one of the following:
    ///     - `.pending`: Indicates that a friend request should be revoked or reset.
    ///     - `.requested`: Indicates that a friend request should be sent.
    ///     - `.accepted`: Indicates that a friend request should be accepted.
    ///     - `.rejected`: Indicates that a friend request should be rejected.
    ///     - `.blocked`: Indicates that the contact should be blocked.
    ///     - `.unblocked`: Indicates that the contact should be unblocked.
    ///   - contact: The `Contact` object representing the contact whose friendship state is being changed.
    ///   - cache: The `PQSSessionStore` used for caching contact data.
    ///   - receiver: The `EventReceiver` that will handle contact update events.
    ///   - sessionDelegate: The `PQSSessionDelegate` for managing session-related tasks.
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///   - logger: The logger for logging events and debugging information.
    ///
    /// - Throws:
    ///   - `EventErrors.databaseNotInitialized`: If the cache is not initialized.
    ///   - `EventErrors.sessionNotInitialized`: If the session context is not initialized.
    ///   - `EventErrors.cannotFindContact`: If the specified contact cannot be found in the cache.
    ///   - `EventErrors.propsError`: If there is an error updating the contact's properties.
    ///   - `EventErrors.userIsBlocked`: If the current user is blocked and cannot perform the action.
    ///   - Any other errors that may occur during the process, such as encoding errors or network issues.
    ///
    /// - Important:
    ///   - Ensure that the session and cache are properly initialized before calling this method.
    ///   - The method prevents redundant state changes (e.g., accepting an already accepted friendship).
    ///   - Blocked users cannot perform friendship state changes.
    ///
    /// - Note: This method is asynchronous and should be awaited.
    func requestFriendshipStateChange(
        state: FriendshipMetadata.State,
        contact: Contact,
        cache: PQSSessionStore,
        receiver: EventReceiver,
        sessionDelegate: PQSSessionDelegate,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws

    /// Updates the delivery state of a message.
    /// - Parameters:
    ///   - message: The `EncryptedMessage` whose delivery state is being updated.
    ///   - deliveryState: The new delivery state of the message.
    ///   - messageRecipient: The recipient of the message.
    ///   - allowExternalUpdate: A boolean indicating whether external updates are allowed.
    ///   - sessionDelegate: The `PQSSessionDelegate` for session management.
    ///   - cache: The `PQSSessionStore` used for caching.
    ///   - receiver: The `EventReceiver` that will handle events.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if the operation fails.
    func updateMessageDeliveryState(
        _ message: EncryptedMessage,
        deliveryState: DeliveryState,
        messageRecipient: MessageRecipient,
        allowExternalUpdate: Bool,
        sessionDelegate: PQSSessionDelegate,
        cache: PQSSessionStore,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey
    ) async throws

    /// Sends an acknowledgment that a contact was created.
    /// - Parameters:
    ///   - secretName: The secret name of the recipient contact.
    ///   - sessionDelegate: The `PQSSessionDelegate` for session management.
    ///   - logger: The logger for logging events.
    /// - Throws: An error if the operation fails.
    func sendContactCreatedAcknowledgment(
        recipient secretName: String,
        sessionDelegate: PQSSessionDelegate,
        logger: NeedleTailLogger
    ) async throws

    /// Requests metadata from a contact.
    /// - Parameters:
    ///   - secretName: The secret name of the contact from whom to request metadata.
    ///   - sessionDelegate: The `PQSSessionDelegate` for session management.
    ///   - logger: The logger for logging events.
    /// - Throws: An error if the operation fails.
    func requestMetadata(
        from secretName: String,
        sessionDelegate: PQSSessionDelegate,
        logger: NeedleTailLogger
    ) async throws

    /// Requests the metadata for the current user.
    /// - Parameters:
    ///   - sessionDelegate: The `PQSSessionDelegate` for session management.
    ///   - logger: The logger for logging events.
    /// - Throws: An error if the operation fails.
    func requestMyMetadata(
        sessionDelegate: PQSSessionDelegate,
        logger: NeedleTailLogger
    ) async throws

    /// Edits the current message.
    /// - Parameters:
    ///   - message: The `EncryptedMessage` to be edited.
    ///   - newText: The new text for the message.
    ///   - sessionDelegate: The `PQSSessionDelegate` for session management.
    ///   - cache: The `PQSSessionStore` used for caching.
    ///   - receiver: The `EventReceiver` that will handle events.
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - logger: The logger for logging events.
    /// - Throws: An error if the operation fails.
    func editCurrentMessage(
        _ message: EncryptedMessage,
        newText: String,
        sessionDelegate: PQSSessionDelegate,
        cache: PQSSessionStore,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws

    /// Finds a communication for a specific message recipient.
    /// - Parameters:
    ///   - messageRecipient: The recipient of the message.
    ///   - cache: The `PQSSessionStore` used for caching.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Returns: A `BaseCommunication` instance associated with the recipient.
    /// - Throws: An error if the operation fails.
    func findCommunication(
        for messageRecipient: MessageRecipient,
        cache: PQSSessionStore,
        symmetricKey: SymmetricKey
    ) async throws -> BaseCommunication
}

public extension SessionEvents {
    /// Adds contacts to the session and synchronizes communication.
    ///
    /// This method processes an array of `SharedContactInfo`, filtering out any contacts that already exist in the cache.
    /// For each new contact, it retrieves the user configuration, creates a `Contact` and `ContactModel`,
    /// and updates the communication model. It also requests metadata from the newly added contacts and
    /// sends a communication synchronization request.
    ///
    /// - Parameters:
    ///   - contactInfos: An array of `SharedContactInfo` containing the contact information to be added.
    ///   - sessionContext: The context of the current session, providing user-specific information.
    ///   - cache: The `PQSSessionStore` used for caching contacts and communications.
    ///   - transport: The `SessionTransport` used for communication with other devices.
    ///   - receiver: The `EventReceiver` that will handle events related to contact creation.
    ///   - sessionDelegate: The `PQSSessionDelegate` for managing session-related tasks.
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///   - logger: The logger for logging events and debugging information.
    ///
    /// - Throws:
    ///   - `EventErrors.propsError` if there is an issue with the properties of the communication model.
    ///   - Any other error that may occur during the process, such as issues with fetching contacts,
    ///     creating contacts, or sending requests.
    ///
    /// - Note: This method also requests the current user's metadata after adding the new contacts.
    func addContacts(
        _ contactInfos: [SharedContactInfo],
        sessionContext: SessionContext,
        cache: PQSSessionStore,
        transport: SessionTransport,
        receiver: EventReceiver,
        sessionDelegate: PQSSessionDelegate,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws {
        let mySecretName = sessionContext.sessionUser.secretName
        let contacts = try await cache.fetchContacts()

        let filteredContactInfos = await contactInfos.asyncFilter { contactInfo in
            // Check if contacts is not nil and does not contain the secretName
            let containsSecretName = await contacts.asyncContains { contact in
                if let secretName = await contact.props(symmetricKey: symmetricKey)?.secretName {
                    return contactInfo.secretName == secretName
                }
                return false
            }

            // We want to include `contactInfo` only if `containsSecretName` is false
            return !containsSecretName
        }

        for contactInfo in filteredContactInfos {
            let userConfiguration = try await transport.findConfiguration(for: contactInfo.secretName)

            let contact = Contact(
                id: UUID(), // Consider using the same UUID for both Contact and ContactModel if they are linked
                secretName: contactInfo.secretName,
                configuration: userConfiguration,
                metadata: contactInfo.metadata
            )

            let contactModel = try ContactModel(
                id: contact.id, // Use the same UUID
                props: .init(
                    secretName: contact.secretName,
                    configuration: contact.configuration,
                    metadata: contact.metadata
                ),
                symmetricKey: symmetricKey
            )

            try await cache.createContact(contactModel)
            try await receiver.createdContact(contact)

            logger.log(level: .debug, message: "Creating Communication Model")
            // Create communication model
            let communicationModel = try await createCommunicationModel(
                recipients: [mySecretName, contactInfo.secretName],
                communicationType: .nickname(contactInfo.secretName),
                metadata: [:],
                symmetricKey: symmetricKey
            )

            guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
                throw EventErrors.propsError
            }

            props.sharedId = contactInfo.sharedCommunicationId

            _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
            try await cache.createCommunication(communicationModel)
            await receiver.updatedCommunication(communicationModel, members: [contactInfo.secretName])
            logger.log(level: .debug, message: "Created Communication Model for \(contactInfo.secretName)")

            try await requestMetadata(
                from: contact.secretName,
                sessionDelegate: sessionDelegate,
                logger: logger
            )

            try await sendCommunicationSynchronization(
                contact: contactInfo.secretName,
                sessionContext: sessionContext,
                sessionDelegate: sessionDelegate,
                cache: cache,
                receiver: receiver,
                symmetricKey: symmetricKey,
                logger: logger
            )
        }

        try await requestMyMetadata(sessionDelegate: sessionDelegate, logger: logger)

        // Synchronize with other devices if necessary
    }

    /// Updates or creates a contact in the local cached database and notifies the client of the changes.
    ///
    /// This method performs the following actions:
    /// 1. Creates a new contact or updates an existing contact in the local cached database.
    /// 2. Notifies the local client that a contact has been created or updated.
    /// 3. Notifies the local client of any changes to the contact's metadata.
    ///
    /// **Important:** After the client is notified of the local contact creation, the method
    /// `requestFriendshipStateChange` must be called to notify the recipient of the friendship request.
    /// This establishes a communication model that allows both parties to communicate with each other.
    ///
    /// - Parameters:
    ///   - secretName: The name of the contact to be added or updated.
    ///   - metadata: A dictionary containing predefined metadata for the contact. This is a base metadata that users can insert metadata into, they are responsible for proper keying and document retieval.
    ///     This can include nicknames and other relevant data. The default value is an empty dictionary.
    ///
    /// - Returns: A `ContactModel` representing the created or updated contact.
    ///
    /// - Throws: An error if the operation fails due to issues such as invalid parameters or database errors.
    func createContact(
        secretName: String,
        metadata: Document = [:],
        requestFriendship: Bool,
        sessionContext: SessionContext,
        cache: PQSSessionStore,
        transport: SessionTransport,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws -> ContactModel {
        let newContactSecretName = secretName.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        let mySecretName = sessionContext.sessionUser.secretName

        guard newContactSecretName != mySecretName else {
            throw EventErrors.invalidSecretName
        }

        // Check if the contact already exists
        if let foundContact = try await cache.fetchContacts().asyncFirst(where: { await $0.props(symmetricKey: symmetricKey)?.secretName == newContactSecretName }) {
            guard let props = await foundContact.props(symmetricKey: symmetricKey) else {
                throw EventErrors.propsError
            }

            // Simplified metadata handling
            let configuration = props.configuration
            let contactMetadata = metadata.isEmpty ? (props.metadata) : metadata

            guard let friendshipMetadata = contactMetadata["friendshipMetadata"] as? Document else { throw EventErrors.missingMetadata }

            let updatedProps = try await foundContact.updatePropsMetadata(
                symmetricKey: symmetricKey,
                metadata: friendshipMetadata,
                with: "friendshipMetadata"
            )

            guard let updatedMetadata = updatedProps?.metadata else {
                throw EventErrors.propsError
            }

            let updatedContact = Contact(
                id: foundContact.id,
                secretName: newContactSecretName,
                configuration: configuration,
                metadata: updatedMetadata
            )

            try await receiver.updateContact(updatedContact)

            let contactModel = try ContactModel(
                id: updatedContact.id, // Use the same UUID
                props: .init(
                    secretName: updatedContact.secretName,
                    configuration: updatedContact.configuration,
                    metadata: updatedContact.metadata
                ),
                symmetricKey: symmetricKey
            )

            try await cache.updateContact(contactModel)
            return contactModel
        } else {
            var userConfiguration = try await transport.findConfiguration(for: newContactSecretName)
            // Not needed on the contact level
            userConfiguration.signedPQKemOneTimePublicKeys.removeAll()
            userConfiguration.signedOneTimePublicKeys.removeAll()

            let contact = Contact(
                id: UUID(), // Consider using the same UUID for both Contact and ContactModel if they are linked
                secretName: newContactSecretName,
                configuration: userConfiguration,
                metadata: metadata
            )

            let contactModel = try ContactModel(
                id: contact.id, // Use the same UUID
                props: .init(
                    secretName: contact.secretName,
                    configuration: contact.configuration,
                    metadata: contact.metadata
                ),
                symmetricKey: symmetricKey
            )

            try await cache.createContact(contactModel)
            try await receiver.createdContact(contact)

            _ = try await updateOrCreateCommunication(
                mySecretName: mySecretName,
                theirSecretName: newContactSecretName,
                cache: cache,
                receiver: receiver,
                symmetricKey: symmetricKey,
                logger: logger
            )

            try await receiver.synchronize(
                contact: contact,
                requestFriendship: requestFriendship
            )
            return contactModel
        }
    }

    // For Contact to Contact Communication Synchronization

    /// Updates or creates a communication model between two contacts.
    ///
    /// This method checks if a communication model already exists for the given secret names.
    /// If it exists, it updates the model; if not, it creates a new one.
    /// It also assigns a shared identifier if it is not already present.
    ///
    /// - Parameters:
    ///   - mySecretName: The secret name of the current user.
    ///   - theirSecretName: The secret name of the contact with whom to synchronize communication.
    ///   - cache: The `PQSSessionStore` used for caching communication models.
    ///   - receiver: The `EventReceiver` that will handle events related to communication updates.
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///   - logger: The logger for logging events and debugging information.
    ///
    /// - Returns: An optional `String` representing the shared identifier if it was created; otherwise, `nil`.
    /// - Throws:
    ///   - `EventErrors.cannotFindCommunication` if the communication model cannot be found or created.
    ///   - `EventErrors.propsError` if there is an issue with the properties of the communication model.
    private func updateOrCreateCommunication(
        mySecretName: String,
        theirSecretName: String,
        cache: PQSSessionStore,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws -> String? {
        var communicationModel: BaseCommunication?
        var shouldUpdateCommunication = false
        do {
            communicationModel = try await findCommunicationType(
                cache: cache,
                communicationType: .nickname(theirSecretName),
                symmetricKey: symmetricKey
            )
            logger.log(level: .debug, message: "Found Communication Model")
            shouldUpdateCommunication = true
        } catch {
            logger.log(level: .debug, message: "Creating Communication Model")
            // Create communication model
            communicationModel = try await createCommunicationModel(
                recipients: [mySecretName, theirSecretName],
                communicationType: .nickname(theirSecretName),
                metadata: [:],
                symmetricKey: symmetricKey
            )
        }

        guard let communicationModel else {
            throw EventErrors.cannotFindCommunication
        }
        guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
            throw EventErrors.propsError
        }

        if props.sharedId == nil {
            let sharedIdentifier = UUID()
            props.sharedId = sharedIdentifier

            _ = try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
            if shouldUpdateCommunication {
                try await cache.updateCommunication(communicationModel)
                await receiver.updatedCommunication(communicationModel, members: [theirSecretName])
                logger.log(level: .debug, message: "Updated Communication Model")
            } else {
                try await cache.createCommunication(communicationModel)
                await receiver.updatedCommunication(communicationModel, members: [theirSecretName])
                logger.log(level: .debug, message: "Created Communication Model")
            }
            return sharedIdentifier.uuidString
        } else {
            logger.log(level: .debug, message: "Shared Id already exists")
            return nil
        }
    }

    /// Sends a communication synchronization request to a specified contact.
    ///
    /// This method initiates a synchronization process for communication with the specified contact.
    /// It first checks that the contact is not the current user, then updates or creates the communication model
    /// before sending the synchronization request to the session delegate.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the contact to synchronize communication with.
    ///   - sessionContext: The context of the current session, providing user-specific information.
    ///   - sessionDelegate: The `PQSSessionDelegate` for managing session-related tasks.
    ///   - cache: The `PQSSessionStore` used for caching communication models.
    ///   - receiver: The `EventReceiver` that will handle events related to communication updates.
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///   - logger: The logger for logging events and debugging information.
    ///
    /// - Throws:
    ///   - `EventErrors.invalidSecretName` if the provided secret name matches the current user's secret name.
    ///   - Any error that may occur during the process, such as issues with updating or creating the communication model.
    func sendCommunicationSynchronization(
        contact secretName: String,
        sessionContext: SessionContext,
        sessionDelegate: PQSSessionDelegate,
        cache: PQSSessionStore,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws {
        logger.log(level: .debug, message: "Sending communication synchronization to \(secretName)")
        let mySecretName = sessionContext.sessionUser.secretName

        guard secretName != mySecretName else {
            throw EventErrors.invalidSecretName
        }

        guard let sharedIdentifier = try await updateOrCreateCommunication(
            mySecretName: mySecretName,
            theirSecretName: secretName,
            cache: cache,
            receiver: receiver,
            symmetricKey: symmetricKey,
            logger: logger
        ) else {
            return
        }

        try await sessionDelegate.synchronizeCommunication(recipient: .nickname(secretName), sharedIdentifier: sharedIdentifier)
        logger.log(level: .debug, message: "Sent communication synchronization")
    }

    /// Requests a change in the friendship state for a specific contact.
    ///
    /// This method manages the complete lifecycle of friendship state changes, including:
    /// 1. Validates the current friendship state and prevents invalid transitions.
    /// 2. Updates the friendship metadata using the appropriate state management methods.
    /// 3. Retrieves the symmetric key for encryption.
    /// 4. Updates the friendship metadata based on the requested state.
    /// 5. Notifies the receiver delegate of the metadata change.
    /// 6. Updates the contact in the local cache.
    /// 7. Sends a message to the recipient regarding the friendship state change.
    ///
    /// ## State Transitions
    /// The method maps each requested state to the appropriate `FriendshipMetadata` method:
    /// - `.pending` → `resetToPendingState()` - Resets the friendship to initial state
    /// - `.requested` → `setRequestedState()` - Initiates a friendship request
    /// - `.accepted` → `setAcceptedState()` - Accepts a friendship request
    /// - `.blocked`/`.blockedByOther` → `setBlockState(isBlocking: false)` - Blocks the contact
    /// - `.unblocked` → `setAcceptedState()` - Unblocks the contact (resets to accepted)
    /// - `.rejected`/`.rejectedByOther`/`.mutuallyRejected` → `rejectRequest()` - Rejects the request
    ///
    /// - Parameters:
    ///   - state: The desired friendship state to be set for the contact. This can be one of the following:
    ///     - `.pending`: Indicates that a friend request should be revoked or reset.
    ///     - `.requested`: Indicates that a friend request should be sent.
    ///     - `.accepted`: Indicates that a friend request should be accepted.
    ///     - `.rejected`: Indicates that a friend request should be rejected.
    ///     - `.blocked`: Indicates that the contact should be blocked.
    ///     - `.unblocked`: Indicates that the contact should be unblocked.
    ///   - contact: The `Contact` object representing the contact whose friendship state is being changed.
    ///   - cache: The `PQSSessionStore` used for caching contact data.
    ///   - receiver: The `EventReceiver` that will handle contact update events.
    ///   - sessionDelegate: The `PQSSessionDelegate` for managing session-related tasks.
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///   - logger: The logger for logging events and debugging information.
    ///
    /// - Throws:
    ///   - `EventErrors.databaseNotInitialized`: If the cache is not initialized.
    ///   - `EventErrors.sessionNotInitialized`: If the session context is not initialized.
    ///   - `EventErrors.cannotFindContact`: If the specified contact cannot be found in the cache.
    ///   - `EventErrors.propsError`: If there is an error updating the contact's properties.
    ///   - `EventErrors.userIsBlocked`: If the current user is blocked and cannot perform the action.
    ///   - Any other errors that may occur during the process, such as encoding errors or network issues.
    ///
    /// - Important:
    ///   - Ensure that the session and cache are properly initialized before calling this method.
    ///   - The method prevents redundant state changes (e.g., accepting an already accepted friendship).
    ///   - Blocked users cannot perform friendship state changes.
    ///
    /// - Note: This method is asynchronous and should be awaited.
    func requestFriendshipStateChange(
        state: FriendshipMetadata.State,
        contact: Contact,
        cache: PQSSessionStore,
        receiver: EventReceiver,
        sessionDelegate: PQSSessionDelegate,
        symmetricKey: SymmetricKey,
        logger: NeedleTailLogger
    ) async throws {
        logger.log(level: .info, message: "Requesting friendship state change for \(contact.secretName) to state \(state).")

        guard let foundContact = try await cache.fetchContacts().asyncFirst(where: { await $0.props(symmetricKey: symmetricKey)?.secretName == contact.secretName }) else { throw EventErrors.cannotFindContact }

        var currentMetadata: FriendshipMetadata?

        if let friendshipDocument = contact.metadata["friendshipMetadata"] as? Document, !friendshipDocument.isEmpty {
            currentMetadata = try contact.metadata.decode(forKey: "friendshipMetadata")
        }
        if currentMetadata == nil {
            currentMetadata = FriendshipMetadata()
        }

        if currentMetadata?.myState == .blocked {
            throw EventErrors.userIsBlocked
        }

        guard var currentMetadata else { return }

        // Do not allow state changes that are not different, i.e. my state is .accepted cannot acceptFriendRequest() again
        if currentMetadata.ourState == .accepted && state == .accepted { return }
        if currentMetadata.myState == .rejected { return }
        switch state {
        case .pending:
            currentMetadata.resetToPendingState()
        case .requested:
            currentMetadata.setRequestedState()
        case .accepted:
            currentMetadata.setAcceptedState()
        case .blocked, .blockedByOther:
            currentMetadata.setBlockState(isBlocking: false)
        case .unblocked:
            currentMetadata.setAcceptedState()
        case .rejectedByOther, .mutuallyRejected, .rejected:
            currentMetadata.rejectRequest()
        }

        let metadata = try BSONEncoder().encode(currentMetadata)
        let updatedProps = try await foundContact.updatePropsMetadata(
            symmetricKey: symmetricKey,
            metadata: metadata,
            with: "friendshipMetadata"
        )

        try await cache.updateContact(foundContact)

        guard let updatedMetadata = updatedProps?.metadata else {
            throw EventErrors.propsError
        }

        let updatedContact = Contact(
            id: contact.id,
            secretName: contact.secretName,
            configuration: contact.configuration,
            metadata: updatedMetadata
        )

        try await receiver.updateContact(updatedContact)

        func convertBoolToData(_ value: Bool) -> Data {
            // Convert Bool to UInt8 (0 for false, 1 for true)
            let byte: UInt8 = value ? 1 : 0
            // Create Data from the byte
            return Data([byte])
        }

        var blockUnblockData: Data?
        if currentMetadata.theirState == .blocked || currentMetadata.theirState == .blockedByOther {
            blockUnblockData = convertBoolToData(true)
        }

        if currentMetadata.theirState == .unblocked {
            blockUnblockData = convertBoolToData(false)
        }

        // Transport
        try await sessionDelegate.requestFriendshipStateChange(
            recipient: .nickname(contact.secretName),
            blockData: blockUnblockData,
            metadata: ["friendshipMetadata": metadata],
            currentState: currentMetadata.myState
        )
        logger.log(level: .info, message: "Sent Friendship State Change Request")
    }

    /// Updates the delivery state of a message.
    ///
    /// This method updates the delivery state of a given `EncryptedMessage` and optionally allows for external updates.
    /// It retrieves the current properties of the message, updates the delivery state, and saves the updated message
    /// to the cache. If allowed, it also notifies the session delegate of the delivery state change.
    ///
    /// - Parameters:
    ///   - message: The `EncryptedMessage` whose delivery state is being updated.
    ///   - deliveryState: The new delivery state to be set for the message.
    ///   - messageRecipient: The recipient of the message.
    ///   - allowExternalUpdate: A boolean indicating whether external updates are allowed (default is `false`).
    ///   - sessionDelegate: The `PQSSessionDelegate` for managing session-related tasks.
    ///   - cache: The `PQSSessionStore` used for caching messages.
    ///   - receiver: The `EventReceiver` that will handle events related to message updates.
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///
    /// - Throws:
    ///   - `EventErrors.propsError` if there is an issue retrieving the message properties.
    func updateMessageDeliveryState(
        _ message: EncryptedMessage,
        deliveryState: DeliveryState,
        messageRecipient: MessageRecipient,
        allowExternalUpdate: Bool = false,
        sessionDelegate: PQSSessionDelegate,
        cache: PQSSessionStore,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey
    ) async throws {
        guard var props = await message.props(symmetricKey: symmetricKey) else { throw EventErrors.propsError }
        props.deliveryState = deliveryState
        let updatedMessage = try await message.updateMessage(with: props, symmetricKey: symmetricKey)
        try await cache.updateMessage(updatedMessage, symmetricKey: symmetricKey)
        await receiver.updatedMessage(updatedMessage)
        if allowExternalUpdate {
            let metadata = DeliveryStateMetadata(state: props.deliveryState, sharedId: updatedMessage.sharedId)
            let encodedDeliveryState = try BSONEncoder().encode(metadata)
            try await sessionDelegate.deliveryStateChanged(recipient: messageRecipient, metadata: encodedDeliveryState)
        }
    }

    /// Sends a contact created acknowledgment to the specified recipient.
    ///
    /// This method sends an acknowledgment to the specified contact indicating that a new contact has been created.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the recipient contact.
    ///   - sessionDelegate: The `PQSSessionDelegate` for managing session-related tasks.
    ///   - logger: The logger for logging events and debugging information.
    ///
    /// - Throws: Any error that may occur during the process of sending the acknowledgment.
    func sendContactCreatedAcknowledgment(
        recipient secretName: String,
        sessionDelegate: PQSSessionDelegate,
        logger: NeedleTailLogger
    ) async throws {
        logger.log(level: .debug, message: "Sending Contact Created Acknowledgment")
        try await sessionDelegate.contactCreated(recipient: .nickname(secretName))
        logger.log(level: .debug, message: "Sent Contact Created Acknowledgment")
    }

    /// Requests metadata from a specified contact.
    ///
    /// This method sends a request for metadata to the specified contact.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the contact from whom to request metadata.
    ///   - sessionDelegate: The `PQSSessionDelegate` for managing session-related tasks.
    ///   - logger: The logger for logging events and debugging information.
    ///
    /// - Throws: Any error that may occur during the process of requesting metadata.
    func requestMetadata(
        from secretName: String,
        sessionDelegate: PQSSessionDelegate,
        logger: NeedleTailLogger
    ) async throws {
        logger.log(level: .debug, message: "Requesting metadata from \(secretName)")
        try await sessionDelegate.requestMetadata(recipient: .nickname(secretName))
        logger.log(level: .debug, message: "Requested metadata from \(secretName)")
    }

    /// Requests the current user's metadata.
    ///
    /// This method sends a request for the current user's metadata.
    ///
    /// - Parameters:
    ///   - sessionDelegate: The `PQSSessionDelegate` for managing session-related tasks.
    ///   - logger: The logger for logging events and debugging information.
    ///
    /// - Throws: Any error that may occur during the process of requesting metadata.
    func requestMyMetadata(
        sessionDelegate: PQSSessionDelegate,
        logger: NeedleTailLogger
    ) async throws {
        logger.log(level: .debug, message: "Requesting my metadata")
        try await sessionDelegate.requestMetadata(recipient: .personalMessage)
        logger.log(level: .debug, message: "Requested my metadata")
    }

    /// Edits the current message with new text.
    ///
    /// This method updates the text of the specified `EncryptedMessage` and notifies the session delegate of the edit.
    ///
    /// - Parameters:
    ///   - message: The `EncryptedMessage` to be edited.
    ///   - newText: The new text to set for the message.
    ///   - sessionDelegate: The `PQSSessionDelegate` for managing session-related tasks.
    ///   - cache: The `PQSSessionStore` used for caching messages.
    ///   - receiver: The `EventReceiver` that will handle events related to message updates.
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///   - logger: The logger for logging events and debugging information.
    ///
    /// - Throws:
    ///   - Any error that may occur during the process, such as issues with updating the message properties or notifying the session delegate.
    func editCurrentMessage(
        _ message: EncryptedMessage,
        newText: String,
        sessionDelegate: PQSSessionDelegate,
        cache: PQSSessionStore,
        receiver: EventReceiver,
        symmetricKey: SymmetricKey,
        logger _: NeedleTailLogger
    ) async throws {
        guard var props = await message.props(symmetricKey: symmetricKey) else { return }

        props.message.text = newText
        _ = try await message.updateProps(symmetricKey: symmetricKey, props: props)
        let updatedMessage = try await message.updateMessage(with: props, symmetricKey: symmetricKey)

        try await cache.updateMessage(updatedMessage, symmetricKey: symmetricKey)
        await receiver.updatedMessage(updatedMessage)

        let editMetadata = EditMessageMetadata(value: newText, sharedId: message.sharedId, sender: "")
        let metadata = try BSONEncoder().encode(editMetadata)
        try await sessionDelegate.editMessage(recipient: props.message.recipient, metadata: metadata)
    }

    /// Finds a communication model for a specified message recipient.
    ///
    /// This method retrieves the communication model associated with the given message recipient from the cache.
    ///
    /// - Parameters:
    ///   - messageRecipient: The recipient of the message for which to find the communication model.
    ///   - cache: The `PQSSessionStore` used for caching communication models.
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///
    /// - Returns: A `BaseCommunication` instance associated with the specified message recipient.
    /// - Throws:
    ///   - Any error that may occur during the process, such as issues with fetching the communication model.
    func findCommunication(
        for messageRecipient: MessageRecipient,
        cache: PQSSessionStore,
        symmetricKey: SymmetricKey
    ) async throws -> BaseCommunication {
        try await findCommunicationType(
            cache: cache,
            communicationType: messageRecipient,
            symmetricKey: symmetricKey
        )
    }

    /// Finds a communication model of a specific type from the cache.
    ///
    /// This method retrieves the communication model associated with the specified communication type from the cache.
    ///
    /// - Parameters:
    ///   - cache: The `PQSSessionStore` used for caching communication models.
    ///   - communicationType: The type of communication to find (e.g., nickname).
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///
    /// - Returns: A `BaseCommunication` instance associated with the specified communication type.
    /// - Throws:
    ///   - `EventErrors.cannotFindCommunication` if no communication model of the specified type is found.
    func findCommunicationType(
        cache: PQSSessionStore,
        communicationType: MessageRecipient,
        symmetricKey: SymmetricKey
    ) async throws -> BaseCommunication {
        let communications = try await cache.fetchCommunications()
        guard let foundCommunication = await communications.asyncFirst(where: { model in
            do {
                let decrypted = try await model.makeDecryptedModel(of: Communication.self, symmetricKey: symmetricKey)
                return decrypted.communicationType == communicationType
            } catch {
                return false
            }
        }) else {
            throw EventErrors.cannotFindCommunication
        }

        return foundCommunication
    }

    /// Creates a new communication model.
    ///
    /// This method initializes a new `BaseCommunication` instance with the specified recipients, communication type,
    /// and metadata.
    ///
    /// - Parameters:
    ///   - recipients: A set of secret names representing the members of the communication.
    ///   - communicationType: The type of communication (e.g., nickname).
    ///   - metadata: Additional metadata associated with the communication.
    ///   - symmetricKey: The symmetric key used for encryption and decryption of sensitive data.
    ///
    /// - Returns: A newly created `BaseCommunication` instance.
    /// - Throws: Any error that may occur during the creation of the communication model.
    func createCommunicationModel(
        recipients: Set<String>,
        communicationType: MessageRecipient,
        metadata: Document,
        symmetricKey: SymmetricKey
    ) async throws -> BaseCommunication {
        try BaseCommunication(
            id: UUID(),
            props: .init(
                messageCount: 0,
                members: recipients,
                metadata: metadata,
                blockedMembers: [],
                communicationType: communicationType
            ),
            symmetricKey: symmetricKey
        )
    }
}

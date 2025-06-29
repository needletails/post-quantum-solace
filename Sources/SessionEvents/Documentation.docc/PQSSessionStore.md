# ``PQSSessionStore``

A protocol that defines the interface for persistent storage and data management in the Post-Quantum Solace SDK.

## Overview

`PQSSessionStore` provides the interface for all persistent storage operations, including session data, messages, contacts, communications, and jobs. It abstracts the underlying storage mechanism and provides a consistent API for data persistence and retrieval.

## Topics

### Session Context

- ``PQSSessionStore/createLocalSessionContext(_:)``
- ``PQSSessionStore/fetchLocalSessionContext()``
- ``PQSSessionStore/updateLocalSessionContext(_:)``
- ``PQSSessionStore/deleteLocalSessionContext()``

### Device Salt

- ``PQSSessionStore/fetchLocalDeviceSalt(keyData:)``
- ``PQSSessionStore/deleteLocalDeviceSalt()``

### Session Identities

- ``PQSSessionStore/createSessionIdentity(_:)``
- ``PQSSessionStore/fetchSessionIdentities()``
- ``PQSSessionStore/updateSessionIdentity(_:)``
- ``PQSSessionStore/deleteSessionIdentity(_:)``

### Messages

- ``PQSSessionStore/createMessage(_:symmetricKey:)``
- ``PQSSessionStore/fetchMessage(id:)``
- ``PQSSessionStore/fetchMessage(sharedId:)``
- ``PQSSessionStore/updateMessage(_:symmetricKey:)``
- ``PQSSessionStore/deleteMessage(_:)``
- ``PQSSessionStore/fetchMessages(sharedCommunicationId:)``
- ``PQSSessionStore/streamMessages(sharedIdentifier:)``
- ``PQSSessionStore/messageCount(sharedIdentifier:)``

### Contacts

- ``PQSSessionStore/createContact(_:)``
- ``PQSSessionStore/fetchContacts()``
- ``PQSSessionStore/updateContact(_:)``
- ``PQSSessionStore/deleteContact(_:)``

### Communications

- ``PQSSessionStore/createCommunication(_:)``
- ``PQSSessionStore/fetchCommunications()``
- ``PQSSessionStore/updateCommunication(_:)``
- ``PQSSessionStore/deleteCommunication(_:)``

### Jobs

- ``PQSSessionStore/createJob(_:)``
- ``PQSSessionStore/fetchJobs()``
- ``PQSSessionStore/updateJob(_:)``
- ``PQSSessionStore/deleteJob(_:)``

### Media Jobs

- ``PQSSessionStore/createMediaJob(_:)``
- ``PQSSessionStore/fetchAllMediaJobs()``
- ``PQSSessionStore/fetchMediaJob(id:)``
- ``PQSSessionStore/fetchMediaJobs(recipient:symmetricKey:)``
- ``PQSSessionStore/fetchMediaJob(synchronizationIdentifier:symmetricKey:)``
- ``PQSSessionStore/deleteMediaJob(_:)``

## Key Features

- **Persistent Storage**: All data is stored persistently and survives app restarts
- **Encrypted Storage**: Sensitive data is encrypted before storage
- **Thread Safety**: All operations are designed for concurrent access
- **Error Handling**: Comprehensive error handling for storage operations
- **Streaming Support**: Support for streaming large datasets
- **Batch Operations**: Efficient batch operations for multiple items

## Usage

### Basic Implementation

```swift
class DatabaseStore: PQSSessionStore {
    private let database: Database
    
    init(database: Database) {
        self.database = database
    }
    
    func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        // Store encrypted message in database
        try await database.insert(message)
    }
    
    func fetchMessage(id: UUID) async throws -> EncryptedMessage {
        // Retrieve message from database
        return try await database.find(id: id)
    }
    
    // Implement other required methods...
}
```

### Session Context Management

```swift
func createLocalSessionContext(_ data: Data) async throws {
    // Validate the data
    guard !data.isEmpty else {
        throw StoreError.invalidData
    }
    
    // Store the encrypted session context
    let context = SessionContextData(
        id: "local_session",
        data: data,
        createdAt: Date(),
        updatedAt: Date()
    )
    
    try await database.insert(context)
    
    logger.debug("Created local session context")
}

func fetchLocalSessionContext() async throws -> Data {
    // Retrieve the session context
    guard let context = try await database.find(id: "local_session") else {
        throw StoreError.sessionContextNotFound
    }
    
    return context.data
}

func updateLocalSessionContext(_ data: Data) async throws {
    // Update the existing session context
    let context = SessionContextData(
        id: "local_session",
        data: data,
        createdAt: Date(),
        updatedAt: Date()
    )
    
    try await database.update(context)
    
    logger.debug("Updated local session context")
}
```

### Message Management

```swift
func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {
    // Validate the message
    guard message.id != UUID() else {
        throw StoreError.invalidMessageId
    }
    
    // Store the encrypted message
    let messageData = MessageData(
        id: message.id,
        data: message.data,
        communicationId: message.communicationId,
        sessionContextId: message.sessionContextId,
        sharedId: message.sharedId,
        sequenceNumber: message.sequenceNumber,
        createdAt: Date()
    )
    
    try await database.insert(messageData)
    
    logger.debug("Created message with ID: \(message.id)")
}

func fetchMessage(id: UUID) async throws -> EncryptedMessage {
    // Retrieve message from database
    guard let messageData = try await database.find(id: id) else {
        throw StoreError.messageNotFound
    }
    
    // Reconstruct the encrypted message
    let message = EncryptedMessage(
        id: messageData.id,
        communicationId: messageData.communicationId,
        sessionContextId: messageData.sessionContextId,
        sharedId: messageData.sharedId,
        sequenceNumber: messageData.sequenceNumber,
        data: messageData.data
    )
    
    return message
}

func fetchMessages(sharedCommunicationId: UUID) async throws -> [MessageRecord] {
    // Query messages by communication ID
    let messages = try await database.query(
        "SELECT * FROM messages WHERE communication_id = ? ORDER BY sequence_number",
        parameters: [sharedCommunicationId]
    )
    
    return messages.map { MessageRecord(from: $0) }
}
```

### Contact Management

```swift
func createContact(_ contact: ContactModel) async throws {
    // Validate the contact
    guard !contact.name.isEmpty else {
        throw StoreError.invalidContactData
    }
    
    // Store the contact
    let contactData = ContactData(
        id: contact.id,
        name: contact.name,
        metadata: contact.metadata,
        createdAt: Date()
    )
    
    try await database.insert(contactData)
    
    logger.debug("Created contact: \(contact.name)")
}

func fetchContacts() async throws -> [ContactModel] {
    // Retrieve all contacts
    let contactDataList = try await database.query("SELECT * FROM contacts ORDER BY name")
    
    return contactDataList.map { ContactModel(from: $0) }
}

func updateContact(_ contact: ContactModel) async throws {
    // Update the contact
    let contactData = ContactData(
        id: contact.id,
        name: contact.name,
        metadata: contact.metadata,
        updatedAt: Date()
    )
    
    try await database.update(contactData)
    
    logger.debug("Updated contact: \(contact.name)")
}
```

### Communication Management

```swift
func createCommunication(_ communication: BaseCommunication) async throws {
    // Store the communication
    let commData = CommunicationData(
        id: communication.id,
        data: communication.data,
        createdAt: Date()
    )
    
    try await database.insert(commData)
    
    logger.debug("Created communication with ID: \(communication.id)")
}

func fetchCommunications() async throws -> [BaseCommunication] {
    // Retrieve all communications
    let commDataList = try await database.query("SELECT * FROM communications")
    
    return commDataList.map { BaseCommunication(from: $0) }
}
```

### Job Management

```swift
func createJob(_ job: JobModel) async throws {
    // Store the job
    let jobData = JobData(
        id: job.id,
        data: job.data,
        createdAt: Date()
    )
    
    try await database.insert(jobData)
    
    logger.debug("Created job with ID: \(job.id)")
}

func fetchJobs() async throws -> [JobModel] {
    // Retrieve all jobs
    let jobDataList = try await database.query("SELECT * FROM jobs ORDER BY created_at")
    
    return jobDataList.map { JobModel(from: $0) }
}
```

### Streaming Support

```swift
func streamMessages(sharedIdentifier: UUID) async throws -> (AsyncThrowingStream<EncryptedMessage, Error>, AsyncThrowingStream<EncryptedMessage, Error>.Continuation?) {
    // Create a stream for messages
    let (stream, continuation) = AsyncThrowingStream<EncryptedMessage, Error>.makeStream()
    
    // Start streaming messages in background
    Task {
        do {
            let messages = try await database.query(
                "SELECT * FROM messages WHERE communication_id = ? ORDER BY sequence_number",
                parameters: [sharedIdentifier]
            )
            
            for messageData in messages {
                let message = EncryptedMessage(from: messageData)
                continuation.yield(message)
            }
            
            continuation.finish()
        } catch {
            continuation.finish(throwing: error)
        }
    }
    
    return (stream, continuation)
}
```

## Error Handling

Implement comprehensive error handling:

```swift
enum StoreError: Error {
    case invalidData
    case sessionContextNotFound
    case messageNotFound
    case contactNotFound
    case communicationNotFound
    case jobNotFound
    case databaseError(Error)
}

func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {
    do {
        try await database.insert(message)
    } catch DatabaseError.constraintViolation {
        throw StoreError.messageNotFound
    } catch DatabaseError.connectionFailed {
        throw StoreError.databaseError(error)
    } catch {
        throw StoreError.databaseError(error)
    }
}
```

## Performance Considerations

### Database Optimization
- Use appropriate indexes for queries
- Implement connection pooling
- Use batch operations when possible
- Monitor query performance

### Caching
- Implement intelligent caching
- Use appropriate cache invalidation
- Monitor cache hit rates
- Implement cache size limits

### Memory Management
- Use streaming for large datasets
- Implement pagination for large queries
- Avoid loading entire datasets into memory
- Monitor memory usage

## Security Considerations

### Data Encryption
- Encrypt sensitive data before storage
- Use strong encryption keys
- Implement proper key management
- Validate encrypted data integrity

### Access Control
- Implement proper access controls
- Validate all input data
- Use parameterized queries
- Monitor for unauthorized access

### Data Validation
- Validate all data before storage
- Implement proper error handling
- Use type-safe data structures
- Monitor for data corruption

## Integration with Session

The `PQSSessionStore` is used by the `SessionCache`:

```swift
let store = DatabaseStore(database: myDatabase)
let cache = SessionCache(store: store)

await session.setDatabaseDelegate(conformer: cache)
```

## Best Practices

### Database Design
- Use appropriate data types
- Implement proper constraints
- Use indexes for performance
- Implement data validation

### Error Handling
- Implement comprehensive error handling
- Provide meaningful error messages
- Log errors for debugging
- Implement retry mechanisms

### Performance
- Optimize database queries
- Implement proper caching
- Use batch operations
- Monitor performance metrics

### Security
- Encrypt sensitive data
- Implement access controls
- Validate all input
- Monitor for security threats 
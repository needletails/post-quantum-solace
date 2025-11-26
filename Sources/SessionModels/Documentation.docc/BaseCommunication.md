# ``BaseCommunication``

A base class for communication models that provides encryption and decryption capabilities.

## Overview

`BaseCommunication` serves as the foundation for secure communication by encrypting all sensitive communication data using symmetric key cryptography. It conforms to `Codable` for serialization and uses `@unchecked Sendable` since the cryptographic operations are thread-safe.

## Topics

### Essentials

- ``BaseCommunication/init(id:props:symmetricKey:)``
- ``BaseCommunication/id``
- ``BaseCommunication/data``

### Properties

- ``BaseCommunication/props(symmetricKey:)``
- ``BaseCommunication/UnwrappedProps``

### Communication Protocol

- ``CommunicationProtocol``
- ``Communication``

### Security

- ``BaseCommunication/SecureModelProtocol``
- ``BaseCommunication/CryptoError``

## Key Features

- **Encrypted Storage**: All communication data is encrypted at rest
- **Thread Safety**: Cryptographic operations are thread-safe
- **Serialization**: Supports encoding/decoding with obfuscated field names
- **Protocol Conformance**: Implements `CommunicationProtocol` for interoperability
- **Graceful Error Handling**: Returns `nil` instead of throwing for decryption failures

## Security Considerations

- All communication data is encrypted using the provided symmetric key
- Only metadata required for database operations remains unencrypted
- Coding keys are obfuscated to prevent easy identification of data structure
- Keys should be managed securely and not persisted alongside encrypted data

## Usage

### Creating a Communication Model

```swift
let communication = try BaseCommunication(
    id: UUID(),
    props: .init(
        messageCount: 0,
        members: ["alice", "bob"],
        metadata: [:],
        blockedMembers: [],
        communicationType: .nickname("alice")
    ),
    symmetricKey: symmetricKey
)
```

### Accessing Communication Properties

```swift
// Access decrypted properties
if let props = await communication.props(symmetricKey: symmetricKey) {
    print("Members: \(props.members)")
    print("Message count: \(props.messageCount)")
    print("Administrator: \(props.administrator ?? "None")")
    print("Communication type: \(props.communicationType)")
}
```

### Working with Communication Types

```swift
if let props = await communication.props(symmetricKey: symmetricKey) {
    switch props.communicationType {
    case .personalMessage:
        // Handle personal messages
        print("Personal communication")
        
    case .nickname(let nickname):
        // Handle nickname-based communication
        print("Communication with: \(nickname)")
        
    case .channel(let channelId):
        // Handle channel communication
        print("Channel communication: \(channelId)")
        
    case .broadcast:
        // Handle broadcast communication
        print("Broadcast communication")
    }
}
```

### Updating Communication Properties

```swift
if var props = await communication.props(symmetricKey: symmetricKey) {
    // Update properties
    props.messageCount += 1
    props.members.insert("charlie")
    props.metadata["lastActivity"] = Date()
    
    // Update the communication model
    _ = try await communication.updateProps(symmetricKey: symmetricKey, props: props)
}
```

## Data Structure

### UnwrappedProps

The `UnwrappedProps` struct contains all the decrypted properties:

```swift
public struct UnwrappedProps: Codable & Sendable {
    public var sharedId: UUID?
    public var messageCount: Int
    public var administrator: String?
    public var operators: Set<String>?
    public var members: Set<String>
    public let blockedMembers: Set<String>
    public var metadata: Document
    public var communicationType: MessageRecipient
}
```

### Communication Types

- **Personal**: Messages sent to the user's own devices
- **Nickname**: Private messages between two users
- **Channel**: Group messages with multiple participants
- **Broadcast**: System-wide messages

## Error Handling

The class handles decryption failures gracefully. All cryptographic errors conform to `LocalizedError` and provide detailed information:

```swift
do {
    try await communication.updateProps(symmetricKey: symmetricKey, props: newProps)
} catch let error as CryptoError {
    // Access localized error information
    if let localizedError = error as? LocalizedError {
        print("Error: \(localizedError.errorDescription ?? "")")
        if let reason = localizedError.failureReason {
            print("Reason: \(reason)")
        }
        if let suggestion = localizedError.recoverySuggestion {
            print("Suggestion: \(suggestion)")
        }
    }
    
    // Handle specific error types
    switch error {
    case .encryptionFailed:
        // Handle encryption failure
        logger.error("Failed to encrypt communication properties")
    case .decryptionFailed:
        // Handle decryption failure
        logger.error("Failed to decrypt communication properties")
    case .propsError:
        // Handle property access error
        logger.error("Failed to access communication properties")
    }
} catch {
    // Handle other errors
    logger.error("Unexpected error: \(error)")
}

// Graceful handling with nil return
if let props = await communication.props(symmetricKey: symmetricKey) {
    // Use decrypted properties
} else {
    // Handle decryption failure
    logger.error("Failed to decrypt communication properties")
    // Implement fallback behavior
}
```

### Error Types

- **`CryptoError.encryptionFailed`**: Encryption operation failed
- **`CryptoError.decryptionFailed`**: Decryption operation failed
- **`CryptoError.propsError`**: Error accessing encrypted properties

All errors provide `errorDescription`, `failureReason`, and `recoverySuggestion` through `LocalizedError` conformance.

## Integration with Other Components

### Session Cache
Communications are typically stored and retrieved through the `SessionCache`:

```swift
// Store a communication
try await cache.createCommunication(communication)

// Retrieve communications
let communications = try await cache.fetchCommunications()

// Update a communication
try await cache.updateCommunication(communication)
```

### Task Processor
Communications are used by the `TaskProcessor` for message routing:

```swift
// Find communication by type
let communication = try await taskProcessor.findCommunicationType(
    cache: cache,
    communicationType: .nickname("bob"),
    session: session
)

// Create communication model
let newCommunication = try await taskProcessor.createCommunicationModel(
    recipients: ["alice", "bob"],
    communicationType: .nickname("alice"),
    metadata: [:],
    symmetricKey: symmetricKey
)
```

## Best Practices

### Security
- Use strong symmetric keys for encryption
- Never expose decrypted communication data
- Implement proper key management
- Secure storage of sensitive data

### Performance
- Cache frequently accessed properties
- Minimize decryption operations
- Use batch operations when possible
- Monitor memory usage

### Error Handling
- Handle decryption failures gracefully
- Implement proper fallback mechanisms
- Log errors for debugging
- Provide user-friendly error messages

## Thread Safety

The `BaseCommunication` class is designed for concurrent access:
- **Sendable Conformance**: Safe to pass between concurrent contexts
- **Thread-Safe Operations**: Cryptographic operations are thread-safe
- **Immutable Design**: Most properties are immutable after creation
- **Controlled Updates**: Updates are managed through controlled methods 
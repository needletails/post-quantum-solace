# ``EncryptedMessage``

A model representing an encrypted message with metadata and cryptographic properties.

## Overview

`EncryptedMessage` encapsulates a complete encrypted message including its content, metadata, sender information, and cryptographic context. It provides methods for encrypting and decrypting message properties while maintaining the security of the underlying cryptographic operations.

## Topics

### Essentials

- ``EncryptedMessage/init(id:communicationId:sessionContextId:sharedId:sequenceNumber:props:symmetricKey:)``
- ``EncryptedMessage/id``
- ``EncryptedMessage/communicationId``
- ``EncryptedMessage/sessionContextId``
- ``EncryptedMessage/sharedId``
- ``EncryptedMessage/sequenceNumber``
- ``EncryptedMessage/data``

### Message Properties

- ``EncryptedMessage/props(symmetricKey:)``
- ``EncryptedMessage/updateProps(symmetricKey:props:)``
- ``EncryptedMessage/makeDecryptedModel(of:symmetricKey:)``

### Message Metadata

- ``EncryptedMessage/MessageProps``
- ``EncryptedMessage/DeliveryState``

## Key Features

- **End-to-End Encryption**: All message content is encrypted with session keys
- **Metadata Encryption**: Message metadata is encrypted separately from content
- **Sender Information**: Includes sender identity and device information
- **Delivery Tracking**: Tracks message delivery state and timestamps
- **Sequence Management**: Maintains message ordering within conversations
- **Flexible Properties**: Supports custom metadata and properties

## Security Considerations

- **Encrypted Storage**: All sensitive data is encrypted before storage
- **Key Management**: Uses session-specific symmetric keys for encryption
- **Metadata Protection**: Message metadata is encrypted to prevent information leakage
- **Sender Verification**: Sender information is cryptographically verified
- **Forward Secrecy**: Messages are protected by forward-secret key exchange

## Usage

### Creating an Encrypted Message

```swift
// Create message properties
let messageProps = EncryptedMessage.MessageProps(
    id: UUID(),
    base: communication,
    sentDate: Date(),
    deliveryState: .sending,
    message: cryptoMessage,
    senderSecretName: senderName,
    senderDeviceId: deviceId
)

// Create the encrypted message
let encryptedMessage = try EncryptedMessage(
    id: UUID(),
    communicationId: communication.id,
    sessionContextId: sessionContext.id,
    sharedId: sharedMessageId,
    sequenceNumber: nextSequenceNumber,
    props: messageProps,
    symmetricKey: sessionKey
)
```

### Accessing Message Properties

```swift
// Get decrypted message properties
guard let props = await encryptedMessage.props(symmetricKey: sessionKey) else {
    throw MessageError.decryptionFailed
}

// Access message content
let text = props.message.text
let sender = props.senderSecretName
let timestamp = props.sentDate
let deliveryState = props.deliveryState

// Access communication information
let communication = props.base
let messageId = props.id
```

### Updating Message Properties

```swift
// Get current properties
guard var props = await encryptedMessage.props(symmetricKey: sessionKey) else {
    throw MessageError.decryptionFailed
}

// Update delivery state
props.deliveryState = .delivered

// Update the message
let updatedMessage = try await encryptedMessage.updateProps(
    symmetricKey: sessionKey,
    props: props
)
```

### Working with Message Content

```swift
// Access the underlying crypto message
guard let props = await encryptedMessage.props(symmetricKey: sessionKey) else {
    throw MessageError.decryptionFailed
}

let cryptoMessage = props.message

// Access message content
let text = cryptoMessage.text
let recipient = cryptoMessage.recipient
let metadata = cryptoMessage.metadata

// Process message based on type
switch recipient {
case .nickname(let nickname):
    await handlePrivateMessage(text, from: props.senderSecretName)
case .channel(let channelId):
    await handleChannelMessage(text, in: channelId)
case .personalMessage:
    await handlePersonalMessage(text)
case .broadcast:
    await handleBroadcastMessage(text)
}
```

### Message Delivery Tracking

```swift
// Check delivery state
guard let props = await encryptedMessage.props(symmetricKey: sessionKey) else {
    throw MessageError.decryptionFailed
}

switch props.deliveryState {
case .sending:
    await showSendingIndicator()
case .sent:
    await showSentIndicator()
case .delivered:
    await showDeliveredIndicator()
case .read:
    await showReadIndicator()
case .failed:
    await showFailedIndicator()
}
```

### Message Metadata

```swift
// Access message metadata
guard let props = await encryptedMessage.props(symmetricKey: sessionKey) else {
    throw MessageError.decryptionFailed
}

// Get sender information
let senderName = props.senderSecretName
let senderDevice = props.senderDeviceId

// Get timing information
let sentDate = props.sentDate
let isRecent = Date().timeIntervalSince(sentDate) < 300 // 5 minutes

// Get communication context
let communication = props.base
let messageId = props.id
```

## Data Structure

### MessageProps

```swift
public struct MessageProps: Codable & Sendable {
    public let id: UUID
    public let base: BaseCommunication
    public let sentDate: Date
    public let deliveryState: DeliveryState
    public let message: CryptoMessage
    public let senderSecretName: String
    public let senderDeviceId: UUID
}
```

### DeliveryState

```swift
public enum DeliveryState: String, Codable, CaseIterable {
    case sending
    case sent
    case delivered
    case read
    case failed
}
```

## Message Lifecycle

### Message Creation
1. **Content Creation**: Create the plaintext message content
2. **Property Assembly**: Assemble message properties with metadata
3. **Encryption**: Encrypt properties with session symmetric key
4. **Storage**: Store encrypted message in database

### Message Processing
1. **Retrieval**: Retrieve encrypted message from storage
2. **Decryption**: Decrypt message properties with session key
3. **Validation**: Validate message content and metadata
4. **Processing**: Process message based on type and content

### Message Updates
1. **Property Access**: Access current message properties
2. **Modification**: Modify properties as needed
3. **Re-encryption**: Re-encrypt updated properties
4. **Storage Update**: Update stored message with new data

## Integration with Session

The `EncryptedMessage` is used throughout the session system:

```swift
// Create message during outbound processing
let message = try await taskProcessor.createOutboundMessageModel(
    message: cryptoMessage,
    communication: communication,
    session: session,
    symmetricKey: sessionKey,
    members: recipients,
    sharedId: sharedId
)

// Store message in cache
try await cache.createMessage(message, symmetricKey: sessionKey)

// Notify receiver delegate
await session.receiverDelegate?.createdMessage(message)
```

## Best Practices

### Security
- Always use strong session keys for encryption
- Validate message content before processing
- Verify sender information when possible
- Handle decryption failures gracefully

### Performance
- Cache decrypted properties when appropriate
- Use efficient encryption/decryption methods
- Minimize property updates to reduce re-encryption
- Implement proper cleanup for sensitive data

### Error Handling
- Implement comprehensive error handling
- Provide meaningful error messages
- Log errors for debugging
- Implement fallback mechanisms

### Memory Management
- Avoid retaining large message content in memory
- Use weak references when appropriate
- Implement proper cleanup
- Monitor memory usage

## Error Handling

Implement proper error handling for message operations:

```swift
func processMessage(_ message: EncryptedMessage) async {
    do {
        guard let props = await message.props(symmetricKey: sessionKey) else {
            throw MessageError.decryptionFailed
        }
        
        // Process the message
        await handleMessage(props)
        
    } catch MessageError.decryptionFailed {
        logger.error("Failed to decrypt message: \(message.id)")
        await showDecryptionError()
        
    } catch {
        logger.error("Failed to process message: \(error)")
        await showProcessingError()
    }
}
```

## Thread Safety

The `EncryptedMessage` struct is designed for concurrent access:
- **Sendable Conformance**: Safe to pass between concurrent contexts
- **Immutable Design**: Core properties are immutable after creation
- **Thread-Safe Operations**: Encryption/decryption operations are thread-safe
- **No Mutable State**: No internal mutable state that could cause race conditions

## Performance Considerations

### Encryption Overhead
- Encryption/decryption operations are computationally expensive
- Cache decrypted properties when possible
- Minimize property updates to reduce re-encryption
- Use efficient cryptographic libraries

### Memory Usage
- Encrypted messages can be large
- Implement streaming for large messages
- Use appropriate data structures
- Monitor memory usage during processing

### Storage Optimization
- Use efficient storage formats
- Implement compression when appropriate
- Use appropriate indexing for queries
- Monitor storage performance 
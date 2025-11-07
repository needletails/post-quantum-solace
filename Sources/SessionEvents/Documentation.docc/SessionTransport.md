# ``SessionTransport``

A protocol that defines the interface for network communication and key distribution in the Post-Quantum Solace SDK.

## Overview

`SessionTransport` is responsible for handling all network-level communication, including message transmission, key distribution, user configuration management, and one-time key operations. It provides the bridge between the cryptographic session layer and the actual network infrastructure.

## Topics

### Message Transmission

- ``SessionTransport/sendMessage(_:metadata:)``

### User Configuration

- ``SessionTransport/findConfiguration(for:)``
- ``SessionTransport/publishUserConfiguration(_:recipient:)``

### One-Time Key Management

- ``SessionTransport/fetchOneTimeKeys(for:deviceId:)``
- ``SessionTransport/fetchOneTimeKeyIdentities(for:deviceId:type:)``
- ``SessionTransport/updateOneTimeKeys(for:deviceId:keys:)``
- ``SessionTransport/updateOneTimeMLKEMKeys(for:deviceId:keys:)``
- ``SessionTransport/deleteOneTimeKeys(for:with:type:)``
- ``SessionTransport/batchDeleteOneTimeKeys(for:with:type:)``

### Key Rotation

- ``SessionTransport/publishRotatedKeys(for:deviceId:rotated:)``

## Key Features

- **Message Routing**: Send encrypted messages to specific recipients
- **Key Distribution**: Manage one-time key upload, download, and deletion
- **User Configuration**: Handle user configuration publishing and retrieval
- **Key Rotation**: Support for key rotation and compromise recovery
- **Network Abstraction**: Abstract away specific network implementation details

## Usage

### Basic Implementation

```swift
class NetworkTransport: SessionTransport {
    func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {
        // Send message over network
        try await networkService.send(message, to: metadata.secretName)
    }
    
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        // Fetch user configuration from server
        return try await apiService.getUserConfiguration(secretName)
    }
    
    func publishUserConfiguration(_ configuration: UserConfiguration, recipient: UUID) async throws {
        // Publish configuration to server
        try await apiService.publishConfiguration(configuration, for: recipient)
    }
    
    // Implement other required methods...
}
```

### Message Transmission

```swift
func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {
    // Extract recipient information
    let recipient = metadata.secretName
    let deviceId = metadata.deviceId
    let sharedMessageId = metadata.sharedMessageId
    
    // Prepare network payload
    let payload = MessagePayload(
        message: message,
        recipient: recipient,
        deviceId: deviceId,
        sharedMessageId: sharedMessageId,
        transportMetadata: metadata.transportMetadata
    )
    
    // Send over network
    try await networkService.send(payload)
    
    // Log for debugging
    logger.debug("Sent message to \(recipient) (device: \(deviceId))")
}
```

### One-Time Key Management

```swift
func updateOneTimeKeys(for secretName: String, deviceId: String, keys: [UserConfiguration.SignedOneTimePublicKey]) async throws {
    // Upload new one-time keys to server
    let request = OneTimeKeyUpdateRequest(
        secretName: secretName,
        deviceId: deviceId,
        keys: keys
    )
    
    try await apiService.uploadOneTimeKeys(request)
    
    logger.debug("Uploaded \(keys.count) one-time keys for \(secretName)")
}

func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> [UserConfiguration.SignedOneTimePublicKey] {
    // Fetch one-time keys from server
    let keys = try await apiService.fetchOneTimeKeys(secretName: secretName, deviceId: deviceId)
    
    logger.debug("Fetched \(keys.count) one-time keys for \(secretName)")
    return keys
}

func deleteOneTimeKeys(for secretName: String, with keyId: String, type: KeysType) async throws {
    // Delete specific one-time key
    try await apiService.deleteOneTimeKey(
        secretName: secretName,
        keyId: keyId,
        type: type
    )
    
    logger.debug("Deleted one-time key \(keyId) for \(secretName)")
}
```

### User Configuration Management

```swift
func findConfiguration(for secretName: String) async throws -> UserConfiguration {
    // Fetch user configuration from server
    let configuration = try await apiService.getUserConfiguration(secretName)
    
    // Validate configuration
    guard configuration.isValid else {
        throw TransportError.invalidConfiguration
    }
    
    logger.debug("Found configuration for \(secretName)")
    return configuration
}

func publishUserConfiguration(_ configuration: UserConfiguration, recipient: UUID) async throws {
    // Validate configuration before publishing
    guard configuration.isValid else {
        throw TransportError.invalidConfiguration
    }
    
    // Publish to server
    try await apiService.publishConfiguration(configuration, for: recipient)
    
    logger.debug("Published configuration for recipient \(recipient)")
}
```

## Network Considerations

### Message Delivery
- Implement reliable message delivery
- Handle network failures gracefully
- Provide delivery confirmation when possible
- Implement retry mechanisms for failed deliveries

### Key Management
- Ensure secure transmission of keys
- Implement proper key validation
- Handle key conflicts and updates
- Provide key availability guarantees

### Error Handling
- Implement comprehensive error handling
- Provide meaningful error messages
- Handle network timeouts appropriately
- Implement fallback mechanisms

## Security Considerations

### Message Security
- Ensure end-to-end encryption
- Validate message signatures
- Prevent message tampering
- Implement proper authentication

### Key Security
- Secure key transmission
- Validate key authenticity
- Prevent key reuse
- Implement key rotation

### Network Security
- Use secure communication protocols
- Implement proper authentication
- Prevent man-in-the-middle attacks
- Validate server certificates

## Performance Optimization

### Connection Management
- Implement connection pooling
- Use persistent connections when possible
- Handle connection failures gracefully
- Implement connection health checks

### Caching
- Cache frequently accessed configurations
- Implement intelligent key caching
- Use appropriate cache invalidation
- Monitor cache performance

### Batch Operations
- Batch key operations when possible
- Implement efficient bulk operations
- Use appropriate batch sizes
- Monitor batch operation performance

## Error Handling

Implement comprehensive error handling:

```swift
func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {
    do {
        try await networkService.send(message, to: metadata.secretName)
    } catch NetworkError.timeout {
        // Handle timeout
        throw TransportError.messageTimeout
    } catch NetworkError.connectionFailed {
        // Handle connection failure
        throw TransportError.connectionFailed
    } catch {
        // Handle other errors
        throw TransportError.sendFailed(error)
    }
}
```

## Integration with Session

The `SessionTransport` is set on the main session:

```swift
let session = PQSSession.shared
await session.setTransportDelegate(conformer: NetworkTransport())
```

## Best Practices

### Network Implementation
- Use reliable network libraries
- Implement proper error handling
- Handle network state changes
- Monitor network performance

### Security Implementation
- Use secure communication protocols
- Implement proper authentication
- Validate all network responses
- Monitor for security threats

### Performance Implementation
- Optimize network requests
- Implement proper caching
- Use efficient data formats
- Monitor performance metrics

### Error Recovery
- Implement retry mechanisms
- Provide fallback options
- Handle partial failures gracefully
- Log errors for debugging 

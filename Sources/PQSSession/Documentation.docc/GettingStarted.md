# Getting Started

Learn how to integrate the Post-Quantum Solace SDK into your application.

## Overview

The Post-Quantum Solace SDK provides a comprehensive solution for secure messaging with both classical and post-quantum cryptography. This guide will walk you through the essential steps to get started.

## Prerequisites

- iOS 15.0+ / macOS 12.0+
- Swift 5.5+
- Xcode 13.0+

## Installation

### Swift Package Manager

Add the Post-Quantum Solace SDK to your project:

```swift
dependencies: [
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "1.0.0")
]
```

### Import the SDK

```swift
import PostQuantumSolace
```

## Basic Setup

### 1. Initialize the Session

The SDK uses a singleton pattern for session management:

```swift
let session = PQSSession.shared
```

### 2. Set Up Delegates

Configure the required delegates for your application:

```swift
// Set up transport delegate for network communication
await session.setTransportDelegate(conformer: myTransport)

// Set up database delegate for persistent storage
await session.setDatabaseDelegate(conformer: myStore)

// Set up receiver delegate for event handling
session.setReceiverDelegate(conformer: myReceiver)
```

### 3. Create a Session

Create a new user session:

```swift
try await session.createSession(
    secretName: "alice",
    appPassword: "securePassword",
    createInitialTransport: {
        // Set up your transport layer here
        try await setupNetworkTransport()
    }
)
```

### 4. Start the Session

Start the session with the application password:

```swift
try await session.startSession(appPassword: "securePassword")
```

## Implementing Required Protocols

### SessionTransport

Handle network communication:

```swift
class NetworkTransport: SessionTransport {
    func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {
        // Send message over your network
        try await networkService.send(message, to: metadata.secretName)
    }
    
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        // Fetch user configuration from your server
        return try await apiService.getUserConfiguration(secretName)
    }
    
    // Implement other required methods...
}
```

### PQSSessionStore

Handle persistent storage:

```swift
class DatabaseStore: PQSSessionStore {
    func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        // Store encrypted message in your database
        try await database.insert(message)
    }
    
    func fetchMessage(id: UUID) async throws -> EncryptedMessage {
        // Retrieve message from your database
        return try await database.find(id: id)
    }
    
    // Implement other required methods...
}
```

### EventReceiver

Handle application events:

```swift
class AppEventReceiver: EventReceiver {
    func createdMessage(_ message: EncryptedMessage) async {
        // Handle new message
        await updateUI(with: message)
    }
    
    func updatedCommunication(_ model: BaseCommunication, members: Set<String>) async {
        // Handle communication update
        await refreshChannelList()
    }
    
    // Implement other required methods...
}
```

## Sending Messages

### Text Messages

```swift
try await session.writeTextMessage(
    recipient: .nickname("bob"),
    text: "Hello, world!",
    metadata: ["timestamp": Date()],
    destructionTime: 3600 // Self-destruct after 1 hour
)
```

### Different Recipient Types

```swift
// Personal message (to your own devices)
try await session.writeTextMessage(
    recipient: .personalMessage,
    text: "Note to self",
    metadata: [:]
)

// Private message
try await session.writeTextMessage(
    recipient: .nickname("bob"),
    text: "Private message",
    metadata: [:]
)

// Channel message
try await session.writeTextMessage(
    recipient: .channel("general"),
    text: "Channel message",
    metadata: [:]
)
```

## Receiving Messages

Messages are automatically received and processed through the `EventReceiver`:

```swift
class AppEventReceiver: EventReceiver {
    func createdMessage(_ message: EncryptedMessage) async {
        // Decrypt and display the message
        if let props = await message.props(symmetricKey: sessionKey) {
            await displayMessage(props.message.text, from: props.senderSecretName)
        }
    }
}
```

## Key Management

### Automatic Key Rotation

The SDK automatically manages key rotation:

```swift
// Keys are rotated automatically, but you can trigger manual rotation
try await session.rotateKeysOnPotentialCompromise()

// Check if PQ-KEM keys need rotation
if try await session.rotatePQKemKeysIfNeeded() {
    print("PQ-KEM keys were rotated")
}
```

### One-Time Key Management

```swift
// Refresh one-time keys when needed
await session.refreshOneTimeKeysTask()
await session.refreshKyberOneTimeKeysTask()
```

## Device Management

### Linking Devices

```swift
// Create a cryptographic bundle for device linking
let bundle = try await session.createDeviceCryptographicBundle(isMaster: false)

// Link the device
try await session.linkDevice(bundle: bundle, password: "devicePassword")
```

### Device Configuration

```swift
// Update user configuration with new devices
try await session.updateUserConfiguration([newDeviceConfig])

// Update one-time keys
try await session.updateUseroneTimePublicKeys(newKeys)
```

## Error Handling

The SDK provides comprehensive error handling:

```swift
do {
    try await session.writeTextMessage(...)
} catch let error as PQSSession.SessionErrors {
    switch error {
    case .sessionNotInitialized:
        // Handle session setup issues
        print("Session not properly initialized")
        
    case .databaseNotInitialized:
        // Handle storage issues
        print("Database not configured")
        
    case .transportNotInitialized:
        // Handle network issues
        print("Transport layer not ready")
        
    case .invalidSignature:
        // Handle cryptographic verification failures
        print("Message signature verification failed")
        
    default:
        // Handle other errors
        print("Unexpected error: \(error)")
    }
}
```

## Best Practices

### Security

- Use strong application passwords
- Implement proper key rotation
- Monitor for potential compromises
- Secure storage of sensitive data

### Performance

- Use dedicated queues for cryptographic operations
- Implement proper caching strategies
- Handle errors gracefully
- Monitor memory usage

### Integration

- Implement proper error handling
- Use async/await for all operations
- Follow the delegate pattern
- Test thoroughly with different scenarios

## Next Steps

- Explore the [API Reference](doc:APIReference) for detailed documentation
- Check out [Examples](doc:Examples) for common use cases
- Read the [Security Guide](doc:SecurityGuide) for best practices
- Review [Troubleshooting](doc:Troubleshooting) for common issues 
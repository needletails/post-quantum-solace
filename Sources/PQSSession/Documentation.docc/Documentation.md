# Post-Quantum Solace SDK

A secure, post-quantum cryptographic messaging SDK with end-to-end encryption.

## Overview

The Post-Quantum Solace SDK provides a comprehensive solution for secure messaging with both classical (Curve25519) and post-quantum (MLKEM1024) cryptography. Built with Swift's modern concurrency features, it offers forward secrecy, device management, and automatic key rotation.

## Topics

### Getting Started

- <doc:GettingStarted>
- <doc:Tutorials>
- <doc:Installation>

### Core Modules

- ``PQSSession``
- ``TaskProcessor``
- ``SessionCache``
- ``SessionEvents``
- ``SessionModels``

### Key Features

- **Post-Quantum Security**: MLKEM1024 for long-term security
- **Forward Secrecy**: Double Ratchet protocol implementation
- **Device Management**: Master/child device support
- **Automatic Key Rotation**: Compromise recovery and key freshness
- **End-to-End Encryption**: All communications are encrypted
- **Thread Safety**: Actor-based concurrency model

### Architecture

The SDK is built around several core components:

#### PQSSession
The main session manager that orchestrates all cryptographic operations and manages the session lifecycle.

#### TaskProcessor
Handles asynchronous encryption/decryption tasks using dedicated cryptographic executors.

#### SessionCache
Provides two-tier caching with in-memory and persistent storage for optimal performance.

#### SessionEvents
Event-driven system for handling messages, contacts, and communication updates.

#### SessionModels
Core data structures with built-in encryption and secure serialization.

## Quick Start

```swift
import PostQuantumSolace

// Initialize the session
let session = PQSSession.shared

// Set up delegates
await session.setTransportDelegate(conformer: myTransport)
await session.setDatabaseDelegate(conformer: myStore)
session.setReceiverDelegate(conformer: myReceiver)

// Create a new session
try await session.createSession(
    secretName: "alice",
    appPassword: "securePassword",
    createInitialTransport: setupTransport
)

// Start the session
try await session.startSession(appPassword: "securePassword")

// Send a message
try await session.writeTextMessage(
    recipient: .nickname("bob"),
    text: "Hello, world!",
    metadata: ["timestamp": Date()],
    destructionTime: 3600
)
```

## Security Model

### Cryptographic Protocols
- **Double Ratchet**: For forward secrecy and message ordering
- **MLKEM1024**: Post-quantum key exchange
- **Curve25519**: Classical cryptography for immediate security
- **AES-GCM**: Symmetric encryption for message content

### Key Management
- **One-Time Keys**: Pre-generated for immediate communication
- **Long-Term Keys**: For persistent identity verification
- **Automatic Rotation**: Scheduled and compromise-based key rotation
- **Device Verification**: Signed device configurations

### Privacy Features
- **Secret Names**: Privacy-preserving user identification
- **Device Isolation**: Separate cryptographic contexts per device
- **Metadata Encryption**: All sensitive metadata is encrypted
- **Forward Secrecy**: Keys are rotated after each message

## Performance

- **Async/Await**: Modern Swift concurrency throughout
- **Actor Isolation**: Thread-safe concurrent access
- **Dedicated Executors**: Cryptographic operations on separate queues
- **Efficient Caching**: Two-tier cache system for optimal performance
- **Batch Operations**: Key generation and updates in batches

## Error Handling

The SDK provides comprehensive error handling with detailed error types:

```swift
do {
    try await session.writeTextMessage(...)
} catch let error as PQSSession.SessionErrors {
    switch error {
    case .sessionNotInitialized:
        // Handle session setup issues
    case .databaseNotInitialized:
        // Handle storage issues
    case .transportNotInitialized:
        // Handle network issues
    default:
        // Handle other errors
    }
}
```

## Thread Safety

All public APIs are designed for concurrent access:
- **Actor-based**: Core components use Swift actors
- **Sendable**: All data types conform to Sendable
- **Isolation**: Proper isolation for mutable state
- **Async**: All operations are asynchronous

## Integration

### Transport Layer
Implement `SessionTransport` to provide network communication:
- Message sending and receiving
- Key distribution and management
- User configuration synchronization

### Storage Layer
Implement `PQSSessionStore` to provide persistent storage:
- Encrypted message storage
- Contact and communication management
- Session state persistence

### Event Handling
Implement `EventReceiver` to handle application events:
- Message creation and updates
- Contact management
- Communication state changes

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

## Support

For more information, see:
- <doc:APIReference>
- <doc:Examples>
- <doc:Troubleshooting>
- <doc:SecurityGuide> 

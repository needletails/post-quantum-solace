<img src="post_quantum_solace.svg" alt="Post Quantum Solace" width="200" />

# Post-Quantum Solace

[![Swift](https://img.shields.io/badge/Swift-6.1+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-iOS%2018%2B%20%7C%20macOS%2015%2B%20%7C%20Linux%20%7C%20Android-blue.svg)](https://developer.apple.com)
[![Version](https://img.shields.io/badge/Version-2.0.0-blue.svg)](https://github.com/needletails/post-quantum-solace)
[![License](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](LICENSE)

A secure, post-quantum cryptographic messaging SDK with end-to-end encryption, built for the quantum-resistant future.

## 🌟 Features

- **🔐 Post-Quantum Security**: MLKEM1024 for long-term security against quantum attacks
- **🔄 Forward Secrecy**: Double Ratchet protocol implementation for perfect forward secrecy
- **📱 Device Management**: Master/child device support with secure linking
- **🔄 Automatic Key Rotation**: Compromise recovery and key freshness
- **🔒 End-to-End Encryption**: All communications are encrypted
- **⚡ Thread Safety**: Actor-based concurrency model for modern Swift
- **🎯 Privacy-First**: Secret names and metadata encryption
- **📦 Self-Destructing Messages**: Configurable message expiration

## 📋 Requirements

- **iOS**: 18.0+
- **macOS**: 15.0+
- **Linux**: Ubuntu 24.04+ or equivalent
- **Android**: API Level 24+ (Android 7.0+)
- **Swift**: 6.1+
- **Xcode**: 15.0+ (for iOS/macOS development)

## 🚀 Installation

### Swift Package Manager

Add the Post-Quantum Solace SDK to your project:

```swift
dependencies: [
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "2.0.0")
]
```

For version 1.x:
```swift
dependencies: [
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "1.0.0", upToNextMajor: "2.0.0")
]
```

### Import the SDK

```swift
import PostQuantumSolace
```

## 🆕 What's New in 2.0.0

Version 2.0.0 introduces significant improvements to the API surface, error handling, and developer experience:

### ✨ New Features

- **`SessionConfiguration`**: Simplified session setup with a single configuration struct
  - Configure all delegates in one call
  - Type-safe initialization
  - Reduced boilerplate code

- **Enhanced Error Handling**: All error types now conform to `LocalizedError`
  - Detailed error descriptions
  - Failure reasons with context
  - Actionable recovery suggestions
  - Better integration with Swift error handling

- **`PQSSessionConstants`**: Centralized configuration constants
  - No more magic numbers
  - `Sendable` for concurrency safety
  - Easy to reference and customize

- **`CryptoError`**: New error type for cryptographic operations
  - Specific errors for encryption/decryption failures
  - Consistent error handling across all crypto operations

### 🔄 Migration from 1.x to 2.0.0

#### Recommended: Use SessionConfiguration

**Before (1.x):**
```swift
await session.setTransportDelegate(conformer: myTransport)
await session.setDatabaseDelegate(conformer: myStore)
session.setReceiverDelegate(conformer: myReceiver)
await session.setPQSSessionDelegate(conformer: myDelegate)
await session.setSessionEventDelegate(conformer: myEventDelegate)
```

**After (2.0.0):**
```swift
let config = SessionConfiguration(
    transport: myTransport,
    store: myStore,
    receiver: myReceiver,
    delegate: myDelegate,
    eventDelegate: myEventDelegate
)
try await session.configure(with: config)
```

#### Error Handling Updates

**Before (1.x):**
```swift
catch let error as PQSSession.SessionErrors {
    print("Error: \(error.rawValue)")
}
```

**After (2.0.0):**
```swift
catch let error as PQSSession.SessionErrors {
    print("Error: \(error.errorDescription ?? "")")
    if let reason = error.failureReason {
        print("Reason: \(reason)")
    }
    if let suggestion = error.recoverySuggestion {
        print("Suggestion: \(suggestion)")
    }
}
```

#### Using Constants

**Before (1.x):**
```swift
if keyCount < 10 {  // Magic number
    await refreshKeys()
}
```

**After (2.0.0):**
```swift
if keyCount < PQSSessionConstants.oneTimeKeyLowWatermark {
    await refreshKeys()
}
```

### ⚠️ Breaking Changes

- **Error Types**: All error enums now conform to `LocalizedError`. While this is backward compatible, accessing `rawValue` directly is no longer recommended. Use `errorDescription` instead.

- **CacheErrors**: The custom `description`, `reason`, and `suggestion` properties have been replaced with `LocalizedError` properties (`errorDescription`, `failureReason`, `recoverySuggestion`).

### 📝 Backward Compatibility

- All existing APIs remain functional
- Individual delegate setters still work (not deprecated)
- Error types maintain their original cases
- No changes to protocol definitions

### 🔗 See Also

- [Migration Guide](Sources/PQSSession/Documentation.docc/GettingStarted.md#migration-from-1x)
- [API Reference](Sources/PQSSession/Documentation.docc/)

## 🌐 Cross-Platform Support

Post-Quantum Solace is designed to work seamlessly across multiple platforms:

### iOS & macOS
- Native Swift implementation with full Apple ecosystem integration
- Optimized for iOS 18+ and macOS 15+
- Supports all Apple Silicon and Intel architectures

### Linux
- Full Swift support on Ubuntu 24.04+ and equivalent distributions
- Compatible with Swift Package Manager on Linux
- Tested on Ubuntu 24.04

### Android
- Swift for Android support via Swift Package Manager
- Compatible with Android API Level 24+ (Android 7.0+)
- Supports both ARM64 and x86_64 architectures
- Integration with Android NDK and Gradle build system
- Requires [Swift Android SDK 6.1+](https://github.com/finagolfin/swift-android-sdk/releases)

### Platform-Specific Considerations

**Android Development:**
- Install [Swift Android SDK 6.1+](https://github.com/finagolfin/swift-android-sdk/releases)
- Use Swift Package Manager with Android NDK integration
- Ensure proper JNI bindings for Android-specific functionality
- Consider memory management for mobile environments

**Linux Development:**
- Install Swift toolchain for your Linux distribution
- Ensure proper cryptographic library dependencies
- Test on target Linux distributions

## 🏗️ Architecture

The SDK is built around several core components:

- **`PQSSession`**: Main session manager orchestrating cryptographic operations
- **`TaskProcessor`**: Handles async encryption/decryption with dedicated executors
- **`SessionCache`**: Two-tier caching with in-memory and persistent storage
- **`SessionEvents`**: Event-driven system for messages and communication updates
- **`SessionModels`**: Core data structures with built-in encryption

## 🚀 Quick Start

### 1. Initialize the Session

```swift
let session = PQSSession.shared
```

### 2. Set Up Delegates

**Recommended: Using SessionConfiguration (Simplified Setup)**

```swift
// Create a configuration with all required delegates
let config = SessionConfiguration(
    transport: myTransport,
    store: myStore,
    receiver: myReceiver,
    delegate: mySessionDelegate,        // Optional
    eventDelegate: myEventDelegate      // Optional
)

// Configure the session in one call
try await session.configure(with: config)
```

**Alternative: Individual Delegate Setup**

```swift
// Set up transport delegate for network communication
await session.setTransportDelegate(conformer: myTransport)

// Set up database delegate for persistent storage
await session.setDatabaseDelegate(conformer: myStore)

// Set up receiver delegate for event handling
session.setReceiverDelegate(conformer: myReceiver)
```

### 3. Create and Start Session

```swift
// Create a new session
try await session.createSession(
    secretName: "alice",
    appPassword: "securePassword",
    createInitialTransport: {
        // Set up your transport layer here
        try await setupNetworkTransport()
    }
)

// Start the session
try await session.startSession(appPassword: "securePassword")
```

### 4. Send Messages

```swift
// Send a text message
try await session.writeTextMessage(
    recipient: .nickname("bob"),
    text: "Hello, world!",
    metadata: ["timestamp": Date()],
    destructionTime: 3600 // Self-destruct after 1 hour
)

// Send a personal note
try await session.writeTextMessage(
    recipient: .personalMessage,
    text: "Note to self",
    metadata: [:]
)

// Send to a channel
try await session.writeTextMessage(
    recipient: .channel("general"),
    text: "Channel message",
    metadata: [:]
)
```

### Message Types Explained

The SDK supports three main message types, each with different use cases and privacy characteristics:

#### 📝 Personal Messages

Personal messages are notes you send to yourself, synchronized across all your devices. They're useful for:
- **Cross-device synchronization**: Access the same notes on your phone, tablet, and computer
- **Private notes**: Store sensitive information that only you can access
- **Device-to-device communication**: Send reminders or data between your own devices

```swift
// Send a personal note that syncs across all your devices
try await session.writeTextMessage(
    recipient: .personalMessage,
    text: "Meeting at 3pm tomorrow",
    metadata: ["category": "reminder"],
    destructionTime: 86400 // Auto-delete after 24 hours
)
```

**Privacy**: Personal messages are encrypted and only accessible to your devices. They may be visible to other users on the network depending on your system's privacy settings, but the content remains encrypted.

#### 🔒 Private Messages (Nickname-based)

Private messages are end-to-end encrypted direct messages between two users. They provide:
- **One-to-one communication**: Direct, private conversations with another user
- **Perfect forward secrecy**: Each message uses unique encryption keys
- **Device synchronization**: Messages are delivered to all of the recipient's devices
- **Identity verification**: Messages are cryptographically signed to verify authenticity

```swift
// Send a private message to another user
try await session.writeTextMessage(
    recipient: .nickname("alice"),
    text: "Can we schedule a meeting?",
    metadata: ["priority": "high"],
    destructionTime: 3600 // Self-destruct after 1 hour
)
```

**Security Features**:
- Messages are encrypted using the Double Ratchet protocol
- Each message uses unique session keys for forward secrecy
- Cryptographic signatures verify message authenticity
- Automatic key rotation ensures long-term security

**Privacy**: Only you and the recipient can decrypt and read the messages. Even if someone intercepts the encrypted messages, they cannot decrypt them without the private keys.

#### 📢 Channel Messages

Channels are group communication spaces where multiple users can participate. They support:
- **Group conversations**: Multiple participants in a single channel
- **Role-based permissions**: Administrators and operators with elevated privileges
- **Member management**: Add/remove members, block users
- **Channel metadata**: Store channel-specific information and settings

```swift
// Send a message to a channel
try await session.writeTextMessage(
    recipient: .channel("engineering"),
    text: "New feature deployed!",
    metadata: ["deployment": "v2.0.0"],
    destructionTime: nil // Permanent message
)
```

**Channel Structure**:
- **Administrator**: The user who created the channel (typically one)
- **Operators**: Users with elevated permissions (minimum 1 required)
- **Members**: Regular participants who can send/receive messages (minimum 3 required)
- **Blocked Members**: Users who have been blocked from the channel

**Channel Requirements** (configurable via `PQSSessionConstants`):
- Minimum operators: 1 (default)
- Minimum members: 3 (default)

**Channel Management**:
Channels are automatically created when you send the first message. The SDK handles:
- Member synchronization across all devices
- Operator and administrator role management
- Message delivery to all channel members
- Automatic channel metadata updates

**Privacy**: Channel messages are encrypted and delivered to all members. Each member receives an encrypted copy that only they can decrypt with their private keys. Channel membership and metadata are also encrypted.

### Choosing the Right Message Type

| Feature | Personal | Private (Nickname) | Channel |
|---------|----------|-------------------|---------|
| **Recipients** | Your devices only | One other user | Multiple users |
| **Encryption** | End-to-end | End-to-end | End-to-end |
| **Forward Secrecy** | ✅ | ✅ | ✅ |
| **Group Support** | ❌ | ❌ | ✅ |
| **Role Management** | ❌ | ❌ | ✅ |
| **Use Case** | Notes, reminders | Direct messages | Team discussions |

### Receiving Messages

All message types are received through the `EventReceiver` protocol:

```swift
class AppEventReceiver: EventReceiver {
    func createdMessage(_ message: EncryptedMessage) async {
        // Decrypt and handle the message
        if let props = await message.props(symmetricKey: sessionKey) {
            switch props.recipient {
            case .personalMessage:
                await handlePersonalMessage(props)
            case .nickname(let sender):
                await handlePrivateMessage(props, from: sender)
            case .channel(let channelName):
                await handleChannelMessage(props, in: channelName)
            case .broadcast:
                await handleBroadcastMessage(props)
            }
        }
    }
    
    func updatedCommunication(_ model: BaseCommunication, members: Set<String>) async {
        // Handle channel updates, member changes, etc.
        await refreshChannelList()
    }
}
```

## 🔧 Implementation Examples

### SessionTransport Protocol

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

### PQSSessionStore Protocol

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

### EventReceiver Protocol

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

## 🔐 Security Model

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

## ⚡ Performance

- **Async/Await**: Modern Swift concurrency throughout
- **Actor Isolation**: Thread-safe concurrent access
- **Dedicated Executors**: Cryptographic operations on separate queues
- **Efficient Caching**: Two-tier cache system for optimal performance
- **Batch Operations**: Key generation and updates in batches

### Configuration Constants

The SDK provides centralized constants for configuration values via `PQSSessionConstants`:

```swift
// Key refresh threshold (default: 10)
PQSSessionConstants.oneTimeKeyLowWatermark

// Batch size for key generation (default: 100)
PQSSessionConstants.oneTimeKeyBatchSize

// Key rotation interval in days (default: 7)
PQSSessionConstants.keyRotationIntervalDays

// Channel requirements
PQSSessionConstants.minimumChannelOperators  // Default: 1
PQSSessionConstants.minimumChannelMembers     // Default: 3
```

These constants are `Sendable` and can be safely accessed from any concurrent context.

## 🛠️ Error Handling

The SDK provides comprehensive error handling with `LocalizedError` conformance, offering detailed error descriptions, failure reasons, and recovery suggestions:

```swift
do {
    try await session.writeTextMessage(
        recipient: .nickname("bob"),
        text: "Hello, world!"
    )
} catch let error as PQSSession.SessionErrors {
    // Access localized error information directly (SessionErrors conforms to LocalizedError)
    print("Error: \(error.errorDescription ?? "Unknown error")")
    
    if let reason = error.failureReason {
        print("Reason: \(reason)")
    }
    
    if let suggestion = error.recoverySuggestion {
        print("Suggestion: \(suggestion)")
    }
    
    // Pattern matching for specific error handling
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
    case .cannotFindOneTimeKey, .drainedKeys:
        // Keys will be automatically refreshed
        print("Waiting for key refresh...")
    default:
        // Handle other errors
        print("Unexpected error: \(error)")
    }
}
```

### Error Types

All error enums conform to `LocalizedError`:
- `PQSSession.SessionErrors` - Session-related errors
- `SessionCache.CacheErrors` - Cache and storage errors
- `CryptoError` - Cryptographic operation errors
- `EventErrors` - Event handling errors
- `SigningErrors` - Signature verification errors

## 🧪 Testing

Run the test suite to verify functionality:

```bash
swift test
```

### Cross-Platform Testing

The package includes comprehensive tests covering:
- Session management
- Key synchronization
- Message encryption/decryption
- Device linking
- End-to-end scenarios
- Cross-platform compatibility

**Platform-Specific Testing:**
- **iOS/macOS**: Run tests in Xcode or via `swift test`
- **Linux**: Use Swift Package Manager on your target Linux distribution
- **Android**: Test via Android NDK integration and emulator/device testing

## 📚 Documentation

For detailed documentation, see:
- [API Reference](Sources/PQSSession/Documentation.docc/)
- [Getting Started Guide](Sources/PQSSession/Documentation.docc/GettingStarted.md)
- [Architecture Overview](Sources/PQSSession/Documentation.docc/Documentation.md)

### Version History

- **2.0.0** (Current): Enhanced error handling with `LocalizedError`, `SessionConfiguration` for simplified setup, `PQSSessionConstants` for centralized configuration, `CryptoError` for cryptographic operations, and comprehensive documentation updates
- **1.x**: Initial release with core post-quantum cryptographic messaging functionality

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines for details.

## 📄 License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## 🔗 Dependencies

- [swift-crypto](https://github.com/apple/swift-crypto) - Apple's cryptographic library
- [double-ratchet-kit](https://github.com/needletails/double-ratchet-kit) - Double Ratchet protocol implementation
- [needletail-crypto](https://github.com/needletails/needletail-crypto) - Cryptographic utilities
- [needletail-logger](https://github.com/needletails/needletail-logger) - Logging framework
- [needletail-algorithms](https://github.com/needletails/needletail-algorithms) - Algorithm implementations

## 🏢 About

Post-Quantum Solace is developed by the [NeedleTails Organization](https://github.com/needletails) as part of our commitment to secure, quantum-resistant communication across all major platforms.

Built with cross-platform compatibility in mind, Post-Quantum Solace ensures your applications can maintain the highest security standards whether deployed on iOS, macOS, Linux, or Android.

---

**Ready for the quantum future?** Start building secure, post-quantum applications today with Post-Quantum Solace! 🔐✨

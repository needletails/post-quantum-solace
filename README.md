<img src="post_quantum_solace.svg" alt="Post Quantum Solace" width="200" />

# Post-Quantum Solace

[![Swift](https://img.shields.io/badge/Swift-6.1+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-iOS%2018%2B%20%7C%20macOS%2015%2B%20%7C%20Linux%20%7C%20Android-blue.svg)](https://developer.apple.com)
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
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "1.0.0")
]
```

### Import the SDK

```swift
import PostQuantumSolace
```

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

## 🛠️ Error Handling

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

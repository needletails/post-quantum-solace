<img src="post_quantum_solace.svg" alt="Post Quantum Solace" width="200" />

# Post-Quantum Solace

[![Swift](https://img.shields.io/badge/Swift-6.1+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-iOS%2018%2B%20%7C%20macOS%2015%2B%20%7C%20Linux%20%7C%20Android-blue.svg)](https://developer.apple.com)
[![Version](https://img.shields.io/badge/Version-4.0.0-blue.svg)](https://github.com/needletails/post-quantum-solace)
[![License](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](LICENSE)

A secure, post-quantum cryptographic messaging SDK with end-to-end encryption, built for the quantum-resistant future.

## 🎉 Version 4.0.0

**4.0.0** is a major API break focused on the host integration surface:
instance-based construction, granular host protocols, a unified error enum,
and consistent X25519 terminology. The 3.x ratchet, recovery behavior, and
**on-disk encodings are unchanged** — a 3.x local database opens in place.
Requires **DoubleRatchetKit 4.0.0**.

> **Upgrading from 3.x?** See the [4.0.0 Migration Guide](#-400-migration-guide).
> For older migration guides (1.x → 2.0, 2.x → 3.0), see the README at the
> [`3.2.1` tag](https://github.com/needletails/post-quantum-solace/blob/3.2.1/README.md).

> **Import note:** The Swift package product is `PostQuantumSolace`; the
> importable module is `PQSSession` (`import PQSSession`).

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
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "4.0.0")
]
```

For the 3.x line:
```swift
dependencies: [
    .package(url: "https://github.com/needletails/post-quantum-solace.git", "3.0.0"..<"4.0.0")
]
```

### Import the SDK

The library product is `PostQuantumSolace`; the importable module is `PQSSession`:

```swift
import PQSSession
```

## 🆕 What's New in 4.0.0

Version 4.0.0 reworks how a host application constructs and integrates the
SDK. Cryptography, recovery behavior, and persisted data formats are carried
over from 3.2.x unchanged.

### Construction and lifecycle

- **Instance-based sessions**: The shared singleton is gone. You create a
  session with `PQSSession(configuration:)` and own its lifetime.
- **`SessionConfiguration`**: One value bundles the required host conformances
  (`transport`, `store`, `observer`), the optional `delegate`, and an
  `auditSink` (file-backed by default).

### Granular host protocols

The monolithic 3.x protocols are split so hosts implement exactly what they
provide. Typealiases keep single-object hosts convenient:

| 3.x protocol | 4.0.0 protocols | Typealias |
|---|---|---|
| `SessionTransport` | `PQSTransport` + `PQSKeyDirectory` + `PQSRecoveryTransport` | `PQSNetworkHost` |
| `PQSSessionStore` | `PQSStore` + `PQSRecoveryStore` | `PQSPersistenceHost` |
| `PQSSessionDelegate` | `MessagingPolicy` + `RecoveryObserver` | `PQSHostDelegate` |
| `EventReceiver` | `MessageStoreObserver` | — |

### Unified errors

- **`PQSError`** (in `SessionModels`) replaces `PQSSession.SessionErrors`,
  `EventErrors`, and `CryptoError`. All public SDK throws are `PQSError`
  cases; the case names from 3.x (`signingKeyOutOfSync`,
  `deviceIdentityCorrupted`, `drainedKeys`, …) are preserved.

### Terminology and internals

- **X25519 naming**: API surfaces that said "curve" now say "x25519"
  (`getVerifiedX25519Keys(deviceId:)`, `OneTimeKeys.x25519`, `KeyKind`
  cases, …). Persisted and wire encodings are pinned to the 3.x byte strings,
  so stored data is unaffected.
- **Internalized machinery**: The task processor (now the internal
  `MessagePipeline`) and `SessionCache` are no longer public API. Hosts
  interact through `PQSSession` and the host protocols only.
- **Audit sink**: `PQSAuditSink` lets you route the send/receive/recovery
  audit trail; `FilePQSAuditSink` is the default.

### Compatibility

- **Local databases carry over.** `SessionContext.schemaVersion` migrates
  1 → 2 in place on first unlock. Ratchet snapshots, session identities, and
  recovery ledgers keep their 3.x `BinaryCodable` encodings — verified
  byte-identical by golden persisted-data fixtures in the test suite.
- **DoubleRatchetKit 4.0.0 required.** Session establishment is now
  `initiateSession` / `respondToSession` (formerly `openAsSender` /
  `openAsRecipient`).

## 🧭 4.0.0 Migration Guide

4.0.0 is **source-breaking** for hosts, but **not data-breaking**: no local
database migration steps are required beyond shipping the new binaries.

### Step 1: Pin both SDKs

```swift
dependencies: [
    .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "4.0.0"),
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "4.0.0")
]
```

### Step 2: Construct the session with a configuration

**Before (3.x):**
```swift
let session = PQSSession.shared
await session.setTransportDelegate(conformer: myTransport)
await session.setDatabaseDelegate(conformer: myStore)
session.setReceiverDelegate(conformer: myReceiver)
await session.setPQSSessionDelegate(conformer: myDelegate)
```

**After (4.0.0):**
```swift
let session = await PQSSession(configuration: SessionConfiguration(
    transport: myTransport,        // any PQSNetworkHost
    store: myStore,                // any PQSPersistenceHost
    observer: myReceiver,          // any MessageStoreObserver
    delegate: myDelegate           // optional PQSHostDelegate
))
```

The individual delegate setters are no longer public; the configuration is
the single wiring point.

### Step 3: Re-conform your host types

The member requirements are the same as 3.x — only the protocol names and
grouping changed:

```swift
// 3.x: class NetworkTransport: SessionTransport
final class NetworkTransport: PQSNetworkHost { /* unchanged members */ }

// 3.x: class DatabaseStore: PQSSessionStore
final class DatabaseStore: PQSPersistenceHost { /* unchanged members */ }

// 3.x: class AppEventReceiver: EventReceiver
final class AppEventReceiver: MessageStoreObserver { /* unchanged members */ }

// 3.x: class AppDelegate: PQSSessionDelegate
final class AppHostDelegate: PQSHostDelegate { /* unchanged members */ }
```

If your host splits responsibilities across objects, conform each object to
just the granular protocols it implements (`PQSTransport`, `PQSKeyDirectory`,
`PQSRecoveryTransport`, `PQSStore`, `PQSRecoveryStore`, `MessagingPolicy`,
`RecoveryObserver`).

### Step 4: Catch `PQSError`

**Before (3.x):**
```swift
} catch let error as PQSSession.SessionErrors {
```

**After (4.0.0):**
```swift
} catch let error as PQSError {
```

Case names are unchanged, so `switch` bodies usually port verbatim.

### Step 5: Adopt the x25519 spellings

```swift
// 3.x                                     // 4.0.0
config.getVerifiedCurveKeys(deviceId:)     config.getVerifiedX25519Keys(deviceId:)
oneTimeKeys.curve                          oneTimeKeys.x25519
longTermKeys.curve                         longTermKeys.x25519
```

These are rename-only changes; the underlying keys, algorithms
(Curve25519/X25519), and persisted bytes are identical.

### ✅ Post-upgrade checklist

- [ ] `Package.swift` pins DRK and PQS to `from: "4.0.0"`
- [ ] Session constructed via `PQSSession(configuration:)`
- [ ] Host types conform to the split protocols (or the typealiases)
- [ ] `catch` clauses use `PQSError`
- [ ] "curve" spellings updated to "x25519"
- [ ] Existing 3.x local databases unlock and message flows work (no data
      migration expected — verify, don't convert)

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

- **`PQSSession`**: Main session actor orchestrating cryptographic operations —
  the only object hosts talk to directly
- **`SessionEvents`** (module): The host protocol surface — transport, store,
  observer, and delegate protocols listed above
- **`SessionModels`** (module): Core data structures with built-in encryption,
  plus `PQSError` and typed identifiers (`SecretName`, `EnvelopeID`,
  `LogicalMessageID`)
- **Internal pipeline**: Message encryption/decryption runs on a dedicated
  internal pipeline with its own executors; two-tier caching (in-memory +
  your store) is likewise internal

## 🚀 Quick Start

### 1. Initialize the Session

```swift
let session = await PQSSession(configuration: SessionConfiguration(
    transport: myTransport,        // any PQSNetworkHost
    store: myStore,                // any PQSPersistenceHost
    observer: myReceiver,          // any MessageStoreObserver
    delegate: mySessionDelegate    // optional PQSHostDelegate
))
```

### 2. Create and Start Session

```swift
// Create a new account
try await session.createAccount(
    secretName: "alice",
    appPassword: "securePassword",
    createInitialTransport: {
        // Set up your transport layer here
        try await setupNetworkTransport()
    }
)

// Start the session (subsequent launches only need this)
try await session.unlock(appPassword: "securePassword")
```

### 3. Send Messages

```swift
struct AppMetadata: Codable, Sendable { let timestamp: Date }

// Send a text message
try await session.send(
    recipient: .nickname("bob"),
    text: "Hello, world!",
    metadata: try BinaryEncoder().encode(AppMetadata(timestamp: Date())),
    destructionTime: 3600 // Self-destruct after 1 hour
)

// Send a personal note
try await session.send(
    recipient: .personalMessage,
    text: "Note to self"
)

// Send to a channel
try await session.send(
    recipient: .channel("general"),
    text: "Channel message"
)
```

> `metadata` is an opaque `Data` blob the SDK encrypts and forwards
> verbatim. Encode it with whatever serializer your app uses (`BinaryCodable`,
> `JSONEncoder`, …); the SDK does not interpret it.

### Message Types Explained

The SDK supports three main message types, each with different use cases and privacy characteristics:

#### 📝 Personal Messages

Personal messages are notes you send to yourself, synchronized across all your devices. They're useful for:
- **Cross-device synchronization**: Access the same notes on your phone, tablet, and computer
- **Private notes**: Store sensitive information that only you can access
- **Device-to-device communication**: Send reminders or data between your own devices

```swift
struct ReminderMetadata: Codable, Sendable { let category: String }

// Send a personal note that syncs across all your devices
try await session.send(
    recipient: .personalMessage,
    text: "Meeting at 3pm tomorrow",
    metadata: try BinaryEncoder().encode(ReminderMetadata(category: "reminder")),
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
struct PriorityMetadata: Codable, Sendable { let priority: String }

// Send a private message to another user
try await session.send(
    recipient: .nickname("alice"),
    text: "Can we schedule a meeting?",
    metadata: try BinaryEncoder().encode(PriorityMetadata(priority: "high")),
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
struct DeploymentMetadata: Codable, Sendable { let deployment: String }

// Send a message to a channel
try await session.send(
    recipient: .channel("engineering"),
    text: "New feature deployed!",
    metadata: try BinaryEncoder().encode(DeploymentMetadata(deployment: "v4.0.0"))
)
```

**Channel Structure**:
- **Administrator**: The user who created the channel (typically one)
- **Operators**: Users with elevated permissions (minimum 1 required)
- **Members**: Regular participants who can send/receive messages
- **Blocked Members**: Users who have been blocked from the channel

**Channel Requirements** (configurable via `PQSSessionConstants`):
- Minimum operators: 1 (default)
- Minimum members: 2 (default)

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

All message types are received through the `MessageStoreObserver` protocol:

```swift
final class AppMessageObserver: MessageStoreObserver {
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

### PQSNetworkHost (transport)

`PQSNetworkHost` is `PQSTransport & PQSKeyDirectory & PQSRecoveryTransport` —
message delivery, the published-key directory, and authenticated out-of-band
resend:

```swift
final class NetworkTransport: PQSNetworkHost {
    // PQSTransport
    func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {
        try await networkService.send(message, to: metadata.secretName)
    }

    // PQSKeyDirectory
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        try await apiService.getUserConfiguration(secretName)
    }

    // PQSRecoveryTransport
    func sendOutOfBandResendRequest(
        failedEnvelopeMessageIds: [String],
        to secretName: String,
        deviceId: UUID,
        requestingDeviceId: UUID
    ) async throws {
        try await apiService.requestResend(failedEnvelopeMessageIds, secretName, deviceId)
    }

    // Implement the remaining requirements of each protocol...
}
```

### PQSPersistenceHost (store)

`PQSPersistenceHost` is `PQSStore & PQSRecoveryStore` — encrypted-at-rest
persistence plus the recovery ledgers:

```swift
final class DatabaseStore: PQSPersistenceHost {
    func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        // Store encrypted message in your database
        try await database.insert(message)
    }

    func fetchMessage(id: UUID) async throws -> EncryptedMessage {
        // Retrieve message from your database
        try await database.find(id: id)
    }

    // Implement the remaining requirements of each protocol...
}
```

### MessageStoreObserver (events)

```swift
final class AppMessageObserver: MessageStoreObserver {
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

### PQSHostDelegate (optional policy and recovery hooks)

`PQSHostDelegate` is `MessagingPolicy & RecoveryObserver`. All recovery hooks
ship with no-op defaults, so conformers only override what they need:

```swift
final class AppHostDelegate: PQSHostDelegate {
    // RecoveryObserver — forward linked-device compromise to the master device
    func linkedDeviceReportedPotentialCompromise(deviceId: UUID, intentId: UUID?) async {
        guard await session.isMasterDevice else { return }
        try? await session.rotateKeysOnPotentialCompromise()
    }

    // RecoveryObserver — surface deferred resend during peer reestablishment
    func inboundRecoveryDeferred(
        senderSecretName: String,
        senderDeviceId: UUID,
        failedSharedMessageId: String,
        failureClass: String
    ) async {
        // e.g. show a subtle "syncing with peer…" state for this conversation
    }
}
```

## 🔐 Security Model

### Cryptographic Protocols
- **Double Ratchet**: For forward secrecy and message ordering
- **MLKEM1024**: Post-quantum key exchange
- **Curve25519 (X25519)**: Classical cryptography for immediate security
- **AES-GCM**: Symmetric encryption for message content

### Key Management
- **One-Time Keys**: Pre-generated for immediate communication
- **Long-Term Keys**: For persistent identity verification
- **Automatic Rotation**: Scheduled and compromise-based key rotation
- **Device Verification**: Signed device configurations

### Trust and identity
- **Trust On First Use (TOFU) pinning**: The account-level signing key is
  pinned on first observation; drift throws `PQSError.signingKeyOutOfSync`
  until the user confirms via `acknowledgeAccountIdentityChange(_:)`.
- **Per-device signing keys**: Master rotations update only the account-level
  key; child devices keep their own per-device signing key.
- **`SecurityIdentity`**: Safety numbers and out-of-band fingerprint
  comparison.

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
PQSSessionConstants.minimumChannelMembers    // Default: 2
```

These constants are `Sendable` and can be safely accessed from any concurrent context.

## 🛠️ Error Handling

All public SDK throws are cases of the unified `PQSError` enum
(`Error`, `Equatable`, `Sendable`), so hosts can pattern-match exhaustively:

```swift
do {
    try await session.send(
        recipient: .nickname("bob"),
        text: "Hello, world!"
    )
} catch let error as PQSError {
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
    case .signingKeyOutOfSync:
        // TOFU mismatch — route to identity verification UI
        await routeToIdentityRecovery()
    case .deviceIdentityCorrupted:
        // Unrecoverable device identity — unlink and re-link
        await routeToReLink()
    case .cannotFindOneTimeKey, .drainedKeys:
        // Keys will be automatically refreshed
        print("Waiting for key refresh...")
    default:
        // Handle other errors
        print("Unexpected error: \(error)")
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
- Golden persisted-data fixtures (byte-identical 3.x compatibility)
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
- [Account Identity Recovery](Sources/PQSSession/Documentation.docc/AccountIdentityRecovery.md)
- [Friendship contact bootstrap](Sources/PQSSession/Documentation.docc/FriendshipContactBootstrap.md)

### Version History

- **4.0.0** (Current): Instance-based construction, granular host protocols,
  unified `PQSError`, x25519 terminology, internalized pipeline. 3.x local
  data carries over unchanged. Requires **DoubleRatchetKit 4.0.0**.
- **3.2.x**: Multi-device friendship delete → re-add reliability;
  `SessionContext.hostLocalPolicyData`.
- **3.1.x**: Session recovery and multi-device hardening on 3.0.0.
- **3.0.0**: TOFU pinning, per-device identity, control-event coalescing,
  inbound recovery, BinaryCodable metadata; requires **DoubleRatchetKit 3.0.0**.
- **2.0.0**: `SessionConfiguration`, `LocalizedError`, `PQSSessionConstants`.
- **1.x**: Initial release.

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines for details.

## 📄 License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## 🔗 Dependencies

- [swift-crypto](https://github.com/apple/swift-crypto) - Apple's cryptographic library
- [double-ratchet-kit](https://github.com/needletails/double-ratchet-kit) - Double Ratchet protocol implementation (**4.0.0+** required for PQS 4.x)
- [needletail-crypto](https://github.com/needletails/needletail-crypto) - Cryptographic utilities
- [needletail-logger](https://github.com/needletails/needletail-logger) - Logging framework
- [needletail-algorithms](https://github.com/needletails/needletail-algorithms) - Algorithm implementations

## 🏢 About

Post-Quantum Solace is developed by the [NeedleTails Organization](https://github.com/needletails) as part of our commitment to secure, quantum-resistant communication across all major platforms.

Built with cross-platform compatibility in mind, Post-Quantum Solace ensures your applications can maintain the highest security standards whether deployed on iOS, macOS, Linux, or Android.

---

**Ready for the quantum future?** Start building secure, post-quantum applications today with Post-Quantum Solace! 🔐✨

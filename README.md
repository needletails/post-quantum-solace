<img src="post_quantum_solace.svg" alt="Post Quantum Solace" width="200" />

# Post-Quantum Solace

[![Swift](https://img.shields.io/badge/Swift-6.1+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-iOS%2018%2B%20%7C%20macOS%2015%2B%20%7C%20Linux%20%7C%20Android-blue.svg)](https://developer.apple.com)
[![Version](https://img.shields.io/badge/Version-3.2.0-blue.svg)](https://github.com/needletails/post-quantum-solace)
[![License](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](LICENSE)

A secure, post-quantum cryptographic messaging SDK with end-to-end encryption, built for the quantum-resistant future.

## 🎉 Version 3.2.0

**3.2.0** improves multi-device friendship delete → re-add (live-device OTK
bootstrap, friendship `blockData` unblock, host-local policy on
`SessionContext`). Requires **DoubleRatchetKit 3.0.0**.

Details:
[`FriendshipContactBootstrap`](Sources/PQSSession/Documentation.docc/FriendshipContactBootstrap.md).

> **Upgrading from 2.x?** See the
> [3.0.0 Migration Guide](#-300-migration-guide). For the 1.x → 2.0 API break,
> see the [2.0.0 Migration Guide](#-200-migration-guide).

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
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "3.2.0")
]
```

For the 3.0 / 3.1 line (before friendship bootstrap targeting):
```swift
dependencies: [
    .package(url: "https://github.com/needletails/post-quantum-solace.git", "3.0.0"..<"3.2.0")
]
```

For version 2.x:
```swift
dependencies: [
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "2.0.0", upToNextMajor: "3.0.0")
]
```

For version 1.x:
```swift
dependencies: [
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "1.0.0", upToNextMajor: "2.0.0")
]
```

### Import the SDK

The library product is `PostQuantumSolace`; the importable module is `PQSSession`:

```swift
import PQSSession
```

## 🆕 What's New in 3.0.0

Version 3.0.0 hardens the trust model, formalizes the per-device identity
invariant, and ships recovery and multi-device behavior for production
deployments.

### ✨ New Features

#### Trust, identity, and verification

- **Trust On First Use (TOFU) pinning**: The account-level signing key is pinned
  on first observation and any drift on a subsequent server refresh is rejected
  with `PQSSession.SessionErrors.signingKeyOutOfSync` instead of being silently
  adopted.
- **User-mediated identity recovery**: New
  `PQSSession.acknowledgeAccountIdentityChange(_:)` lets a master device commit
  to a server-advertised identity after explicit user confirmation. See
  [`AccountIdentityRecovery`](Sources/PQSSession/Documentation.docc/AccountIdentityRecovery.md).
- **Per-device signing key invariant**: Master rotations only update the
  account-level key; child devices keep their own per-device signing key.
  Reprovisioning and key-rotation paths throw `deviceIdentityCorrupted` if a
  bundle tries to replace that key, while startup logs any cached divergence as
  a diagnostic so fresh re-link flows can complete.
- **`SecurityIdentity`** (in `SessionModels`): First-class type for safety
  numbers and out-of-band fingerprint comparison.
  See [`SecurityIdentity`](Sources/SessionModels/Documentation.docc/SecurityIdentity.md).

#### Session recovery and control events

- **Control event coalescing**: Sender-side episodes and receiver-side
  deduplication prevent storms of compromise / refresh / repair notifications.
  Tunables live on `PQSSessionConstants`. See
  [`ControlEventCoalescing`](Sources/PQSSession/Documentation.docc/ControlEventCoalescing.md).
- **`SessionReestablishmentEnvelope` wire format**: Control messages carry
  `intentId` and `epoch` for deduplication across multi-device delivery.
- **Archived session identity fallback**: Inactive ratchet snapshots (bounded
  per device) are tried when the active identity cannot decrypt — supporting
  delayed and out-of-order delivery after reestablishment.
- **Graceful inbound decrypt recovery**: `missingOneTimeKey` and `CryptoKitError`
  paths replace OTK batches and emit `peerRefresh` instead of looping resend
  requests; failure-class suppression prevents repeated recovery on the same frame.
- **`PQSSessionDelegate.inboundRecoveryDeferred`**: Optional hook when resend is
  deferred until the peer completes reestablishment (default no-op).

#### Multi-device and messaging

- **Sibling device fan-out**: Persistable `.nickname` outbound messages are also
  encrypted to the sender's linked devices so delivery receipts and conversation
  state stay consistent across master/child devices.
- **Broadcast recipient (`MessageRecipient.broadcast`)**: First-class broadcast
  fan-out for one-to-many announcements.
- **`OneTimeKeyRefreshPolicy`**: Explicit policies (`.automatic`,
  `.replenishBatch`, `.replaceCurrentDeviceBatch`) for the OTK refresh tasks.
- **Linked-device compromise hook**: Optional
  `PQSSessionDelegate.linkedDeviceReportedPotentialCompromise(deviceId:intentId:)`
  ships with a no-op default so existing delegates keep compiling.

#### Wire format and hardening

- **Binary-codable wire / persistence**: `metadata`, transport blobs and
  stored channel/contact metadata are now plain `Data` produced by
  `BinaryCodable` instead of BSON `Document` values.
- **Recovery flood bounds**: In-memory recovery bookkeeping maps are pruned and
  capped (`PQSSessionConstants.recoveryTrackingMaxEntries`); batched resend
  requests are capped at `FailedMessageResendRequest.maxBatchedIds`.
- **`DecryptFailureAuditLog`**: Optional file-backed audit trail for inbound
  decrypt failures (enabled by default; disable via `DecryptFailureAuditLog.configure(isEnabled: false)`).
- **DoubleRatchetKit 3.0.0**: Depends on deferred-persistence semantics in the
  underlying ratchet layer.

## 🧭 3.0.0 Migration Guide

Version 3.0.0 introduces **source-breaking** changes for integrators on 2.x.
Plan a coordinated upgrade with **DoubleRatchetKit 3.0.0** and retest trust,
metadata, and decrypt-recovery flows before shipping.

### ⚠️ Breaking Changes

1. **TOFU account-identity pinning**
   - **2.x**: A refreshed `UserConfiguration` from the network could be adopted
     even when the account signing key changed.
   - **3.0.0**: Drift throws `PQSSession.SessionErrors.signingKeyOutOfSync` until
     the user explicitly confirms via `acknowledgeAccountIdentityChange(_:)`.

2. **Master-only compromise rotation**
   - **2.x**: Linked devices could call `rotateKeysOnPotentialCompromise()`.
   - **3.0.0**: Only the master device may rotate; linked devices get
     `compromiseRotationRequiresMasterDevice`.

3. **Metadata is `Data`, not BSON `Document`**
   - **2.x**: `metadata` parameters accepted BSON `Document` values.
   - **3.0.0**: All metadata is `Data` from `BinaryEncoder` / `BinaryDecoder`.

4. **OTK refresh policy enum**
   - **2.x**: `refreshOneTimeKeysTask(forceRefresh: Bool)`.
   - **3.0.0**: `refreshOneTimeKeysTask(policy: OneTimeKeyRefreshPolicy)`.

5. **New `MessageRecipient.broadcast` case**
   - **2.x**: `.nickname` and `.channel` only.
   - **3.0.0**: Exhaustive `switch`es over `MessageRecipient` must handle
     `.broadcast` (or use `default`).

6. **New `SessionErrors` cases**
   - `signingKeyOutOfSync`, `compromiseRotationRequiresMasterDevice`,
     `deviceIdentityCorrupted`, `longTermKeyRotationFailed`.

7. **Wire-format control events**
   - `TransportEvent.sessionReestablishment` carries a `SessionReestablishmentEnvelope`
     (`intentId`, `epoch`) instead of a bare kind enum.
   - `FailedMessageResendRequest` may batch `failedSharedMessageIds` (capped at
     `FailedMessageResendRequest.maxBatchedIds` on inbound handling).

8. **DoubleRatchetKit 3.0.0 required**
   - Do not pair PQS 3.x with DRK 2.x. Ratchet state no longer advances on
     failed decrypt attempts in the underlying layer.

### 🎯 Why These Changes?

- **Trust**: Account-level signing keys must not change silently after first use.
- **Device identity**: Child devices keep their own signing keys; only the master
  rotates the account key on compromise.
- **Recovery**: Archived identities, coalesced control events, and failure-class
  suppression prevent decrypt storms and bricking active sessions.
- **Interop**: Binary-codable `Data` metadata is consistent across platforms and
  storage backends.

### 📝 Migration Steps

#### Step 1: Pin both SDKs to 3.0.0

```swift
dependencies: [
    .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "3.0.0"),
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "3.0.0")
]
```

Upgrade **DoubleRatchetKit first**, then Post-Quantum Solace. Rebuild and fix
any compile errors from new `SessionErrors` cases or `MessageRecipient.broadcast`.

#### Step 2: Handle the TOFU error path

`startSession`, `refreshUserConfiguration`, and any path that adopts a fresh
`UserConfiguration` can throw `signingKeyOutOfSync`. Route to identity
verification UI — do not retry silently.

```swift
do {
    try await session.startSession(appPassword: password)
} catch PQSSession.SessionErrors.signingKeyOutOfSync {
    // Show recovery UI. Only call acknowledgeAccountIdentityChange after the
    // user explicitly confirms (e.g. passcode + visual fingerprint compare).
    try await session.acknowledgeAccountIdentityChange(serverConfiguration)
    try await session.startSession(appPassword: password)
}
```

#### Step 3: Restrict compromise rotation to the master device

Forward linked-device compromise signals to the master via
`PQSSessionDelegate.linkedDeviceReportedPotentialCompromise` (or your transport).

```swift
func linkedDeviceReportedPotentialCompromise(deviceId: UUID, intentId: UUID?) async {
    guard await session.isMasterDevice else { return }
    try? await session.rotateKeysOnPotentialCompromise()
}
```

On linked devices, `rotateKeysOnPotentialCompromise()` now throws
`compromiseRotationRequiresMasterDevice`.

#### Step 4: Handle `deviceIdentityCorrupted`

If reprovisioning or key rotation sees a child device re-attested with a foreign
per-device signing key, the SDK throws `deviceIdentityCorrupted`. Treat that as
"unlink and re-link" — there is no in-place repair.

```swift
do {
    try await session.installLinkedDeviceReprovisioningBundle(bundle)
} catch PQSSession.SessionErrors.deviceIdentityCorrupted {
    try await session.deleteSession()
    presentReLinkFlow()
}
```

#### Step 5: Re-encode metadata blobs

**Before (2.x):**
```swift
try await session.writeTextMessage(
    recipient: .nickname("bob"),
    text: "Hello",
    metadata: ["priority": "high"] as Document
)
```

**After (3.0.0):**
```swift
struct AppMetadata: Codable, Sendable { let priority: String }

try await session.writeTextMessage(
    recipient: .nickname("bob"),
    text: "Hello",
    metadata: try BinaryEncoder().encode(AppMetadata(priority: "high"))
)
```

Re-encode any metadata you persisted yourself outside the SDK.

#### Step 6: Adopt `OneTimeKeyRefreshPolicy`

```swift
try await session.refreshOneTimeKeysTask(policy: .automatic)           // background
try await session.refreshOneTimeKeysTask(policy: .replenishBatch)      // after consumption
try await session.refreshOneTimeKeysTask(policy: .replaceCurrentDeviceBatch) // during rotation
```

Same for `refreshMLKEMOneTimeKeysTask(policy:)`.

#### Step 7: Use `SecurityIdentity` for safety numbers

```swift
let local  = await session.localSecurityIdentity()!
let remote = SecurityIdentity(secretName: contact.secretName,
                              configuration: contact.configuration)

let safetyNumber     = SecurityIdentity.safetyNumber(local: local, remote: remote)
let shortFprintHex   = remote.shortFingerprintHex(byteCount: 8)
```

#### Step 8: Optional recovery UI hook

Implement `PQSSessionDelegate.inboundRecoveryDeferred` to surface deferred resend
while the peer completes reestablishment (default extension is a no-op).

```swift
func inboundRecoveryDeferred(
    senderSecretName: String,
    senderDeviceId: UUID,
    failedSharedMessageId: String,
    failureClass: String
) async {
    // e.g. show a subtle "syncing with peer…" state for this conversation
}
```

### ✅ Post-upgrade checklist

- [ ] `Package.swift` pins DRK and PQS to `from: "3.0.0"`
- [ ] `SessionErrors` switches updated for new cases
- [ ] `MessageRecipient` switches handle `.broadcast`
- [ ] App metadata read/write uses `BinaryEncoder` / `BinaryDecoder`
- [ ] Identity-change UX wired to `signingKeyOutOfSync` → `acknowledgeAccountIdentityChange`
- [ ] Compromise flow is master-only; linked devices forward via delegate
- [ ] Active sessions retested: decrypt failure → resend, out-of-order delivery, reestablishment
- [ ] Multi-device: nickname messages and delivery receipts across linked devices

### 📌 Migration Notes

- `PQSSessionDelegate.linkedDeviceReportedPotentialCompromise` and
  `inboundRecoveryDeferred` ship with no-op defaults — existing delegates compile.
- `SessionConfiguration`, `LocalizedError`, and `PQSSessionConstants` from 2.0 are unchanged.
- `startSession(appPassword:)` performs a non-fatal diagnostic check for cached
  per-device signing-key divergence. Enforcement happens on reprovisioning and
  key-rotation paths, where the SDK can distinguish corruption from transient
  fresh-link state.
- Custom transports that bypass `adoptVerifiedUserConfiguration(_:)` will have
  inbound refreshes rejected under TOFU.
- On-disk ratchet snapshots from sessions mid-recovery during upgrade may need
  reestablishment — retest active conversations after deploying.

### 🔗 See Also (3.0.0)

- [Account Identity Recovery Guide](Sources/PQSSession/Documentation.docc/AccountIdentityRecovery.md)
- [Control Event Coalescing](Sources/PQSSession/Documentation.docc/ControlEventCoalescing.md)
- [SecurityIdentity Reference](Sources/SessionModels/Documentation.docc/SecurityIdentity.md)

## 🧭 2.0.0 Migration Guide

Version 2.0.0 introduced `SessionConfiguration`, `LocalizedError` on session errors,
and `PQSSessionConstants`. These are **source-breaking** changes from 1.x.

### ⚠️ Breaking Changes

1. **Delegate wiring** — individual `set*Delegate` calls replaced by
   `configure(with: SessionConfiguration)` (individual setters still work).
2. **Error handling** — `SessionErrors` conforms to `LocalizedError`; prefer
   `errorDescription` over `rawValue`.
3. **Constants** — magic numbers replaced by `PQSSessionConstants`.

### 📝 Migration Steps

#### Step 1: Use SessionConfiguration

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

#### Step 2: Update error handling

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

#### Step 3: Replace magic numbers with constants

**Before (1.x):**
```swift
if keyCount < 10 {
    await refreshKeys()
}
```

**After (2.0.0):**
```swift
if keyCount < PQSSessionConstants.oneTimeKeyLowWatermark {
    await refreshKeys()
}
```

### 📌 Migration Notes

- Already on 3.x? Skip this section unless you maintain a 1.x → 2.x upgrade path.
- See [Getting Started](Sources/PQSSession/Documentation.docc/GettingStarted.md) for current setup patterns.

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
struct AppMetadata: Codable, Sendable { let timestamp: Date }

// Send a text message
try await session.writeTextMessage(
    recipient: .nickname("bob"),
    text: "Hello, world!",
    metadata: try BinaryEncoder().encode(AppMetadata(timestamp: Date())),
    destructionTime: 3600 // Self-destruct after 1 hour
)

// Send a personal note
try await session.writeTextMessage(
    recipient: .personalMessage,
    text: "Note to self"
)

// Send to a channel
try await session.writeTextMessage(
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
try await session.writeTextMessage(
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
try await session.writeTextMessage(
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
try await session.writeTextMessage(
    recipient: .channel("engineering"),
    text: "New feature deployed!",
    metadata: try BinaryEncoder().encode(DeploymentMetadata(deployment: "v3.0.0"))
)
```

**Channel Structure**:
- **Administrator**: The user who created the channel (typically one)
- **Operators**: Users with elevated permissions (minimum 1 required)
- **Members**: Regular participants who can send/receive messages (minimum 2 required)
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
PQSSessionConstants.minimumChannelMembers     // Default: 2
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
- [Friendship contact bootstrap (3.2.0)](Sources/PQSSession/Documentation.docc/FriendshipContactBootstrap.md)

### Version History

- **3.2.0** (Current): Multi-device friendship delete → re-add reliability;
  `SessionContext.hostLocalPolicyData`. Details in
  [`FriendshipContactBootstrap`](Sources/PQSSession/Documentation.docc/FriendshipContactBootstrap.md).
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
- [double-ratchet-kit](https://github.com/needletails/double-ratchet-kit) - Double Ratchet protocol implementation (**3.0.0+** required for PQS 3.x)
- [needletail-crypto](https://github.com/needletails/needletail-crypto) - Cryptographic utilities
- [needletail-logger](https://github.com/needletails/needletail-logger) - Logging framework
- [needletail-algorithms](https://github.com/needletails/needletail-algorithms) - Algorithm implementations

## 🏢 About

Post-Quantum Solace is developed by the [NeedleTails Organization](https://github.com/needletails) as part of our commitment to secure, quantum-resistant communication across all major platforms.

Built with cross-platform compatibility in mind, Post-Quantum Solace ensures your applications can maintain the highest security standards whether deployed on iOS, macOS, Linux, or Android.

---

**Ready for the quantum future?** Start building secure, post-quantum applications today with Post-Quantum Solace! 🔐✨

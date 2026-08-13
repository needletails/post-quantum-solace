# Getting Started

Integrate the Post-Quantum Solace SDK into your Swift application.

## Overview

This guide walks through configuring delegates, creating or restoring a
session, sending and receiving messages, rotating keys, linking new devices,
and recovering from a verified account-identity change.

## Prerequisites

- iOS 18.0+ / macOS 15.0+ (also Linux and Android via the supported package platforms)
- Swift 6.1+
- Xcode 15+
- DoubleRatchetKit 4.0.0+

## Installation

Add Post-Quantum Solace to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/needletails/post-quantum-solace.git", from: "4.0.0")
]
```

The library product is `PostQuantumSolace`; the importable module is `PQSSession`:

```swift
import PQSSession
```

## 1. Configure delegates

A session is constructed from a ``SessionConfiguration`` — it bundles the
three required host conformances, the optional host delegate, and the audit
sink:

```swift
let session = await PQSSession(configuration: SessionConfiguration(
    transport: myTransport,         // any PQSNetworkHost
    store: myStore,                 // any PQSPersistenceHost
    observer: myObserver,           // any MessageStoreObserver
    delegate: myHostDelegate        // optional PQSHostDelegate
))
```

The configuration is the single wiring point; there are no public delegate
setters in 4.0.0.

## 2. Create or start a session

For a brand-new account / device:

```swift
try await session.createAccount(
    secretName: "alice",
    appPassword: "correct horse battery staple",
    createInitialTransport: {
        try await self.bootstrapNetworkConnection()
    }
)
```

For subsequent launches (the local session is persisted):

```swift
try await session.unlock(appPassword: "correct horse battery staple")
```

## 3. Implement the host protocols

### PQSNetworkHost

`PQSNetworkHost` is `PQSTransport & PQSKeyDirectory & PQSRecoveryTransport`:

```swift
final class NetworkTransport: PQSNetworkHost {
    func sendMessage(_ message: SignedRatchetMessage,
                     metadata: SignedRatchetMessageMetadata) async throws {
        try await api.send(message, to: metadata.secretName, deviceId: metadata.deviceId)
    }

    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        try await api.fetchConfiguration(for: secretName)
    }

    func publishUserConfiguration(_ configuration: UserConfiguration,
                                  recipient secretName: String,
                                  recipient identity: UUID) async throws {
        try await api.publish(configuration, secretName: secretName, deviceId: identity)
    }

    // ... fetchOneTimeKeys / updateOneTimeKeys / publishRotatedKeys / etc.
}
```

> Important: `publishUserConfiguration` takes **two** `recipient`-prefixed
> parameters: the recipient's `secretName` and the recipient device's `UUID`.

### PQSPersistenceHost

`PQSPersistenceHost` is `PQSStore & PQSRecoveryStore`:

```swift
final class DatabaseStore: PQSPersistenceHost {
    func createMessage(_ message: EncryptedMessage,
                       symmetricKey: SymmetricKey) async throws {
        try await db.insert(message)
    }

    func fetchMessage(id: UUID) async throws -> EncryptedMessage {
        try await db.fetchMessage(id: id)
    }
    // ... see `PQSStore` and `PQSRecoveryStore` for the full surface
}
```

### MessageStoreObserver

```swift
final class AppMessageObserver: MessageStoreObserver {
    func createdMessage(_ message: EncryptedMessage) async {
        let key = try? await session.getDatabaseSymmetricKey()
        if let key, let props = await message.props(symmetricKey: key) {
            await ui.append(text: props.message.text,
                            from: props.senderSecretName)
        }
    }

    func updatedCommunication(_ model: BaseCommunication,
                              members: Set<String>) async {
        await ui.refreshChannel(model.id, members: members)
    }

    func createdChannel(_ model: BaseCommunication) async {
        await ui.openChannel(model.id)
    }

    // ... see `MessageStoreObserver` for the full surface
}
```

## 4. Send a message

`metadata` is a Binary-encoded application blob — the SDK does not interpret
its contents. Pass `Data()` if you have nothing to attach.

```swift
try await session.send(
    recipient: .nickname("bob"),
    text: "Hello, world!",
    metadata: try BinaryEncoder().encode(MyAppMetadata(priority: .high)),
    destructionTime: 3600 // self-destruct after 1 hour, optional
)
```

### Recipient kinds

```swift
// Personal note (delivered to your other devices only):
try await session.send(recipient: .personalMessage, text: "Note to self")

// 1:1 conversation:
try await session.send(recipient: .nickname("bob"),     text: "Hi Bob")

// Channel:
try await session.send(recipient: .channel(channelId),  text: "Hi everyone")

// System broadcast (rare; usually transport-level):
try await session.send(recipient: .broadcast,           text: "Service notice")
```

## 5. Receive a message

Inbound messages flow from your transport into the SDK via
``PQSSession/receiveMessage(message:sender:deviceId:messageId:)``, then bubble
up to `MessageStoreObserver.createdMessage(_:)`. Decryption uses the database
symmetric key:

```swift
func createdMessage(_ message: EncryptedMessage) async {
    guard let key = try? await session.getDatabaseSymmetricKey(),
          let props = await message.props(symmetricKey: key) else { return }
    await ui.show(text: props.message.text, from: props.senderSecretName)
}
```

## 6. Key management

The SDK refills one-time keys automatically when their count drops below
``PQSSessionConstants/oneTimeKeyLowWatermark``. You can also nudge them:

```swift
_ = await session.refreshOneTimeKeysTask()         // X25519 OTPKs
_ = await session.refreshMLKEMOneTimeKeysTask()    // post-quantum OTPKs
```

For routine, scheduled rotation of this device's long-term keys:

```swift
try await session.rotateCurrentDeviceKeys()
```

For a hard reset after a suspected compromise (master-only):

```swift
try await session.rotateKeysOnPotentialCompromise()
```

> Important: ``PQSSession/rotateKeysOnPotentialCompromise()`` rotates the
> account-level signing key. Calling it on a child device throws
> `PQSError.compromiseRotationRequiresMasterDevice`.

### Useful constants

`PQSSessionConstants` exposes tunable knobs as `Sendable` static lets:

```swift
PQSSessionConstants.oneTimeKeyLowWatermark      // 10
PQSSessionConstants.oneTimeKeyBatchSize         // 100
PQSSessionConstants.keyRotationIntervalDays     // 7
PQSSessionConstants.minimumChannelOperators     // 1
PQSSessionConstants.minimumChannelMembers       // 2
PQSSessionConstants.peerRefreshCooldownSeconds  // 30
PQSSessionConstants.linkedDeviceCompromiseObservedCooldownSeconds // 300
```

## 7. Linking a second device

```swift
let bundle = try await session.createDeviceCryptographicBundle(isMaster: false)
try await session.linkDevice(bundle: bundle, password: "device-pin-or-otp")
```

The new device adopts the same account-level signing key (TOFU-pinned on
first set), and registers its **own** per-device signing key.

## 8. Account identity verification & recovery

### Compute a safety number

```swift
guard let me = await session.localSecurityIdentity() else { return }
let theirConfig = try await myTransport.findConfiguration(for: "bob")
let them = SecurityIdentity(secretName: "bob", configuration: theirConfig)

let display = SecurityIdentity.safetyNumber(local: me, remote: them)
print(display) // "12345 67890 12345 67890 ..." 12 groups of 5 digits
```

### Recover from a TOFU mismatch

If a configuration refresh throws
`PQSError.signingKeyOutOfSync`, the **server's account
signing key has changed** since you last accepted it. Surface a confirmation
flow to the user (compare safety numbers, scan QR, etc.). After the user
verifies, commit the new identity:

```swift
let serverConfig = try await myTransport.findConfiguration(for: mySecretName)
try await session.acknowledgeAccountIdentityChange(serverConfig)
```

This is the **only** path that bypasses TOFU, and it logs the transition at
`.error` for support triage. Gate it behind a strong, explicit user
confirmation (passcode, biometrics, or a typed destructive phrase).

## 9. Error handling

All public SDK throws are cases of the unified `PQSError` enum
(`Error`, `Equatable`, `Sendable`), so hosts can pattern-match directly:

```swift
do {
    try await session.send(
        recipient: .nickname("bob"),
        text: "Hello"
    )
} catch let error as PQSError {
    switch error {
    case .sessionNotInitialized:    await prompt("Sign in again.")
    case .databaseNotInitialized:   await prompt("Storage unavailable.")
    case .transportNotInitialized:  await prompt("Network unavailable.")
    case .signingKeyOutOfSync:      await routeToIdentityRecovery()
    case .deviceIdentityCorrupted:  await routeToReLink()
    case .compromiseRotationRequiresMasterDevice:
        await prompt("Use your master device to rotate keys.")
    case .cannotFindOneTimeKey, .drainedKeys:
        // Background refill will run; show a transient banner if needed.
        break
    default:
        await prompt("\(error)")
    }
} catch {
    await prompt(error.localizedDescription)
}
```

### Error types

- `PQSError` (in `SessionModels`) — the single public error surface for
  session lifecycle, messaging, key management, and recovery operations. It
  replaces the 3.x `PQSSession.SessionErrors`, `EventErrors`, and
  `CryptoError` enums; internal errors are mapped onto it before they reach
  host code.

## Best practices

### Security
- Use strong app passwords; back them with biometrics where possible.
- Treat ``PQSSession/acknowledgeAccountIdentityChange(_:)`` like factory-reset:
  always require explicit, conscious user consent.
- Surface `PQSError.signingKeyOutOfSync` to the user — never
  swallow it silently.
- Compare safety numbers out of band before sharing sensitive content.

### Performance
- Let the SDK manage one-time key refills — only call the manual entry points
  when you have a specific reason.
- Run cryptographic work on the SDK's dedicated executors (it does this for
  you); avoid wrapping public APIs in extra `Task.detached` calls on the main
  actor.

### Integration
- Implement the three required host protocols (`PQSNetworkHost`,
  `PQSPersistenceHost`, `MessageStoreObserver`) in dedicated, single-purpose
  types; add a `PQSHostDelegate` when you need policy or recovery hooks.
- Wire them once via ``SessionConfiguration`` at construction.
- Persist `EncryptedMessage` and `BaseCommunication` blobs verbatim — the SDK
  treats them as opaque ciphertext.
- For multi-device friendship add / delete → re-add, implement
  `RecoveryObserver.preferredOnlinePeerDeviceId(for:)` and call
  ``PQSSession/bootstrapPeerContactSession(secretName:purpose:)`` before the
  first friendship packet. See <doc:FriendshipContactBootstrap>.

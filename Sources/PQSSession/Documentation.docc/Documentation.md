# Post-Quantum Solace SDK

A secure, post-quantum cryptographic messaging SDK with end-to-end encryption,
account-level identity pinning, and per-device key custody.

## Overview

The Post-Quantum Solace SDK gives Swift applications a complete pipeline for
multi-device, post-quantum-secure messaging. Each user owns an **account-level
signing key** (the trust anchor); each device owns its own per-device signing
key, long-term Curve25519 / MLKEM1024 keys, and a continually-replenished pool
of one-time pre-keys. The Double Ratchet (via the
[`DoubleRatchetKit`](https://github.com/needletails/double-ratchet-kit) module)
provides forward secrecy, while MLKEM1024 contributes the post-quantum half of
each handshake.

The SDK is designed around three jobs:

- **`PQSSession`** — the session actor that owns session state, drives
  encryption / decryption, schedules key rotation, and coordinates all other
  components. You construct one with a ``SessionConfiguration``.
- **`SessionEvents` (host protocols)** — the surfaces an application
  implements to plug the SDK into its network, database, and UI:
  `PQSNetworkHost` (transport), `PQSPersistenceHost` (store),
  `MessageStoreObserver` (events), and the optional `PQSHostDelegate`.
- **`SessionModels`** — the on-disk and on-the-wire data types
  (`UserConfiguration`, `EncryptedMessage`, `BaseCommunication`,
  `SecurityIdentity`, `PQSError`, etc.) that move between those pieces.

## Topics

### Getting Started

- <doc:GettingStarted>

### Guides

- <doc:AccountIdentityRecovery>
- <doc:ControlEventCoalescing>
- <doc:FriendshipContactBootstrap>
- <doc:MultideviceDecryptRecovery>
- <doc:DeferredOTKConsumption>

### Core entry point

- ``PQSSession``
- ``SessionConfiguration``
- ``PQSSessionConstants``

### Lifecycle & configuration

- ``PQSSession/init(configuration:ratchetConfiguration:)``
- ``PQSSession/createAccount(secretName:appPassword:createInitialTransport:)``
- ``PQSSession/unlock(appPassword:)``
- ``PQSSession/linkDevice(bundle:password:)``
- ``PQSSession/shutdown()``
- ``PQSSession/resumeJobQueue()``
- ``PQSSession/isViable``
- ``SessionContext``
- ``SessionContext/hostLocalPolicyData``

### Account identity & TOFU trust

- ``PQSSession/localSecurityIdentity()``
- ``PQSSession/adoptVerifiedUserConfiguration(_:)``
- ``PQSSession/acknowledgeAccountIdentityChange(_:)``
- ``PQSSession/updateUserConfiguration(_:)``
- ``PQSSession/updateUserOneTimePublicKeys(_:)``
- ``PQSSession/createDeviceCryptographicBundle(isMaster:)``
- ``PQSSession/CryptographicBundle``

### Messaging & contacts

- ``PQSSession/send(recipient:text:transportInfo:metadata:destructionTime:sharedIdOverride:shouldPersistOverride:targetDeviceId:coalescingKey:)``
- ``PQSSession/receiveMessage(message:sender:deviceId:messageId:)``
- ``PQSSession/conversation(for:)``
- ``PQSSession/addContacts(_:)``
- ``PQSSession/createContact(secretName:metadata:friendshipMetadata:requestFriendship:)``
- ``PQSSession/sendCommunicationSynchronization(contact:)``
- ``PQSSession/requestFriendshipStateChange(state:contact:)``
- ``PQSSession/bootstrapPeerContactSession(secretName:purpose:)``
- ``PQSSession/peerNeedsOutboundBootstrap(_:)``
- ``PeerContactBootstrapPurpose``
- ``PQSSession/updateMessageDeliveryState(_:deliveryState:messageRecipient:allowExternalUpdate:)``
- ``PQSSession/editCurrentMessage(_:newText:)``

### Key rotation

- ``PQSSession/rotateCurrentDeviceKeys()``
- ``PQSSession/rotateKeysOnPotentialCompromise()``
- ``PQSSession/refreshOneTimeKeysTask(policy:)``
- ``PQSSession/refreshMLKEMOneTimeKeysTask(policy:)``
- ``PQSSession/OneTimeKeyRefreshPolicy``

### Application password & app-data crypto

- ``PQSSession/getAppSymmetricKey()``
- ``PQSSession/getDatabaseSymmetricKey()``
- ``PQSSession/verifyAppPassword(_:)``
- ``PQSSession/changeAppPassword(_:)``

### Errors

All public throws are cases of the unified `PQSError` enum, defined in
`SessionModels`.

### Host protocol surfaces

Defined in the `SessionEvents` module:

- `PQSNetworkHost` = `PQSTransport & PQSKeyDirectory & PQSRecoveryTransport`
- `PQSPersistenceHost` = `PQSStore & PQSRecoveryStore`
- `MessageStoreObserver`
- `PQSHostDelegate` = `MessagingPolicy & RecoveryObserver` (optional)

### Internal building blocks

- <doc:MessagePipeline>

## Security model

### Two layers of trust

The SDK enforces both **automatic** trust pinning and **manual** out-of-band
verification:

1. **Trust On First Use (TOFU)** — the local account's
   `signingPublicKey` is pinned the first time it is set. Any subsequent
   server-supplied `UserConfiguration` whose account signing key differs from
   the pin is rejected by ``PQSSession/adoptVerifiedUserConfiguration(_:)``
   with `PQSError.signingKeyOutOfSync`. Legitimate
   rotations install via authenticated channels (master rotation,
   linked-device reprovisioning) that update the pin first, so a subsequent
   refresh sees a matching key.
2. **Safety numbers** — ``SecurityIdentity``
   60-digit safety numbers via ``SecurityIdentity/safetyNumber(local:remote:version:iterations:)``.
   Two users compare these out of band (in-person scan, voice, etc.) to rule
   out a man-in-the-middle.

When a TOFU mismatch is detected, the app should surface a confirmation flow
and call ``PQSSession/acknowledgeAccountIdentityChange(_:)`` only after the
user has positively re-verified the new identity (or, conversely, unlink the
device and re-link from the master).

### Cryptographic primitives

- **Double Ratchet** — forward secrecy + message ordering (per-message keys).
- **MLKEM1024** — post-quantum KEM contribution to every key agreement.
- **Curve25519** — classical key agreement and signing for immediate security.
- **AES-GCM** — authenticated symmetric encryption for ciphertext and
  Binary-encoded `EncryptedMessage` / `BaseCommunication` payloads.

### Per-device identity invariant

Every device owns a stable per-device signing key for the lifetime of its
`DeviceID`. Master rotations distribute a new account-level signing key, but
they never replace a child's per-device key. Startup
(``PQSSession/unlock(appPassword:)``) performs a non-fatal diagnostic
check for cached divergence so fresh re-link flows can finish. Reprovisioning
and key-rotation paths enforce the invariant and emit
`PQSError.deviceIdentityCorrupted` if a bundle tries to
re-attest a child device with a foreign per-device key; that device should be
re-linked.

## Quick start

```swift
import PQSSession

let session = await PQSSession(configuration: SessionConfiguration(
    transport: myTransport,
    store: myStore,
    observer: myReceiver,
    delegate: mySessionDelegate           // optional
))

try await session.createAccount(
    secretName: "alice",
    appPassword: "correct horse battery staple",
    createInitialTransport: setupNetworkTransport
)
try await session.unlock(appPassword: "correct horse battery staple")

try await session.send(
    recipient: .nickname("bob"),
    text: "Hello, world!",
    metadata: Data() // any application-defined Binary blob
)
```

## Error handling

All public SDK throws are cases of the unified `PQSError` enum
(defined in `SessionModels`):

```swift
do {
    try await session.send(
        recipient: .nickname("bob"),
        text: "Hello, world!"
    )
} catch let error as PQSError {
    switch error {
    case .signingKeyOutOfSync:
        await presentAccountIdentityRecovery()        // see GettingStarted

    case .deviceIdentityCorrupted:
        await unlinkAndPromptToReLink()

    case .compromiseRotationRequiresMasterDevice:
        await showMasterOnlyHint()

    case .cannotFindOneTimeKey, .drainedKeys:
        // Background tasks will refill; surface a transient retry banner.
        break

    default:
        await showError("\(error)")
    }
}
```

## Thread safety

- ``PQSSession`` is an `actor` — every public method is async and serializes
  on the actor's executor.
- All persisted/transmitted models conform to `Sendable`.
- The internal message pipeline runs cryptographic work on dedicated
  executors so heavy encrypt/decrypt work does not contend with the rest of
  the app (see <doc:MessagePipeline>).

## Integration

- **Transport** — implement `PQSNetworkHost` to send signed ratchet
  messages, publish/fetch `UserConfiguration` and one-time keys, and provide
  authenticated out-of-band resend.
- **Store** — implement `PQSPersistenceHost` for encrypted persistence of
  contexts, messages, contacts, communications, queued jobs, and recovery
  ledgers.
- **Observer** — implement `MessageStoreObserver` to react to message and
  contact lifecycle changes in your UI.
- **Optional delegate** — implement `PQSHostDelegate` to participate
  in metadata redaction, transport routing, compromise notifications, and
  (for multi-device hosts) `RecoveryObserver.preferredOnlinePeerDeviceId(for:)`
  so friendship OTK bootstrap targets a live peer device. See
  <doc:FriendshipContactBootstrap>.

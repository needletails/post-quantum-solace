# ``PQSSession``

The session actor at the heart of the Post-Quantum Solace SDK. It owns
session state, drives every encrypt/decrypt path, schedules key rotation,
enforces TOFU on the account-level signing key, and coordinates the host
protocol surfaces.

## Overview

`PQSSession` is an `actor`; every public method is async and serializes on
the actor's executor. You construct an instance with
``init(configuration:ratchetConfiguration:)``, passing a
``SessionConfiguration`` that wires your transport, store, observer, and
optional host delegate. Afterward you create a brand-new local session with
``createAccount(secretName:appPassword:createInitialTransport:)`` or restore
an existing one with ``unlock(appPassword:)``.

## Topics

### Construction

- ``init(configuration:ratchetConfiguration:)``
- ``init(_:)``
- ``SessionConfiguration``
- ``isViable``
- ``linkDelegate``

### Session lifecycle

- ``createAccount(secretName:appPassword:createInitialTransport:)``
- ``unlock(appPassword:)``
- ``linkDevice(bundle:password:)``
- ``shutdown()``
- ``resumeJobQueue()``

### Session context

- ``sessionContext``
- ``setSessionContext(_:)``
- ``appPassword``

### Account identity & TOFU trust

- <doc:AccountIdentityRecovery>
- ``localSecurityIdentity()``
- ``adoptVerifiedUserConfiguration(_:)``
- ``acknowledgeAccountIdentityChange(_:)``
- ``updateUserConfiguration(_:)``
- ``createNewUser(configuration:signingPrivateKeyData:devices:keys:mlKEMKeys:)``
- ``createDeviceCryptographicBundle(isMaster:)``
- ``CryptographicBundle``
- ``KeyPair``

### Messaging

- ``send(recipient:text:transportInfo:metadata:destructionTime:sharedIdOverride:shouldPersistOverride:targetDeviceId:coalescingKey:)``
- ``receiveMessage(message:sender:deviceId:messageId:)``
- ``editCurrentMessage(_:newText:)``
- ``updateMessageDeliveryState(_:deliveryState:messageRecipient:allowExternalUpdate:)``

### Channels & contacts

- ``conversation(for:)``
- ``addContacts(_:)``
- ``createContact(secretName:metadata:friendshipMetadata:requestFriendship:)``
- ``sendCommunicationSynchronization(contact:)``
- ``sendContactCreatedAcknowledgment(recipient:)``
- ``requestFriendshipStateChange(state:contact:)``
- ``bootstrapPeerContactSession(secretName:purpose:)``
- ``peerNeedsOutboundBootstrap(_:)``
- ``PeerContactBootstrapPurpose``
- ``requestMetadata(from:)``
- ``requestMyMetadata()``
- ``setAddingContact(_:)``

### Friendship bootstrap (delete → re-add)

Before the first friendship packet after add or crypto wipe, call
``bootstrapPeerContactSession(secretName:purpose:)`` with
``PeerContactBootstrapPurpose/newOutbound`` (requester) or
``PeerContactBootstrapPurpose/friendshipReply`` (acceptor). Use
``peerNeedsOutboundBootstrap(_:)`` to decide whether bootstrap is still
required. Multi-device hosts should implement
`RecoveryObserver.preferredOnlinePeerDeviceId(for:)` so OTK notify
targets a live peer device rather than a ghost still listed in the published
account config. Full host checklist:
<doc:FriendshipContactBootstrap>.

### Key rotation

- ``rotateCurrentDeviceKeys()``
- ``rotateKeysOnPotentialCompromise()``
- ``refreshOneTimeKeysTask(policy:)``
- ``refreshMLKEMOneTimeKeysTask(policy:)``
- ``OneTimeKeyRefreshPolicy``
- ``updateUserOneTimePublicKeys(_:)``

### Identities (per-device)

- ``removeIdentity(with:)``

### Device naming

- ``getDeviceName()``

### Application password & app-data crypto

- ``getAppSymmetricKey()``
- ``getDatabaseSymmetricKey()``
- ``verifyAppPassword(_:)``
- ``changeAppPassword(_:)``

### Logging

- ``setLogLevel(_:)``

### Errors

All public throws are cases of the unified `PQSError` enum, defined in
`SessionModels`.

### Configuration constants

- ``PQSSessionConstants``

## Trust model (TOFU)

The local account's `signingPublicKey` is **pinned** the first time a
`SessionContext` is set. Routine refresh paths
(``adoptVerifiedUserConfiguration(_:)``) reject any server-supplied
configuration whose account signing key disagrees with the pin, throwing
`PQSError.signingKeyOutOfSync`.

Two paths legitimately update the pin:

1. **Authenticated rotation initiated locally**, e.g. master invoking
   ``rotateKeysOnPotentialCompromise()``. The pin is updated *before* the
   new configuration is published, so subsequent refreshes see a matching
   key.
2. **User-acknowledged identity change** via
   ``acknowledgeAccountIdentityChange(_:)``. This is the only externally
   callable bypass for TOFU and must be gated behind explicit user consent.

Use ``localSecurityIdentity()`` together with
``SecurityIdentity/safetyNumber(local:remote:version:iterations:)`` to render
a 60-digit safety number for out-of-band verification.

Contacts also pin the peer's account-level `signingPublicKey`. A forced
identity refresh that sees a different peer account key throws
`PQSError.peerSigningKeyOutOfSync` and notifies
`RecoveryObserver.peerAccountIdentityChanged(secretName:deviceId:failedSharedMessageId:)`
instead of attempting automatic ratchet repair. Resume communication only
after the user verifies and accepts the new safety number.

## Master vs. linked devices

- The master device holds the account-level signing **private** key. It is
  the only device that can call ``rotateKeysOnPotentialCompromise()`` and
  ``updateUserConfiguration(_:)``.
- Linked (child) devices each own a **per-device** signing key for the
  lifetime of their `DeviceID`. They consume server-published bundles via
  ``adoptVerifiedUserConfiguration(_:)``.
- Startup performs a non-fatal diagnostic check for cached per-device key
  divergence. Reprovisioning and key-rotation paths enforce the invariant and
  throw `PQSError.deviceIdentityCorrupted` if a bundle tries to
  re-attest a child device with a foreign per-device key; that device should be
  re-linked.

## Quick start

```swift
let session = await PQSSession(configuration: SessionConfiguration(
    transport: myTransport,
    store: myStore,
    observer: myReceiver
))

try await session.createAccount(
    secretName: "alice",
    appPassword: "correct horse battery staple",
    createInitialTransport: bootstrapTransport
)
try await session.unlock(appPassword: "correct horse battery staple")

try await session.send(
    recipient: .nickname("bob"),
    text: "Hello, world!",
    metadata: Data(),
    destructionTime: 3600
)
```

## Thread safety

`PQSSession` is an `actor`, so all public methods are serialized on the
actor's executor. Long-running cryptographic work is offloaded to dedicated
executors managed by the SDK's internal message pipeline so that
encrypt/decrypt does not contend with regular API calls (see
<doc:MessagePipeline>).

## See also

- ``SessionConfiguration``
- ``PQSSessionConstants``
- `SecurityIdentity`
- `PQSError`
- <doc:FriendshipContactBootstrap>
- <doc:AccountIdentityRecovery>
- <doc:ControlEventCoalescing>

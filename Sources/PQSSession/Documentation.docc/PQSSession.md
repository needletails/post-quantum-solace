# ``PQSSession``

The singleton actor at the heart of the Post-Quantum Solace SDK. It owns
session state, drives every encrypt/decrypt path, schedules key rotation,
enforces TOFU on the account-level signing key, and coordinates the four
delegate surfaces.

## Overview

`PQSSession` is an `actor`; every public method is async and serializes on
the actor's executor. Always use ``shared``. Configuration happens once via
``configure(with:)``; afterward you create a brand-new local session with
``createSession(secretName:appPassword:createInitialTransport:)`` or restore
an existing one with ``startSession(appPassword:)``.

## Topics

### Singleton

- ``shared``
- ``init(_:)``
- ``isViable``

### Configuration

- ``configure(with:)``
- ``setTransportDelegate(conformer:)``
- ``setDatabaseDelegate(conformer:)``
- ``setReceiverDelegate(conformer:)``
- ``setPQSSessionDelegate(conformer:)``
- ``setSessionEventDelegate(conformer:)``
- ``linkDelegate``

### Session lifecycle

- ``createSession(secretName:appPassword:createInitialTransport:)``
- ``startSession(appPassword:)``
- ``linkDevice(bundle:password:)``
- ``shutdown()``
- ``resumeJobQueue()``

### Session context & cache

- ``sessionContext``
- ``setSessionContext(_:)``
- ``cache``
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

- ``writeTextMessage(recipient:text:transportInfo:metadata:destructionTime:sharedIdOverride:)``
- ``receiveMessage(message:sender:deviceId:messageId:)``
- ``editCurrentMessage(_:newText:)``
- ``updateMessageDeliveryState(_:deliveryState:messageRecipient:allowExternalUpdate:)``

### Channels & contacts

- ``findCommunication(for:)``
- ``addContacts(_:)``
- ``createContact(secretName:metadata:friendshipMetadata:requestFriendship:)``
- ``sendCommunicationSynchronization(contact:)``
- ``sendContactCreatedAcknowledgment(recipient:)``
- ``requestFriendshipStateChange(state:contact:)``
- ``requestMetadata(from:)``
- ``requestMyMetadata()``
- ``setAddingContact(_:)``

### Key rotation

- ``rotateCurrentDeviceKeys()``
- ``rotateKeysOnPotentialCompromise()``
- ``refreshOneTimeKeysTask(policy:)``
- ``refreshMLKEMOneTimeKeysTask(policy:)``
- ``OneTimeKeyRefreshPolicy``
- ``updateUseroneTimePublicKeys(_:)``

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

- ``SessionErrors``

### Configuration constants

- ``PQSSessionConstants``

## Trust model (TOFU)

The local account's `signingPublicKey` is **pinned** the first time a
`SessionContext` is set. Routine refresh paths
(``adoptVerifiedUserConfiguration(_:)``) reject any server-supplied
configuration whose account signing key disagrees with the pin, throwing
``SessionErrors/signingKeyOutOfSync``.

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
``SessionErrors/peerSigningKeyOutOfSync`` and notifies
``PQSSessionDelegate/peerAccountIdentityChanged(secretName:deviceId:failedSharedMessageId:)``
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
  throw ``SessionErrors/deviceIdentityCorrupted`` if a bundle tries to
  re-attest a child device with a foreign per-device key; that device should be
  re-linked.

## Quick start

```swift
let session = PQSSession.shared

try await session.configure(with: SessionConfiguration(
    transport: myTransport,
    store: myStore,
    receiver: myReceiver
))

try await session.createSession(
    secretName: "alice",
    appPassword: "correct horse battery staple",
    createInitialTransport: bootstrapTransport
)
try await session.startSession(appPassword: "correct horse battery staple")

try await session.writeTextMessage(
    recipient: .nickname("bob"),
    text: "Hello, world!",
    metadata: Data(),
    destructionTime: 3600
)
```

## Thread safety

`PQSSession` is an `actor`, so all public methods are serialized on the
actor's executor. Long-running cryptographic work is offloaded to dedicated
executors managed by ``TaskProcessor`` so that encrypt/decrypt does not
contend with regular API calls.

## See also

- ``SessionConfiguration``
- ``PQSSessionConstants``
- ``SecurityIdentity``
- ``SessionErrors``

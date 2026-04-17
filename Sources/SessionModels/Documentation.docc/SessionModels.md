# SessionModels

Core data structures with built-in symmetric encryption and secure
serialization, used everywhere by the Post-Quantum Solace SDK.

## Overview

The `SessionModels` module defines every persistent and over-the-wire
data type the SDK needs: encrypted messages, communication channels,
contacts, jobs, session context, user configurations, and the
account-level identity used for safety-number verification.

All sensitive payloads are encrypted with a `SymmetricKey` before they
are persisted; all `Codable` types use single-letter coding keys to
obfuscate on-disk layout.

## Topics

### Account identity

- ``SecurityIdentity``
- ``UserConfiguration``
- ``UserConfiguration/SignedDeviceConfiguration``
- ``UserConfiguration/SignedOneTimePublicKey``
- ``UserConfiguration/SignedMLKEMOneTimeKey``
- ``KeysType``

### Session state

- ``SessionContext``
- ``SessionContext/RegistrationState``
- ``SessionUser``
- ``LinkDeviceInfo``
- ``LinkedDeviceReprovisioningBundle``
- ``DeviceLinkingDelegate``

### Messages

- ``EncryptedMessage``
- ``EncryptedMessage/UnwrappedProps``
- ``CryptoMessage``
- ``DeliveryState``
- ``MessageRecipient``

### Communications

- ``BaseCommunication``
- ``BaseCommunication/UnwrappedProps``
- ``Communication``
- ``CommunicationProtocol``
- ``ChannelInfo``
- ``ChannelStoredMetadata``
- ``ChannelLocalOverlay``

### Contacts & friendship

- ``Contact``
- ``ContactModel``
- ``SharedContactInfo``
- ``FriendshipMetadata``
- ``FriendshipMetadata/State``

### Jobs & data packets

- ``JobModel``
- ``DataPacket``

### Crypto helpers

- ``DeviceKeys``
- ``RotatedPublicKeys``
- ``OneTimeKeys``
- ``UserDeviceConfiguration``

### Transport envelopes

- ``TransportEvent``
- ``SynchronizationKeyIdentities``
- ``FailedMessageResendRequest``
- ``DeliveryStateMetadata``
- ``EditMessageMetadata``

### Errors

- ``CryptoError``

## Design notes

### Encrypted at rest

Every secure model in this module
(``EncryptedMessage``, ``BaseCommunication``, ``ContactModel``,
``JobModel``) follows the same pattern:

1. The plaintext is a Swift struct named `UnwrappedProps`.
2. The persisted/serialized type stores only `id` (or other lookup
   metadata) and an opaque `data: Data` blob, encrypted with a
   `SymmetricKey` derived from ``SessionContext/databaseEncryptionKey``.
3. `props(symmetricKey:)` returns the decrypted props, or `nil` if the
   key is wrong or the blob is corrupted; `decryptProps(symmetricKey:)`
   throws ``CryptoError/decryptionFailed`` instead.
4. `updateProps(symmetricKey:props:)` atomically re-encrypts.

### Coding-key obfuscation

All `Codable` conformances use single-letter coding keys (e.g.
`case sentDate = "c"`). This is *security through obscurity*, not
authentication — the encryption key is the actual secret — but it
removes obvious labels from on-disk and on-wire blobs.

## See also

- ``SessionConfiguration``
- ``PQSSession``
- ``SecurityIdentity``
- ``CryptoError``

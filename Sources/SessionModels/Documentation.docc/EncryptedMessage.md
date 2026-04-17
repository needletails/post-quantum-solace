# ``EncryptedMessage``

A locally-persisted encrypted message: lookup metadata in plaintext,
payload (text, recipient, sender, delivery state, application metadata)
encrypted with a session-level symmetric key.

## Overview

`EncryptedMessage` is the on-disk and over-the-wire representation of a
single message inside a communication. The plaintext is described by
``EncryptedMessage/UnwrappedProps``; the persisted form stores only
indexable metadata (`id`, `communicationId`, `sessionContextId`,
`sharedId`, `sequenceNumber`) plus an opaque ``EncryptedMessage/data``
blob that carries the encrypted, Binary-serialized props.

Use ``EncryptedMessage/props(symmetricKey:)`` for graceful access (returns
`nil` on failure) and ``EncryptedMessage/decryptProps(symmetricKey:)`` for
explicit error handling.

## Topics

### Initialization

- ``EncryptedMessage/init(id:communicationId:sessionContextId:sharedId:sequenceNumber:props:symmetricKey:)``
- ``EncryptedMessage/init(id:communicationId:sessionContextId:sharedId:sequenceNumber:data:)``

### Lookup metadata

- ``EncryptedMessage/id``
- ``EncryptedMessage/communicationId``
- ``EncryptedMessage/sessionContextId``
- ``EncryptedMessage/sharedId``
- ``EncryptedMessage/sequenceNumber``
- ``EncryptedMessage/data``

### Encrypted props access

- ``EncryptedMessage/UnwrappedProps``
- ``EncryptedMessage/props(symmetricKey:)``
- ``EncryptedMessage/decryptProps(symmetricKey:)``
- ``EncryptedMessage/updateProps(symmetricKey:props:)``
- ``EncryptedMessage/updateMessage(with:symmetricKey:)``
- ``EncryptedMessage/makeDecryptedModel(of:symmetricKey:)``

### Companion types

- ``CryptoMessage``
- ``DeliveryState``

## Working with messages

```swift
// Build the plaintext and encrypt.
let props = EncryptedMessage.UnwrappedProps(
    id: UUID(),
    base: communication,
    sentDate: Date(),
    deliveryState: .sending,
    message: cryptoMessage,
    senderSecretName: senderName,
    senderDeviceId: deviceId
)

let message = try EncryptedMessage(
    id: UUID(),
    communicationId: communication.id,
    sessionContextId: sessionContext.sessionContextId,
    sharedId: sharedMessageId,
    sequenceNumber: nextSequenceNumber,
    props: props,
    symmetricKey: sessionKey
)
```

```swift
// Decrypt to access content.
guard let props = await message.props(symmetricKey: sessionKey) else { return }
let text = props.message.text
let metadata = props.message.metadata // Data — application-defined
let appMetadata = try BinaryDecoder().decode(MyAppMetadata.self,
                                             from: metadata)
```

```swift
// Update delivery state.
guard var props = await message.props(symmetricKey: sessionKey) else { return }
props.deliveryState = .delivered
let updated = try await message.updateMessage(with: props, symmetricKey: sessionKey)
```

## Delivery states

``DeliveryState`` is **not** a simple plain enum; it is `Codable` and
carries associated values for failure and scheduling:

```swift
public enum DeliveryState: Codable, Sendable, Equatable {
    case delivered
    case read
    case received
    case waitingDelivery
    case none
    case blocked
    case failed(String)        // human-readable failure reason
    case sending
    case scheduled(Date)       // future delivery
}
```

Pattern-match exhaustively when rendering UI.

## Errors

Encryption and decryption surface ``CryptoError``. The most common
cause for a `nil` from ``EncryptedMessage/props(symmetricKey:)`` is a
key mismatch — typically a stale ``SessionContext/databaseEncryptionKey``
or a wrong app-symmetric-key derivation.

## See also

- ``CryptoMessage``
- ``DeliveryState``
- ``BaseCommunication``
- ``CryptoError``

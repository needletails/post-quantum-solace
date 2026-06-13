# ``BaseCommunication``

The encrypted, persistent representation of a communication channel —
direct chat, group chat, or broadcast — between members.

## Overview

`BaseCommunication` stores only `id` and an opaque ``BaseCommunication/data``
blob in plaintext. Everything else (members, blocked members,
administrator, operators, message count, application metadata, and the
``MessageRecipient`` discriminator) lives inside an encrypted
``BaseCommunication/UnwrappedProps`` payload that you decrypt at use
time with the session's symmetric key.

`Communication` is a plaintext-friendly companion struct returned by
``BaseCommunication/makeDecryptedModel(of:symmetricKey:)``. It is what
most application code consumes after decryption.

## Topics

### Initialization

- ``BaseCommunication/init(id:props:symmetricKey:)``
- ``BaseCommunication/init(id:data:)``

### Identity

- ``BaseCommunication/id``
- ``BaseCommunication/data``

### Decryption & updates

- ``BaseCommunication/UnwrappedProps``
- ``BaseCommunication/props(symmetricKey:)``
- ``BaseCommunication/decryptProps(symmetricKey:)``
- ``BaseCommunication/updateProps(symmetricKey:props:)``
- ``BaseCommunication/makeDecryptedModel(of:symmetricKey:)``

### Companion types

- ``Communication``
- ``CommunicationProtocol``
- ``MessageRecipient``
- ``ChannelInfo``
- ``ChannelStoredMetadata``
- ``ChannelLocalOverlay``

### Errors

- ``CryptoError``

## Working with communications

```swift
// Create.
let props = BaseCommunication.UnwrappedProps(
    sharedId: nil,
    messageCount: 0,
    administrator: myUserName,
    operators: nil,
    members: ["alice", "bob"],
    metadata: Data(),
    blockedMembers: [],
    communicationType: .channel("design")
)
let communication = try BaseCommunication(
    id: UUID(),
    props: props,
    symmetricKey: sessionKey
)
```

```swift
// Read.
guard let props = await communication.props(symmetricKey: sessionKey) else { return }
print(props.members, props.communicationType)
```

```swift
// Update — increment counter, persist.
guard var props = await communication.props(symmetricKey: sessionKey) else { return }
props.messageCount += 1
_ = try await communication.updateProps(symmetricKey: sessionKey, props: props)
```

## Application metadata

The `metadata: Data` field on `UnwrappedProps` is opaque to the SDK.
Encode whatever your app needs (preferences, channel description,
display configuration) using `BinaryEncoder`/`BinaryDecoder` or any
`Codable` representation, and store it as `Data`.

For channel-specific stored data and per-device overlays, see
``ChannelInfo``, ``ChannelStoredMetadata``, and ``ChannelLocalOverlay``.

## See also

- ``MessageRecipient``
- ``EncryptedMessage``
- ``ChannelInfo``
- ``CryptoError``

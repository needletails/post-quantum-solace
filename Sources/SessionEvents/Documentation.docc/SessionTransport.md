# ``SessionTransport``

The protocol you implement to plug the SDK into your network and key
distribution layer.

## Overview

`SessionTransport` defines every network operation the SDK needs:
sending encrypted messages, fetching and publishing user configurations,
managing one-time pre-keys (Curve25519 and ML-KEM), publishing rotated
keys, and producing upload packets for binary attachments.

The protocol is `Sendable`; every method is `async` and may be called
from the session actor's executor. Implementations must be thread-safe.

## Topics

### Message transport

- ``SessionTransport/sendMessage(_:metadata:)``

### User configuration

- ``SessionTransport/findConfiguration(for:)``
- ``SessionTransport/publishUserConfiguration(_:recipient:recipient:)``

### One-time keys

- ``SessionTransport/fetchOneTimeKeys(for:deviceId:)``
- ``SessionTransport/fetchOneTimeKeyIdentities(for:deviceId:type:)``
- ``SessionTransport/updateOneTimeKeys(for:deviceId:keys:)``
- ``SessionTransport/updateOneTimeMLKEMKeys(for:deviceId:keys:)``
- ``SessionTransport/deleteOneTimeKeys(for:with:type:)``
- ``SessionTransport/batchDeleteOneTimeKeys(for:with:type:)``

### Long-term key rotation

- ``SessionTransport/publishRotatedKeys(for:deviceId:rotated:)``

### Attachments

- ``SessionTransport/createUploadPacket(secretName:deviceId:recipient:metadata:)``

### Helper types

- ``SignedRatchetMessageMetadata``

## Implementation sketch

```swift
final class NetworkTransport: SessionTransport {
    let api: BackendAPI

    func sendMessage(_ message: SignedRatchetMessage,
                     metadata: SignedRatchetMessageMetadata) async throws {
        try await api.sendCiphertext(message,
                                     toSecretName: metadata.secretName,
                                     deviceId: metadata.deviceId,
                                     sharedMessageId: metadata.sharedMessageId,
                                     transportMetadata: metadata.transportMetadata)
    }

    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        try await api.fetchUserConfiguration(secretName: secretName)
    }

    func publishUserConfiguration(_ configuration: UserConfiguration,
                                  recipient secretName: String,
                                  recipient identity: UUID) async throws {
        try await api.publishUserConfiguration(configuration,
                                               secretName: secretName,
                                               deviceId: identity)
    }

    func fetchOneTimeKeys(for secretName: String,
                          deviceId: String) async throws -> OneTimeKeys {
        try await api.fetchOneTimeKeys(secretName: secretName, deviceId: deviceId)
    }

    func fetchOneTimeKeyIdentities(for secretName: String,
                                   deviceId: String,
                                   type: KeysType) async throws -> [UUID] {
        try await api.fetchOneTimeKeyIdentities(secretName: secretName,
                                                deviceId: deviceId,
                                                type: type)
    }

    func updateOneTimeKeys(for secretName: String,
                           deviceId: String,
                           keys: [UserConfiguration.SignedOneTimePublicKey]) async throws {
        try await api.uploadCurveOneTimeKeys(keys,
                                             secretName: secretName,
                                             deviceId: deviceId)
    }

    func updateOneTimeMLKEMKeys(for secretName: String,
                                deviceId: String,
                                keys: [UserConfiguration.SignedMLKEMOneTimeKey]) async throws {
        try await api.uploadMLKEMOneTimeKeys(keys,
                                             secretName: secretName,
                                             deviceId: deviceId)
    }

    func deleteOneTimeKeys(for secretName: String,
                           with id: String,
                           type: KeysType) async throws {
        try await api.deleteOneTimeKey(id: id,
                                       secretName: secretName,
                                       type: type)
    }

    func batchDeleteOneTimeKeys(for secretName: String,
                                with id: String,
                                type: KeysType) async throws {
        try await api.deleteOneTimeKeyBatch(id: id,
                                            secretName: secretName,
                                            type: type)
    }

    func publishRotatedKeys(for secretName: String,
                            deviceId: String,
                            rotated keys: RotatedPublicKeys) async throws {
        try await api.publishRotatedKeys(keys,
                                         secretName: secretName,
                                         deviceId: deviceId)
    }

    func createUploadPacket(secretName: String,
                            deviceId: UUID,
                            recipient: MessageRecipient,
                            metadata: Data) async throws {
        try await api.createUploadPacket(secretName: secretName,
                                         deviceId: deviceId,
                                         recipient: recipient,
                                         metadata: metadata)
    }
}
```

## Wiring up

Pass your conformer through ``SessionConfiguration``:

```swift
try await PQSSession.shared.configure(with: SessionConfiguration(
    transport: NetworkTransport(api: api),
    store: store,
    receiver: receiver
))
```

You can also swap the transport at runtime via
``PQSSession/setTransportDelegate(conformer:)``.

## Trust model interaction

`publishUserConfiguration(_:recipient:recipient:)` is the **only**
network publication path triggered from authenticated rotation
(``PQSSession/rotateKeysOnPotentialCompromise()``,
``PQSSession/updateUserConfiguration(_:)``). All inbound configurations
must flow through ``PQSSession/adoptVerifiedUserConfiguration(_:)``,
which enforces the local TOFU pin on the account-level signing key.

## See also

- ``PQSSession``
- ``PQSSessionStore``
- ``EventReceiver``
- ``SessionEvents``

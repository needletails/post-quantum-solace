# ``PQSNetworkHost``

The typealias you conform to when one object plugs the SDK into your network
and key-distribution layer: ``PQSTransport`` & ``PQSKeyDirectory`` &
``PQSRecoveryTransport``.

## Overview

The transport surface defines every network operation the SDK needs:

- ``PQSTransport`` — sending encrypted messages and producing upload packets
  for binary attachments.
- ``PQSKeyDirectory`` — fetching and publishing user configurations, managing
  one-time pre-keys (X25519 and ML-KEM), and publishing rotated keys.
- ``PQSRecoveryTransport`` — authenticated out-of-band resend requests.
  Hosts must implement these; there is no silent no-op.

All three protocols are `Sendable`; every method is `async` and may be called
from the session actor's executor. Implementations must be thread-safe.

## Topics

### Message transport

- ``PQSTransport/sendMessage(_:metadata:)``
- ``PQSTransport/createUploadPacket(secretName:deviceId:recipient:metadata:)``

### User configuration

- ``PQSKeyDirectory/findConfiguration(for:)``
- ``PQSKeyDirectory/publishUserConfiguration(_:recipient:recipient:)``

### One-time keys

- ``PQSKeyDirectory/fetchOneTimeKeys(for:deviceId:)``
- ``PQSKeyDirectory/fetchOneTimeKeyIdentities(for:deviceId:type:)``
- ``PQSKeyDirectory/updateOneTimeKeys(for:deviceId:keys:)``
- ``PQSKeyDirectory/updateOneTimeMLKEMKeys(for:deviceId:keys:)``
- ``PQSKeyDirectory/deleteOneTimeKeys(for:with:type:)``
- ``PQSKeyDirectory/batchDeleteOneTimeKeys(for:with:type:)``

### Long-term key rotation

- ``PQSKeyDirectory/publishRotatedKeys(for:deviceId:rotated:)``

### Out-of-band recovery

- ``PQSRecoveryTransport/sendOutOfBandResendRequest(failedEnvelopeMessageIds:to:deviceId:requestingDeviceId:)``
- ``PQSRecoveryTransport/sendOutOfBandResendUnavailable(unavailableEnvelopeMessageIds:to:deviceId:respondingDeviceId:)``

### Helper types

- ``SignedRatchetMessageMetadata``

## Implementation sketch

```swift
final class NetworkTransport: PQSNetworkHost {
    let api: BackendAPI

    // MARK: PQSTransport

    func sendMessage(_ message: SignedRatchetMessage,
                     metadata: SignedRatchetMessageMetadata) async throws {
        try await api.sendCiphertext(message,
                                     toSecretName: metadata.secretName,
                                     deviceId: metadata.deviceId,
                                     sharedMessageId: metadata.sharedMessageId,
                                     transportMetadata: metadata.transportMetadata)
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

    // MARK: PQSKeyDirectory

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
                                   type: KeyKind) async throws -> [UUID] {
        try await api.fetchOneTimeKeyIdentities(secretName: secretName,
                                                deviceId: deviceId,
                                                type: type)
    }

    func updateOneTimeKeys(for secretName: String,
                           deviceId: String,
                           keys: [UserConfiguration.SignedOneTimePublicKey]) async throws {
        try await api.uploadX25519OneTimeKeys(keys,
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
                           type: KeyKind) async throws {
        try await api.deleteOneTimeKey(id: id,
                                       secretName: secretName,
                                       type: type)
    }

    func batchDeleteOneTimeKeys(for secretName: String,
                                with id: String,
                                type: KeyKind) async throws {
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

    // MARK: PQSRecoveryTransport

    func sendOutOfBandResendRequest(failedEnvelopeMessageIds: [String],
                                    to secretName: String,
                                    deviceId: UUID,
                                    requestingDeviceId: UUID) async throws {
        try await api.requestResend(ids: failedEnvelopeMessageIds,
                                    secretName: secretName,
                                    deviceId: deviceId,
                                    requestingDeviceId: requestingDeviceId)
    }

    func sendOutOfBandResendUnavailable(unavailableEnvelopeMessageIds: [String],
                                        to secretName: String,
                                        deviceId: UUID,
                                        respondingDeviceId: UUID) async throws {
        try await api.reportResendUnavailable(ids: unavailableEnvelopeMessageIds,
                                              secretName: secretName,
                                              deviceId: deviceId,
                                              respondingDeviceId: respondingDeviceId)
    }
}
```

> Important: `publishUserConfiguration(_:recipient:recipient:)` takes **two**
> `recipient`-prefixed parameters: the recipient's `secretName` and the
> recipient device's `UUID`.

## Wiring up

Pass your conformer through `SessionConfiguration`:

```swift
let session = await PQSSession(configuration: SessionConfiguration(
    transport: NetworkTransport(api: api),
    store: store,
    observer: observer
))
```

If your host splits transport responsibilities across objects, conform each
object to just the granular protocol it implements.

## Trust model interaction

`publishUserConfiguration(_:recipient:recipient:)` is the **only** network
publication path triggered from authenticated rotation
(`PQSSession.rotateKeysOnPotentialCompromise()`,
`PQSSession.updateUserConfiguration(_:)`). All inbound configurations must
flow through `PQSSession.adoptVerifiedUserConfiguration(_:)`, which enforces
the local TOFU pin on the account-level signing key.

## See also

- ``PQSPersistenceHost``
- ``MessageStoreObserver``
- ``PQSHostDelegate``

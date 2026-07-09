# ``PQSSessionDelegate``

A delegate protocol that exposes application-level hooks for the
cryptographic messaging session.

## Overview

`PQSSessionDelegate` is the smallest of the four delegate surfaces, but
also the most policy-heavy. It lets your application inject decisions —
should a transport message be persisted, what is the sender's identity,
should automatic delivery receipts be emitted — and react to compromise
signals from linked devices.

Default implementations are provided for the optional methods listed under
**Optional hooks** below; the remaining methods are required.

The protocol is `Sendable`. All methods are invoked on the session actor
and should be implemented to return quickly.

## Topics

### Sender resolution

- ``PQSSessionDelegate/retrieveUserInfo(_:)``

### Persistence policy

- ``PQSSessionDelegate/shouldPersist(transportInfo:)``
- ``PQSSessionDelegate/processMessage(_:senderSecretName:senderDeviceId:)``
- ``PQSSessionDelegate/shouldFinishCommunicationSynchronization(_:)``

### Communication & contact management

- ``PQSSessionDelegate/synchronizeCommunication(recipient:sharedIdentifier:metadata:)``
- ``PQSSessionDelegate/contactCreated(recipient:)``
- ``PQSSessionDelegate/requestMetadata(recipient:)``
- ``PQSSessionDelegate/requestFriendshipStateChange(recipient:blockData:metadata:currentState:)``

### Message lifecycle

- ``PQSSessionDelegate/deliveryStateChanged(recipient:metadata:)``
- ``PQSSessionDelegate/editMessage(recipient:metadata:)``
- ``PQSSessionDelegate/updateCryptoMessageMetadata(_:sharedMessageId:)``
- ``PQSSessionDelegate/updateEncryptableMessageMetadata(_:transportInfo:identity:recipient:)``

### Receipts, compromise & identity

- ``PQSSessionDelegate/shouldSendAutomaticDeliveryReceipts()``
- ``PQSSessionDelegate/linkedDeviceReportedPotentialCompromise(deviceId:intentId:)``
- ``PQSSessionDelegate/peerAccountIdentityChanged(secretName:deviceId:failedSharedMessageId:)``

### Friendship bootstrap & inbound recovery (optional)

- ``PQSSessionDelegate/preferredOnlinePeerDeviceId(for:)``
- ``PQSSessionDelegate/shouldSuppressInboundRecoveryFromSender(_:)``
- ``PQSSessionDelegate/inboundRecoveryDeferred(senderSecretName:senderDeviceId:failedSharedMessageId:failureClass:)``
- ``PQSSessionDelegate/shouldReplayNonPersistentOutbound(transportInfo:)``

## Optional hooks

These methods have default implementations in a protocol extension:

| Method | Default |
| ------ | ------- |
| ``shouldSendAutomaticDeliveryReceipts()`` | `true` |
| ``linkedDeviceReportedPotentialCompromise(deviceId:intentId:)`` | no-op |
| ``peerAccountIdentityChanged(secretName:deviceId:failedSharedMessageId:)`` | no-op |
| ``preferredOnlinePeerDeviceId(for:)`` | `nil` |
| ``shouldSuppressInboundRecoveryFromSender(_:)`` | `false` |
| ``inboundRecoveryDeferred(senderSecretName:senderDeviceId:failedSharedMessageId:failureClass:)`` | no-op |
| ``shouldReplayNonPersistentOutbound(transportInfo:)`` | `false` |

### Live-device preference for OTK bootstrap

Published account configs can still list ghost devices after reinstall.
Override ``preferredOnlinePeerDeviceId(for:)`` with the currently online
(ISON / presence) device id so
``PQSSession/bootstrapPeerContactSession(secretName:purpose:)`` does not
route handshake notify to an offline ghost that still looks like master.
See <doc:FriendshipContactBootstrap>.

### Friendship `blockData`

``requestFriendshipStateChange(recipient:blockData:metadata:currentState:)``
receives optional `blockData`. For `.requested`, `.accepted`, and `.pending`,
the SDK sends `blockData=false` so the server can clear a stale
`blockedUsers` entry **before** routing. Hosts must apply that unblock before
delivery checks.

## Example

```swift
final class AppSessionDelegate: PQSSessionDelegate {
    func synchronizeCommunication(recipient: MessageRecipient,
                                  sharedIdentifier: String,
                                  metadata: Data) async throws {
        try await api.publish(syncEnvelope(metadata),
                              sharedIdentifier: sharedIdentifier,
                              recipient: recipient)
    }

    func requestFriendshipStateChange(recipient: MessageRecipient,
                                      blockData: Data?,
                                      metadata: Data,
                                      currentState: FriendshipMetadata.State) async throws {
        try await api.updateFriendship(recipient: recipient,
                                       state: currentState,
                                       blockData: blockData,
                                       metadata: metadata)
    }

    func deliveryStateChanged(recipient: MessageRecipient, metadata: Data) async throws {
        try await api.updateDeliveryState(recipient: recipient, metadata: metadata)
    }

    func contactCreated(recipient: MessageRecipient) async throws {
        await UI.showContactCreated(recipient)
    }

    func requestMetadata(recipient: MessageRecipient) async throws {
        try await api.requestMetadata(recipient: recipient)
    }

    func editMessage(recipient: MessageRecipient, metadata: Data) async throws {
        try await api.editMessage(recipient: recipient, metadata: metadata)
    }

    func shouldPersist(transportInfo: Data?) -> Bool {
        // Drop ephemeral control envelopes.
        guard let transportInfo,
              let envelope = try? BinaryDecoder().decode(MyTransportEnvelope.self,
                                                        from: transportInfo) else {
            return true
        }
        return envelope.kind != .ephemeralControl
    }

    func retrieveUserInfo(_ transportInfo: Data?) async -> (secretName: String, deviceId: String)? {
        guard let transportInfo,
              let envelope = try? BinaryDecoder().decode(MyTransportEnvelope.self,
                                                        from: transportInfo) else {
            return nil
        }
        return (envelope.senderSecretName, envelope.senderDeviceId)
    }

    func updateCryptoMessageMetadata(_ message: CryptoMessage,
                                     sharedMessageId: String) -> CryptoMessage {
        var copy = message
        copy.metadata = stamp(copy.metadata, sharedId: sharedMessageId)
        return copy
    }

    func updateEncryptableMessageMetadata(_ message: EncryptedMessage,
                                          transportInfo: Data?,
                                          identity: SessionIdentity,
                                          recipient: MessageRecipient) async -> EncryptedMessage {
        message
    }

    func shouldFinishCommunicationSynchronization(_ transportInfo: Data?) -> Bool {
        true
    }

    func processMessage(_ message: CryptoMessage,
                        senderSecretName: String,
                        senderDeviceId: UUID) async -> Bool {
        await Router.handleEphemeral(message,
                                     from: senderSecretName,
                                     deviceId: senderDeviceId)
    }

    func shouldSendAutomaticDeliveryReceipts() async -> Bool {
        await UserPreferences.deliveryReceiptsEnabled
    }

    func linkedDeviceReportedPotentialCompromise(deviceId: UUID,
                                                 intentId: UUID?) async {
        await UI.surfaceCompromiseAlert(deviceId: deviceId, intentId: intentId)
    }

    func peerAccountIdentityChanged(secretName: String,
                                    deviceId: UUID,
                                    failedSharedMessageId: String?) async {
        await UI.surfacePeerSafetyNumberChange(
            secretName: secretName,
            deviceId: deviceId,
            failedMessageId: failedSharedMessageId)
    }

    func preferredOnlinePeerDeviceId(for secretName: String) async -> UUID? {
        await Presence.onlineDeviceId(for: secretName)
    }

    func shouldSuppressInboundRecoveryFromSender(_ senderSecretName: String) async -> Bool {
        await ContactStore.isLocallyDeleted(senderSecretName)
    }
}
```

## Wiring up

Pass your conformer through ``SessionConfiguration``:

```swift
try await PQSSession.shared.configure(with: SessionConfiguration(
    transport: transport,
    store: store,
    receiver: receiver,
    delegate: AppSessionDelegate()
))
```

You can swap the delegate at runtime via
``PQSSession/setPQSSessionDelegate(conformer:)``.

## See also

- ``PQSSession``
- ``SessionConfiguration``
- ``SessionEvents``
- ``EventReceiver``
- <doc:FriendshipContactBootstrap>

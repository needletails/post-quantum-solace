# ``PQSHostDelegate``

The optional host delegate typealias: ``MessagingPolicy`` &
``RecoveryObserver``.

## Overview

The host delegate is the smallest of the host surfaces, but also the most
policy-heavy. It lets your application inject decisions — should a transport
message be persisted, what is the sender's identity, should automatic
delivery receipts be emitted — and react to compromise and recovery signals.

- ``MessagingPolicy`` — persistence policy, sender resolution, metadata
  hooks, and friendship/contact side effects.
- ``RecoveryObserver`` — inbound/outbound recovery signals, compromise
  notifications, and multi-device bootstrap hints. All recovery hooks ship
  with no-op defaults, so conformers only override what they need.

The protocols are `Sendable`. All methods are invoked on the session actor
and should be implemented to return quickly.

## Topics

### Policy surface

- ``MessagingPolicy``

### Recovery surface

- ``RecoveryObserver``

## Optional hooks

These methods have default implementations in a protocol extension:

| Method | Default |
| ------ | ------- |
| `shouldSendAutomaticDeliveryReceipts()` | `true` |
| `linkedDeviceReportedPotentialCompromise(deviceId:intentId:)` | no-op |
| `peerAccountIdentityChanged(secretName:deviceId:failedSharedMessageId:)` | no-op |
| `preferredOnlinePeerDeviceId(for:)` | `nil` |
| `shouldSuppressInboundRecoveryFromSender(_:)` | `false` |
| `inboundRecoveryDeferred(senderSecretName:senderDeviceId:failedSharedMessageId:failureClass:)` | no-op |
| `shouldReplayNonPersistentOutbound(transportInfo:)` | `false` |

### Live-device preference for OTK bootstrap

Published account configs can still list ghost devices after reinstall.
Override ``RecoveryObserver/preferredOnlinePeerDeviceId(for:)`` with the
currently online (ISON / presence) device id so
`PQSSession.bootstrapPeerContactSession(secretName:purpose:)` does not route
handshake notify to an offline ghost that still looks like master.

### Friendship `blockData`

``MessagingPolicy/requestFriendshipStateChange(recipient:blockData:metadata:currentState:)``
receives optional `blockData`. For `.requested`, `.accepted`, and `.pending`,
the SDK sends `blockData=false` so the server can clear a stale
`blockedUsers` entry **before** routing. Hosts must apply that unblock before
delivery checks.

## Example

```swift
final class AppHostDelegate: PQSHostDelegate {
    // MARK: MessagingPolicy

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

    func createdContact(recipient: MessageRecipient) async throws {
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

    // MARK: RecoveryObserver

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

Pass your conformer through `SessionConfiguration`:

```swift
let session = await PQSSession(configuration: SessionConfiguration(
    transport: transport,
    store: store,
    observer: observer,
    delegate: AppHostDelegate()
))
```

If your host splits policy and recovery across objects, conform one object to
``MessagingPolicy`` and another to ``RecoveryObserver`` and compose them
behind a small `PQSHostDelegate` wrapper.

## See also

- ``PQSNetworkHost``
- ``PQSPersistenceHost``
- ``MessageStoreObserver``

# ``PQSSessionDelegate``

A delegate protocol that exposes application-level hooks for the
cryptographic messaging session.

## Overview

`PQSSessionDelegate` is the smallest of the four delegate surfaces, but
also the most policy-heavy. It lets your application inject decisions —
should a transport message be persisted, what is the sender's identity,
should automatic delivery receipts be emitted — and react to compromise
signals from linked devices.

Default implementations are provided for the optional methods
``shouldSendAutomaticDeliveryReceipts()`` and
``linkedDeviceReportedPotentialCompromise(deviceId:intentId:)``; the
remaining methods are required.

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

### Receipts & compromise

- ``PQSSessionDelegate/shouldSendAutomaticDeliveryReceipts()``
- ``PQSSessionDelegate/linkedDeviceReportedPotentialCompromise(deviceId:intentId:)``

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

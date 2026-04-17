# ``SessionEvents``

The protocol that drives the session's contact, friendship, and
message-state side effects.

## Overview

`SessionEvents` is an *override surface*: the SDK ships a complete
default implementation in a protocol extension. Conform to it only when
you need to alter how contacts are added, how friendship state changes,
how message delivery state propagates, or how communication
synchronization is sent.

By default, `PQSSession` itself conforms to `SessionEvents` and uses the
extension methods. You can install your own conformer at runtime via
``PQSSession/setSessionEventDelegate(conformer:)`` to intercept any of
these flows.

The protocol is `Sendable`. Every method is `async`.

## Topics

### Contact lifecycle

- ``SessionEvents/addContacts(_:sessionContext:cache:transport:receiver:sessionDelegate:symmetricKey:logger:)``
- ``SessionEvents/createContact(secretName:metadata:friendshipMetadata:requestFriendship:sessionContext:cache:transport:receiver:symmetricKey:logger:)``
- ``SessionEvents/sendCommunicationSynchronization(recipient:metadata:sessionContext:sessionDelegate:cache:receiver:symmetricKey:logger:)``
- ``SessionEvents/sendContactCreatedAcknowledgment(recipient:sessionDelegate:logger:)``

### Friendship state

- ``SessionEvents/requestFriendshipStateChange(state:contact:cache:receiver:sessionDelegate:symmetricKey:logger:)``

### Message lifecycle

- ``SessionEvents/updateMessageDeliveryState(_:deliveryState:messageRecipient:allowExternalUpdate:sessionDelegate:cache:receiver:symmetricKey:)``
- ``SessionEvents/editCurrentMessage(_:newText:sessionDelegate:cache:receiver:symmetricKey:logger:)``

### Metadata

- ``SessionEvents/requestMetadata(from:sessionDelegate:logger:)``
- ``SessionEvents/requestMyMetadata(sessionDelegate:logger:)``

### Lookup

- ``SessionEvents/findCommunication(for:cache:symmetricKey:)``

## Customising the default implementation

```swift
struct LoggingSessionEvents: SessionEvents {
    func addContacts(_ contactInfos: [SharedContactInfo],
                     sessionContext: SessionContext,
                     cache: PQSSessionStore,
                     transport: SessionTransport,
                     receiver: EventReceiver,
                     sessionDelegate: PQSSessionDelegate,
                     symmetricKey: SymmetricKey,
                     logger: NeedleTailLogger) async throws {
        analytics.recordContactImport(count: contactInfos.count)

        // Forward to the protocol-extension default implementation.
        try await (self as SessionEvents).addContacts(
            contactInfos,
            sessionContext: sessionContext,
            cache: cache,
            transport: transport,
            receiver: receiver,
            sessionDelegate: sessionDelegate,
            symmetricKey: symmetricKey,
            logger: logger
        )
    }
}

try await PQSSession.shared.setSessionEventDelegate(conformer: LoggingSessionEvents())
```

You normally do **not** need to implement `SessionEvents` yourself —
`PQSSession` already does. Use ``PQSSessionDelegate`` for transport-side
hooks and ``EventReceiver`` for UI-side notifications.

## See also

- ``PQSSession``
- ``PQSSessionDelegate``
- ``EventReceiver``
- ``SessionTransport``

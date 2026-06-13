# ``EventReceiver``

A protocol that defines methods for receiving events related to messages,
contacts, and communications.

## Overview

`EventReceiver` is the application-facing event surface of the SDK. The
`PQSSession` calls into your conformer whenever the local store changes —
inbound and outbound messages, contact updates, channel lifecycle, and
contact-metadata refreshes. Implementations should be cheap and
idempotent; they are invoked from the actor's executor and should not
block on long-running UI work.

All methods are `async`; the protocol is `Sendable`.

## Topics

### Message events

- ``EventReceiver/createdMessage(_:)``
- ``EventReceiver/updatedMessage(_:)``
- ``EventReceiver/deletedMessage(_:)``

### Contact events

- ``EventReceiver/createdContact(_:)``
- ``EventReceiver/updateContact(_:)``
- ``EventReceiver/contactMetadata(changed:)``
- ``EventReceiver/synchronize(contact:requestFriendship:)``
- ``EventReceiver/transportContactMetadata()``

### Communication events

- ``EventReceiver/updatedCommunication(_:members:)``
- ``EventReceiver/createdChannel(_:)``
- ``EventReceiver/removedCommunication(_:)``

## Example

```swift
final class AppEventReceiver: EventReceiver {
    func createdMessage(_ message: EncryptedMessage) async {
        await UI.append(message)
    }

    func updatedMessage(_ message: EncryptedMessage) async {
        await UI.update(message)
    }

    func deletedMessage(_ message: EncryptedMessage) async {
        await UI.remove(message)
    }

    func createdContact(_ contact: Contact) async throws {
        await UI.contacts.insert(contact)
    }

    func updateContact(_ contact: Contact) async throws {
        await UI.contacts.update(contact)
    }

    func removedCommunication(_ type: MessageRecipient) async throws {
        await UI.removeThread(for: type)
    }

    func synchronize(contact: Contact, requestFriendship: Bool) async throws {
        await UI.markPendingSync(contact, requestFriendship: requestFriendship)
    }

    func transportContactMetadata() async throws {
        try await api.uploadMyMetadata()
    }

    func contactMetadata(changed contact: Contact) async {
        await UI.refreshHeader(for: contact)
    }

    func updatedCommunication(_ model: BaseCommunication,
                              members: Set<String>) async {
        await UI.updateThread(model, members: members)
    }

    func createdChannel(_ model: BaseCommunication) async {
        await UI.openChannel(model)
    }
}
```

## Wiring up

Pass your conformer through ``SessionConfiguration``:

```swift
try await PQSSession.shared.configure(with: SessionConfiguration(
    transport: transport,
    store: store,
    receiver: AppEventReceiver()
))
```

You can swap the receiver later via
``PQSSession/setReceiverDelegate(conformer:)``.

## See also

- ``PQSSession``
- ``SessionEvents``
- ``PQSSessionDelegate``
- ``SessionTransport``

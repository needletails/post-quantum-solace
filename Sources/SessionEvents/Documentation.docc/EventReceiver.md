# ``EventReceiver``

A protocol that defines methods for receiving events related to messages and contacts.

## Overview

`EventReceiver` provides the interface for application-level event handling, allowing your application to respond to message creation, contact updates, and communication changes.

## Topics

### Message Events

- ``EventReceiver/createdMessage(_:)``
- ``EventReceiver/updatedMessage(_:)``

### Contact Events

- ``EventReceiver/createdContact(_:)``
- ``EventReceiver/updatedContact(_:)``

### Communication Events

- ``EventReceiver/createdCommunication(_:members:)``
- ``EventReceiver/updatedCommunication(_:members:)``

## Usage

```swift
class AppEventReceiver: EventReceiver {
    func createdMessage(_ message: EncryptedMessage) async {
        // Handle new message
        await updateUI(with: message)
    }
    
    func updatedCommunication(_ model: BaseCommunication, members: Set<String>) async {
        // Handle communication update
        await refreshChannelList()
    }
    
    // Implement other required methods...
}
```

## See Also

- ``PQSSession``
- ``SessionEvents``

# ``SessionEvents``

A protocol that defines methods for handling session events, with default implementations via extensions.

## Overview

`SessionEvents` provides a comprehensive interface for managing session-related operations including contact management, friendship state changes, message delivery tracking, and communication synchronization.

## Topics

### Contact Management

- ``SessionEvents/addContacts(_:sessionContext:cache:transport:receiver:sessionDelegate:symmetricKey:logger:)``

### Message Handling

- ``SessionEvents/processWrite(message:session:)``
- ``SessionEvents/receiveMessage(message:sender:deviceId:messageId:session:)``

## Key Features

- **Default Implementations**: Protocol extensions provide default behavior
- **Customizable**: Override methods to customize behavior
- **Comprehensive**: Covers all major session operations

## Usage

```swift
class CustomSessionEvents: SessionEvents {
    // Override default implementations as needed
    func addContacts(...) async throws {
        // Custom contact handling
    }
}
```

## See Also

- ``PQSSession``
- ``EventReceiver``

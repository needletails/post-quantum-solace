# ``PQSSessionDelegate``

A protocol that provides hooks for application-specific session logic.

## Overview

`PQSSessionDelegate` allows you to customize session behavior by providing callbacks for key lifecycle events and operations.

## Topics

### Session Lifecycle

- ``PQSSessionDelegate/sessionDidStart()``
- ``PQSSessionDelegate/sessionDidShutdown()``

### Key Management

- ``PQSSessionDelegate/sessionDidRotateKeys()``

## Usage

```swift
class MySessionDelegate: PQSSessionDelegate {
    func sessionDidStart() async {
        // Handle session start
        await notifyUser("Session started")
    }
    
    func sessionDidShutdown() async {
        // Handle session shutdown
        await cleanup()
    }
    
    // Implement other methods as needed...
}
```

## See Also

- ``PQSSession``
- ``SessionConfiguration``

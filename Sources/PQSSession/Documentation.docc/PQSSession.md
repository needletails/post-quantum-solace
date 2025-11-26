# ``PQSSession``

The main session manager for the Post-Quantum Solace SDK, orchestrating all cryptographic operations and managing the session lifecycle.

## Overview

`PQSSession` is a singleton actor that serves as the central entry point for the SDK. It manages cryptographic sessions, key management, secure communication channels, and coordinates all SDK components.

## Topics

### Essentials

- ``PQSSession/shared``
- ``PQSSession/configure(with:)``
- ``PQSSession/isViable``

### Session Lifecycle

- ``PQSSession/createSession(secretName:appPassword:createInitialTransport:)``
- ``PQSSession/startSession(appPassword:)``
- ``PQSSession/shutdown()``

### Configuration

- ``SessionConfiguration``
- ``PQSSession/configure(with:)``
- ``PQSSession/setTransportDelegate(conformer:)``
- ``PQSSession/setDatabaseDelegate(conformer:)``
- ``PQSSession/setReceiverDelegate(conformer:)``

### Constants

- ``PQSSessionConstants``

### Error Handling

- ``PQSSession/SessionErrors``

## Key Features

- **Post-Quantum Security**: MLKEM1024 for long-term security
- **Forward Secrecy**: Double Ratchet protocol implementation
- **Device Management**: Master/child device support
- **Automatic Key Rotation**: Compromise recovery and key freshness
- **Thread Safety**: Actor-based concurrency model
- **Singleton Pattern**: Single shared instance for consistent state

## Usage

### Basic Setup

```swift
let session = PQSSession.shared

// Configure with SessionConfiguration (recommended)
let config = SessionConfiguration(
    transport: myTransport,
    store: myStore,
    receiver: myReceiver
)
try await session.configure(with: config)

// Create and start session
try await session.createSession(
    secretName: "alice",
    appPassword: "securePassword",
    createInitialTransport: setupTransport
)
try await session.startSession(appPassword: "securePassword")
```

### Sending Messages

```swift
try await session.writeTextMessage(
    recipient: .nickname("bob"),
    text: "Hello, world!",
    metadata: ["timestamp": Date()],
    destructionTime: 3600
)
```

### Error Handling

All errors conform to `LocalizedError`:

```swift
do {
    try await session.writeTextMessage(...)
} catch let error as PQSSession.SessionErrors {
    if let localizedError = error as? LocalizedError {
        print("Error: \(localizedError.errorDescription ?? "")")
        if let suggestion = localizedError.recoverySuggestion {
            print("Suggestion: \(suggestion)")
        }
    }
}
```

## Configuration Constants

Use `PQSSessionConstants` for configuration values:

```swift
// Key refresh threshold
PQSSessionConstants.oneTimeKeyLowWatermark  // Default: 10

// Batch size for key generation
PQSSessionConstants.oneTimeKeyBatchSize     // Default: 100

// Key rotation interval
PQSSessionConstants.keyRotationIntervalDays // Default: 7
```

## Thread Safety

`PQSSession` is an actor, ensuring thread-safe concurrent access to all session operations.

## See Also

- ``SessionConfiguration``
- ``PQSSessionConstants``
- ``PQSSession/SessionErrors``

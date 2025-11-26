# SessionModels

Core data structures with built-in encryption and secure serialization.

## Overview

The `SessionModels` module provides all the data structures used throughout the SDK, including encrypted messages, communications, contacts, and session state.

## Topics

### Core Models

- ``EncryptedMessage``
- ``BaseCommunication``
- ``Contact``
- ``SessionContext``
- ``UserConfiguration``

### Error Handling

- ``CryptoError``

## Key Features

- **Built-in Encryption**: All sensitive data is encrypted
- **Thread Safety**: All models conform to `Sendable`
- **Secure Serialization**: Obfuscated field names for security
- **Comprehensive Error Handling**: All errors conform to `LocalizedError`

## Error Handling

All cryptographic errors conform to `LocalizedError`:

```swift
do {
    try await communication.updateProps(symmetricKey: key, props: newProps)
} catch let error as CryptoError {
    if let localizedError = error as? LocalizedError {
        print("Error: \(localizedError.errorDescription ?? "")")
        if let suggestion = localizedError.recoverySuggestion {
            print("Suggestion: \(suggestion)")
        }
    }
}
```

## See Also

- ``EncryptedMessage``
- ``BaseCommunication``
- ``CryptoError``

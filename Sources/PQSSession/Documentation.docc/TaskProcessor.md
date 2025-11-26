# ``TaskProcessor``

An actor that manages asynchronous encryption/decryption tasks using dedicated cryptographic executors.

## Overview

`TaskProcessor` handles all cryptographic operations for the SDK, including message encryption/decryption, key management, and Double Ratchet protocol operations.

## Topics

### Essentials

- ``TaskProcessor/init(logger:ratchetConfiguration:)``

### Error Handling

- ``TaskProcessor/JobProcessorErrors``

## Key Features

- **Dedicated Executors**: Cryptographic operations on separate queues
- **Thread Safety**: Actor-based concurrent access
- **Task Sequencing**: Ensures proper ordering of cryptographic operations
- **Error Handling**: Comprehensive error handling with `LocalizedError`

## Error Handling

All errors conform to `LocalizedError`:

```swift
do {
    try await taskProcessor.performRatchet(...)
} catch let error as TaskProcessor.JobProcessorErrors {
    if let localizedError = error as? LocalizedError {
        print("Error: \(localizedError.errorDescription ?? "")")
        if let suggestion = localizedError.recoverySuggestion {
            print("Suggestion: \(suggestion)")
        }
    }
}
```

## See Also

- ``CryptoExecutor``
- ``TaskProcessor/JobProcessorErrors``

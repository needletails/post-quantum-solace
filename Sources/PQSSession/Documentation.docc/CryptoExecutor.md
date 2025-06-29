# ``CryptoExecutor``

A thread-safe executor for cryptographic operations that provides both task-based and serial execution modes.

## Overview

The `CryptoExecutor` ensures that all cryptographic operations are performed on a dedicated dispatch queue, preventing interference with other system operations and maintaining consistent performance characteristics for security-critical computations.

## Topics

### Essentials

- ``CryptoExecutor/init(queue:shouldExecuteAsTask:)``
- ``CryptoExecutor/queue``
- ``CryptoExecutor/shouldExecuteAsTask``

### Execution

- ``CryptoExecutor/enqueue(_:)``
- ``CryptoExecutor/checkIsolated()``

### Executor Types

- ``CryptoExecutor/asUnownedTaskExecutor()``
- ``CryptoExecutor/asUnownedSerialExecutor()``

## Key Features

- **Thread Safety**: All operations performed through this executor are guaranteed to run on the specified dispatch queue
- **Isolation Checks**: Provides runtime checks to ensure operations are running on the correct queue
- **Flexible Execution**: Supports both task-based and serial execution modes
- **Performance Optimization**: Uses dedicated queues with appropriate QoS levels
- **Security Focus**: Designed specifically for cryptographic operations

## Security Notes

- Never share the same executor instance across different security contexts
- Ensure the dispatch queue is not accessible from other parts of the application
- Consider using different executors for different types of cryptographic operations

## Usage

### Creating a Crypto Executor

```swift
// Create a dedicated queue for crypto operations
let cryptoQueue = DispatchQueue(label: "com.needletail.crypto", qos: .userInitiated)
let executor = CryptoExecutor(queue: cryptoQueue)

// Execute a cryptographic job
executor.enqueue {
    // Perform cryptographic operations here
    let encrypted = try encrypt(data: messageData, with: key)
    return encrypted
}
```

### Using Task-Based Execution

```swift
let executor = CryptoExecutor(queue: cryptoQueue, shouldExecuteAsTask: true)

// Execute as Swift concurrency task
let taskExecutor = executor.asUnownedTaskExecutor()
Task(executorPreference: taskExecutor) {
    // This runs on the crypto queue as a Swift task
    let signature = try sign(data: messageData, with: privateKey)
    return signature
}
```

### Using Serial Execution

```swift
let executor = CryptoExecutor(queue: cryptoQueue, shouldExecuteAsTask: false)

// Execute as serial operation
let serialExecutor = executor.asUnownedSerialExecutor()
await withTaskGroup(of: Data.self) { group in
    group.addTask(executorPreference: serialExecutor) {
        // This runs serially on the crypto queue
        return try encrypt(data: messageData, with: key)
    }
}
```

### Queue Isolation Checks

```swift
func performCryptoOperation() {
    cryptoExecutor.checkIsolated()
    // Safe to perform crypto operations here
    // This will crash if called from the wrong queue
}
```

## Performance Considerations

- Use a dedicated queue with appropriate QoS level for crypto operations
- Consider using `.userInitiated` or `.userInteractive` QoS for real-time operations
- The executor supports both task-based and serial execution modes
- Task-based execution provides better integration with Swift concurrency

## Integration with TaskProcessor

The `TaskProcessor` uses `CryptoExecutor` for cryptographic operations:

```swift
// Crypto executor for message encryption/decryption
private let cryptoExecutor = CryptoExecutor(
    queue: DispatchQueue(label: "com.needletails.crypto-executor-queue"),
    shouldExecuteAsTask: false
)

// Key transport executor for key operations
let keyTransportExecutor = CryptoExecutor(
    queue: DispatchQueue(label: "com.needletails.key-transport-executor-queue"),
    shouldExecuteAsTask: false
)
```

## Best Practices

### Queue Management
- Use descriptive queue labels for debugging
- Choose appropriate QoS levels for your use case
- Avoid sharing queues between different security contexts
- Monitor queue performance and adjust as needed

### Execution Mode Selection
- Use task-based execution for better Swift concurrency integration
- Use serial execution for operations that must be strictly ordered
- Consider the performance implications of each mode

### Error Handling
- Handle cryptographic errors appropriately
- Implement proper fallback mechanisms
- Log errors for debugging without exposing sensitive data

### Security
- Never expose cryptographic keys or sensitive data
- Use proper isolation between different security contexts
- Implement secure key management
- Follow cryptographic best practices

## Thread Safety

The `CryptoExecutor` is designed for concurrent access:
- **Queue Isolation**: All operations run on the specified dispatch queue
- **Thread Safety**: Operations are guaranteed to be thread-safe
- **Concurrent Access**: Multiple operations can be enqueued concurrently
- **Proper Isolation**: Runtime checks ensure correct queue usage 
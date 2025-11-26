# ``SessionCache``

A two-tier caching system providing in-memory and persistent storage for session data.

## Overview

`SessionCache` is an actor that implements `PQSSessionStore` and provides efficient caching of session data with both in-memory and persistent storage layers.

## Topics

### Essentials

- ``SessionCache/init(store:)``

### Error Handling

- ``SessionCache/CacheErrors``

## Key Features

- **Two-Tier Caching**: In-memory cache with persistent storage backing
- **Thread Safety**: Actor-based concurrent access
- **Comprehensive Error Handling**: All errors conform to `LocalizedError`
- **Efficient Lookups**: Fast in-memory access with persistent fallback

## Error Handling

All errors conform to `LocalizedError`:

```swift
do {
    try await cache.fetchMessage(id: messageId)
} catch let error as SessionCache.CacheErrors {
    if let localizedError = error as? LocalizedError {
        print("Error: \(localizedError.errorDescription ?? "")")
        if let suggestion = localizedError.recoverySuggestion {
            print("Suggestion: \(suggestion)")
        }
    }
}
```

## See Also

- ``PQSSessionStore``
- ``SessionCache/CacheErrors``

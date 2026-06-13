# ``SessionCache``

A two-tier `actor` that backs ``PQSSession`` with an in-memory hot path
sitting on top of any application-supplied ``PQSSessionStore``.

## Overview

`SessionCache` is the only `PQSSessionStore` consumer the SDK ever wires up
itself. When you call ``PQSSession/setDatabaseDelegate(conformer:)`` (or
``PQSSession/configure(with:)``), the SDK wraps your concrete store in a
`SessionCache` and uses *that* for all storage operations. You normally do
not construct one directly; the SDK does it for you.

The cache:

- Conforms to ``PQSSessionStore`` itself, so call sites are uniform.
- Keeps the most-recently-touched session identities and contacts in memory
  to avoid hammering the persistent store on the hot encrypt/decrypt path.
- Coordinates writes through its actor executor, providing serialized
  consistency with respect to the active session.

## Topics

### Initialization

- ``init(store:)``

### Errors

- ``CacheErrors``

## Error handling

`CacheErrors` conforms to `LocalizedError`:

```swift
do {
    let message = try await session.cache?.fetchMessage(id: messageId)
} catch let error as SessionCache.CacheErrors {
    print(error.errorDescription ?? "")
    print(error.recoverySuggestion ?? "")
}
```

## See also

- ``PQSSession/cache``
- ``PQSSessionStore``
- ``CacheErrors``

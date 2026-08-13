# ``SessionEvents``

The host protocol surface of the Post-Quantum Solace SDK — the protocols an
application implements to plug the SDK into its network, database, and UI.

## Overview

In 4.0.0 the host surface is split into granular protocols so each host
object implements exactly what it provides. Typealiases keep single-object
hosts convenient:

| Surface | Protocols | Typealias |
|---|---|---|
| Transport | ``PQSTransport`` + ``PQSKeyDirectory`` + ``PQSRecoveryTransport`` | ``PQSNetworkHost`` |
| Store | ``PQSStore`` + ``PQSRecoveryStore`` | ``PQSPersistenceHost`` |
| Events | ``MessageStoreObserver`` | — |
| Policy & recovery hooks (optional) | ``MessagingPolicy`` + ``RecoveryObserver`` | ``PQSHostDelegate`` |

All protocols are `Sendable`; every method is `async` and may be called from
the session actor's executor, so implementations must be thread-safe and
should return quickly.

Conformers are wired once, at session construction, through
`SessionConfiguration`:

```swift
let session = await PQSSession(configuration: SessionConfiguration(
    transport: myTransport,        // any PQSNetworkHost
    store: myStore,                // any PQSPersistenceHost
    observer: myObserver,          // any MessageStoreObserver
    delegate: myHostDelegate       // optional PQSHostDelegate
))
```

## Topics

### Transport

- ``PQSNetworkHost``
- ``PQSTransport``
- ``PQSKeyDirectory``
- ``PQSRecoveryTransport``

### Persistence

- ``PQSPersistenceHost``
- ``PQSStore``
- ``PQSRecoveryStore``

### Events

- ``MessageStoreObserver``

### Policy and recovery hooks

- ``PQSHostDelegate``
- ``MessagingPolicy``
- ``RecoveryObserver``

### Helper types

- ``SignedRatchetMessageMetadata``

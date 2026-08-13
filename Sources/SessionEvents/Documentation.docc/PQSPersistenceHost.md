# ``PQSPersistenceHost``

The typealias you conform to when one object provides the SDK's persistent
storage: ``PQSStore`` & ``PQSRecoveryStore``.

## Overview

- ``PQSStore`` — encrypted-at-rest persistence for session contexts, device
  salt, session identities, messages, contacts, communications, and queued
  jobs (including media jobs).
- ``PQSRecoveryStore`` — the recovery ledgers: outbound device send records
  and accepted-envelope records used for replay suppression and resend
  bookkeeping.

Both protocols are `Sendable`; every method is `async` and designed for
concurrent access. The SDK wraps your concrete store in an internal two-tier
cache for the hot encrypt/decrypt path — you do **not** implement caching
yourself.

All blobs the SDK hands you (`EncryptedMessage`, `BaseCommunication`, session
contexts, ratchet snapshots) are opaque ciphertext. Persist them verbatim and
return them verbatim.

## Topics

### Storage surfaces

- ``PQSStore``
- ``PQSRecoveryStore``

### Recovery ledgers

- ``PQSRecoveryStore/upsertOutboundDeviceSendRecord(_:)``
- ``PQSRecoveryStore/deleteOutboundDeviceSendRecords(sharedId:)``
- ``PQSRecoveryStore/upsertAcceptedEnvelope(_:)``
- ``PQSRecoveryStore/pruneAcceptedEnvelopes(olderThan:)``

## Implementation sketch

```swift
final class DatabaseStore: PQSPersistenceHost {
    private let database: Database

    init(database: Database) {
        self.database = database
    }

    // MARK: PQSStore (excerpt)

    func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        try await database.insert(message)
    }

    func fetchMessage(id: UUID) async throws -> EncryptedMessage {
        guard let message = try await database.findMessage(id: id) else {
            throw StoreError.messageNotFound
        }
        return message
    }

    func fetchLocalSessionContext() async throws -> Data {
        guard let context = try await database.find(id: "local_session") else {
            throw StoreError.sessionContextNotFound
        }
        return context.data
    }

    // MARK: PQSRecoveryStore (excerpt)

    func upsertAcceptedEnvelope(_ record: AcceptedEnvelopeRecord) async throws {
        try await database.upsert(record)
    }

    func pruneAcceptedEnvelopes(olderThan date: Date) async throws -> Int {
        try await database.deleteAcceptedEnvelopes(olderThan: date)
    }

    // ... see ``PQSStore`` and ``PQSRecoveryStore`` for the full surface
}
```

## Implementation guidance

- **Encrypted storage** — sensitive payloads arrive already encrypted;
  storing them in an additionally encrypted database is fine but not
  required for message confidentiality.
- **Streaming** — implement the streaming entry points with real streams;
  the SDK uses them for large conversations rather than loading everything
  into memory.
- **Durability** — queued jobs must survive app restarts; the SDK resumes
  them via `PQSSession.resumeJobQueue()` after unlock.
- **Recovery ledgers** — the accepted-envelope and send-record tables are
  pruned by the SDK through ``PQSRecoveryStore/pruneAcceptedEnvelopes(olderThan:)``;
  hosts only provide storage, not policy.

## Wiring up

Pass your conformer through `SessionConfiguration`:

```swift
let store = DatabaseStore(database: myDatabase)

let session = await PQSSession(configuration: SessionConfiguration(
    transport: transport,
    store: store,
    observer: observer
))
```

## See also

- ``PQSNetworkHost``
- ``MessageStoreObserver``
- ``PQSHostDelegate``

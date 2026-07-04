# Account identity recovery

How to detect, communicate, and recover from a TOFU mismatch between
the local pinned account-level signing key and the server-advertised
account state.

## Overview

The SDK pins your account-level signing public key on the device the
first time it sees it. When a server-side rotation, a stolen-account
event, or simply a long-lost master device produces a different
account key for the same `secretName`, the SDK refuses to silently
adopt the new key. Instead, every code path that loads or refreshes
the account configuration throws ``PQSSession/SessionErrors/signingKeyOutOfSync``.

This article explains what to do when that error fires.

## When it fires

You'll see ``PQSSession/SessionErrors/signingKeyOutOfSync`` from any
of these paths:

- ``PQSSession/startSession(appPassword:)`` — pinned key disagrees with
  the server-advertised configuration at boot.
- ``PQSSession/adoptVerifiedUserConfiguration(_:)`` — explicit refresh
  using a configuration the SDK could not authenticate against the
  pin.
- ``PQSSession/rotateKeysOnPotentialCompromise()`` invoked on a
  **linked** (non-master) device — only the master may rotate the
  account-level key.
- Background refresh tasks driven by ``TaskProcessor``.

## Recovery procedure

The correct response is *always* user-mediated. Do not auto-accept a
mismatched configuration.

```swift
do {
    try await session.startSession(appPassword: appPassword)
} catch PQSSession.SessionErrors.signingKeyOutOfSync {
    // 1. Pull the freshly advertised configuration.
    let serverConfig = try await transport.findConfiguration(for: mySecretName)

    // 2. Show the user the safety-number diff.
    let oldIdentity = await session.localSecurityIdentity()
    let newIdentity = SecurityIdentity(secretName: mySecretName,
                                       configuration: serverConfig)

    let oldSafetyNumber = SecurityIdentity.safetyNumber(local: oldIdentity,
                                                       remote: oldIdentity)
    let newSafetyNumber = SecurityIdentity.safetyNumber(local: newIdentity,
                                                       remote: newIdentity)

    let userConfirmed = await ui.confirmIdentityChange(
        old: oldSafetyNumber,
        new: newSafetyNumber
    )
    guard userConfirmed else { return }

    // 3. Acknowledge — overwrites the local pin.
    try await session.acknowledgeAccountIdentityChange(serverConfig)

    // 4. Resume.
    try await session.startSession(appPassword: appPassword)
}
```

## Treat acknowledgement like a factory reset

``PQSSession/acknowledgeAccountIdentityChange(_:)`` is the only way to
overwrite the TOFU pin without a master-side rotation. It implies
that the user has out-of-band confirmed the new key is genuine. After
acknowledgement:

- Every per-peer trust pin remains in place; safety numbers with
  contacts may visibly change because *your own* signingPublicKey is
  what feeds into them.
- Linked devices must re-link. A new account-level key invalidates
  every prior signed-device descriptor.

## Don't auto-acknowledge

Always force a deliberate user choice. Common policy:

| Scenario                                          | Recommended UX                              |
| ------------------------------------------------- | ------------------------------------------- |
| Reinstalled the master device                     | Recover from backup, re-link children       |
| Compromise suspected                              | Reject; rotate via master                   |
| Server / operator-level migration                 | Acknowledge after out-of-band confirmation  |
| Old phone forgotten and now receives a new key    | Wipe local data, re-bootstrap account       |

## Ergonomics for app integrations

Higher-level SDKs (NudgeKit) typically expose this as a
publishable signal so a SwiftUI/Compose layer can react automatically.
The pattern is:

1. Catch ``PQSSession/SessionErrors/signingKeyOutOfSync`` in the
   transport / event pipeline.
2. Surface a `pendingAccountIdentityMismatch` value on an observable
   object.
3. Present a recovery view that walks the user through the safety
   number diff.
4. Call ``PQSSession/acknowledgeAccountIdentityChange(_:)`` only after
   user confirmation.

## See also

- ``PQSSession/acknowledgeAccountIdentityChange(_:)``
- ``PQSSession/adoptVerifiedUserConfiguration(_:)``
- ``PQSSession/SessionErrors/signingKeyOutOfSync``
- ``SecurityIdentity``
- ``UserConfiguration``

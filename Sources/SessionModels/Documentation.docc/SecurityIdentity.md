# ``SecurityIdentity``

Stable, account-level identity used for out-of-band trust verification
between users — the building block behind safety numbers and
QR-scanned identity comparisons.

## Overview

A `SecurityIdentity` is the pair `(secretName, signingPublicKey)` of a
user's **account-level** signing key. The signing key is rotated only
through authenticated rotation paths (see
``PQSSession/rotateKeysOnPotentialCompromise()`` and
<doc:AccountIdentityRecovery>); when it changes, the safety number a
peer renders for the user visibly changes too. That visible change is
the social signal that lets users detect MITM and identity-swap
attacks.

## Topics

### Initialization

- ``SecurityIdentity/init(secretName:signingPublicKey:)``
- ``SecurityIdentity/init(secretName:configuration:)``

### Identity components

- ``SecurityIdentity/secretName``
- ``SecurityIdentity/signingPublicKey``

### Fingerprints

- ``SecurityIdentity/fingerprint(version:iterations:)``
- ``SecurityIdentity/shortFingerprintHex(byteCount:)``

### Safety numbers

- ``SecurityIdentity/safetyNumber(local:remote:version:iterations:)``

## Two layers of trust

The SDK enforces trust in two complementary layers:

- **TOFU (automatic).** The SDK pins each peer's
  `signingPublicKey` per account on first sight and rejects silent
  server-side rotations. A change manifests at runtime as
  ``PQSSession/SessionErrors/signingKeyOutOfSync`` (for the local
  account) or as a `PeerIdentityRefreshAssessment` failure (for a
  remote peer).

- **Safety number (manual).** Users compare a 60-digit safety number
  rendered from `safetyNumber(local:remote:)` out of band — voice,
  in-person QR scan, scanned and matched on a verified channel — to
  confirm there is no MITM between them.

## Determinism

`safetyNumber(local:remote:)` is symmetric and deterministic for a
fixed `(secretName, signingPublicKey)` pair on each side. Both
participants see the same digits regardless of who is rendering it.

## Quick example

```swift
// Local user.
let local = SecurityIdentity(
    secretName: "alice",
    configuration: aliceUserConfiguration
)

// Remote user.
let remote = SecurityIdentity(
    secretName: "bob",
    configuration: bobUserConfiguration
)

// Render for UI.
let number = SecurityIdentity.safetyNumber(local: local, remote: remote)
// "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"

// Compact badge on a profile screen.
let badge = remote.shortFingerprintHex()      // e.g. "A1:B2:C3:D4:E5:F6:07:08"
```

## Display recommendations

- **60-digit safety number.** Render in 12 groups of 5 with spaces.
  Pair with a "Scan their code" affordance that exchanges the same
  bytes via QR.
- **Short hex badge.** Use on profile screens and verified-state
  callouts where space is tight. Always link to the full safety
  number screen.
- **Change indicator.** When a safety number changes, surface it
  prominently and recommend re-verification via
  <doc:AccountIdentityRecovery>.

## See also

- ``UserConfiguration``
- <doc:AccountIdentityRecovery>
- ``PQSSession/SessionErrors/signingKeyOutOfSync``

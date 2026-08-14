# Deferred One-Time-Key Consumption

Design for enabling strict one-time-key (OTK) enforcement without breaking
recovery replays. Status: **designed, not yet implemented** — strict
enforcement stays off in 4.0.0. Implementation is additive (no public API
break) and targets a 4.1 minor of DoubleRatchetKit and Post-Quantum Solace.

## Problem

DoubleRatchetKit supports strict OTK enforcement
(`setEnforceOTKConsistency(true)`): on the first authenticated decrypt of an
inbound PQXDH bootstrap frame, it consumes the local one-time prekey — it
calls `SessionIdentityDelegate.updateOneTimeKey(remove:)` and clears
`localOneTimePrivateKey` from the ratchet state — and fails fast if the same
bootstrap frame arrives again.

Post-Quantum Solace cannot enable that today because recovery legitimately
replays the initiator's first encrypted frame:

- transport failure / lane repair resends the original bootstrap frame;
- archived-identity fallback re-runs session establishment against an older
  snapshot.

Consumption-on-first-decrypt makes those replays fail fast and strands
rotation/repair flows. So 4.0.0 ships with enforcement off, and the private
OTK is retained until normal batch rotation.

### Current security posture

The retained private OTK slightly extends the window in which a *later
device compromise* could decrypt a *recorded bootstrap frame* for that
session. Wire confidentiality is unaffected, and server-side single-use of
published OTKs still holds. The exposure is bounded to the initial handshake
frame, not the conversation.

## Design

### The confirming event (no timers)

The initiator keeps emitting the PQXDH bootstrap header — which carries
`oneTimeKeyId` — until its `sendingHandshakeFinished` flag flips, and that
flag flips only after the initiator has processed the responder's first
authenticated reply. Therefore, on the responder:

> The first inbound frame decrypted via the header-chain path (no
> `oneTimeKeyId`; post-bootstrap turn) is cryptographic proof that the
> initiator has advanced past the handshake and can never legitimately
> resend the bootstrap frame.

Call this event **reverse handshake confirmed**. It is observable purely
from protocol state — no elapsed-time heuristics are involved.

### State machine

| State | Owner | Set when | Cleared when |
|---|---|---|---|
| `pendingConsumedOneTimeKeyId` (new, optional, persisted in `RatchetState`) | DoubleRatchetKit | Bootstrap decrypt succeeds with an OTK, instead of consuming immediately | Reverse handshake confirmed |
| Local private OTK in device keys | Post-Quantum Solace (delegate) | Key generation / publication | `updateOneTimeKey(remove:)` fires on confirmation |

On **reverse handshake confirmed**, DoubleRatchetKit:

1. persists the ratchet state with the pending marker cleared,
2. clears `localOneTimePrivateKey` from state,
3. calls `SessionIdentityDelegate.updateOneTimeKey(remove: id)` — the hook
   that already exists; no new delegate requirements.

The same lifecycle applies to the MLKEM one-time key consumed by the hybrid
PQXDH derivation.

### Replay behavior once implemented

- Bootstrap replay **before** confirmation: decrypts via the retained OTK —
  identical to today's behavior; recovery flows unaffected.
- Bootstrap replay **after** confirmation: fails fast under strict
  enforcement — now *correct*, because the initiator provably advanced; a
  bootstrap replay at that point is an attacker or a bug.

### Crash and idempotency safety

The pending marker is persisted with the ratchet state before the delegate
deletion runs, so a crash between decrypt and deletion replays the deletion
idempotently on the next confirmation. Deletion is keyed by OTK id and is
already idempotent on the Post-Quantum Solace side.

### Why this is not API-breaking

- `enforceOTKConsistency` is a runtime toggle (`setEnforceOTKConsistency`),
  flipped internally by the message pipeline — enabling it later changes no
  signatures.
- `SessionIdentityDelegate.updateOneTimeKey(remove:)` already exists.
- The new `RatchetState` field is optional; legacy blobs decode unchanged
  (the codebase already validates this pattern with pre-existing
  legacy-decode tests and golden persisted-data fixtures).

## Implementation-phase verification checklist

1. Prove from code and dogfood logs that archived-identity fallback decrypts
   bootstrap replays via retained snapshot state without re-requiring the
   private OTK. If a snapshot re-derivation path *does* require it, gate the
   delegate deletion on the last referencing snapshot being pruned
   (Post-Quantum Solace owns snapshot lifecycle).
2. Replay tests: bootstrap replay before and after confirmation; crash
   between marker persistence and deletion; multi-device fan-out where
   sibling lanes are still pre-confirmation while one lane confirms.
3. Golden fixtures: existing 3.x/4.0 blobs decode byte-identically; the new
   field only appears in encodes when a consumption is actually pending.

## See also

- <doc:MultideviceDecryptRecovery>
- <doc:ControlEventCoalescing>
- ``PQSSession``

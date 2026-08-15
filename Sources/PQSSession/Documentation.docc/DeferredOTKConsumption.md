# Deferred One-Time-Key Consumption

Strict one-time-key (OTK) enforcement without breaking recovery replays.
Status: **implemented in Post-Quantum Solace 4.1.0**, entirely on the PQS
side — DoubleRatchetKit 4.0.0 is used as-is, no DRK changes were required.

## Problem

DoubleRatchetKit supports strict OTK enforcement
(`setEnforceOTKConsistency(true)`): on the first authenticated decrypt of an
inbound PQXDH bootstrap frame, it consumes the local one-time prekey — it
calls `SessionIdentityDelegate.updateOneTimeKey(remove:)` and clears
`localOneTimePrivateKey` from the ratchet state.

Post-Quantum Solace could not enable that in 4.0.0 because recovery
legitimately replays the initiator's first encrypted frame:

- transport failure / lane repair resends the original bootstrap frame;
- archived-identity fallback re-runs session establishment against an older
  snapshot or a freshly ensured blank lane.

If the private OTK were *deleted* at first decrypt, those replays would fail
fast and strand rotation/repair flows.

## Why no DoubleRatchetKit changes were needed

Four properties of DRK 4.0.0 make the deferral implementable purely in the
Post-Quantum Solace delegate layer:

1. **Consumption fires only after authenticated decrypt.** All strict-mode
   consumption sites run after the bootstrap frame passes AEAD
   authentication, and DRK clears the `RatchetState` copy of the OTK itself.
2. **The decrypt preflight re-hydrates from the host pool.** When a
   bootstrap frame cites an `oneTimeKeyId` and the state copy is gone, DRK
   asks the delegate via `fetchOneTimePrivateKey(_:)` and only throws
   `missingOneTimeKey` under strict mode when the host pool also lacks the
   key. Whether a replay decrypts is therefore decided by *when PQS deletes
   the pool key* — which is exactly the lever this design controls.
3. **`updateOneTimeKey(remove:)` is a notification, not a command.** The
   delegate owns the pool; deferring the destructive part is a delegate
   implementation detail, invisible to DRK.
4. **The lane still needs the state copy after every consume.** In
   DRK 4.0.0 the OTK is not a one-shot bootstrap key: its public half is
   embedded in every outgoing header while present in state, and it
   participates in every PQXDH epoch re-key. Strict mode clears the state
   copy on every consuming decrypt, so after each commit PQS writes the pool
   key back via `respondToSession` (a local-key change, not a sending DH
   ratchet). This restore is deliberately unconditional: if the state copy
   stayed nil, the next outbound header would embed no OTK and the peer
   would perform a receive-driven epoch re-key we never mirrored — permanent
   chain divergence. Once the pool key is deleted (lane superseded) the
   restore becomes a no-op.

## Design

### The confirming events (no timers)

Because a DRK 4.0.0 lane embeds and re-uses its OTK in every epoch re-key,
a live lane cites the same `oneTimeKeyId` for its whole lifetime — "the
initiator stops citing after the reverse handshake" does **not** happen
with this DRK release. The events that *do* prove a key can never be
legitimately cited again are:

> 1. **Lane re-key (supersede).** A committed inbound frame on the same
>    lane citing a *different* `oneTimeKeyId`: the peer re-fetched our
>    bundle and epoch re-keyed the lane, so the superseded key is
>    unreachable for it from that point on.
> 2. **No-id frame.** A committed inbound frame with no `oneTimeKeyId`:
>    the lane operates without an OTK. This is also the forward-compatible
>    trigger for a future DRK that stops citing once the reverse handshake
>    completes.

Both events are observable purely from protocol state — no elapsed-time
heuristics are involved — and PQS observes them directly because it decodes
every inbound header before handing the frame to DRK. Pending entries whose
lane never re-keys are bounded by normal batch key rotation.

### State machine (all PQS-owned)

| State | Set when | Cleared when |
|---|---|---|
| Signed public OTK entry in `activeUserConfiguration` | Key publication | First `updateOneTimeKey(remove:)` for the id — pruned and a freshly minted replacement is published (doubles as the mint-once idempotency marker) |
| `DeviceKeys.pendingOneTimeKeyConsumptions` (optional, persisted in the session context) | A committed inbound frame citing one-time-key ids — recorded against the winning lane in `finalizeAcceptedInbound` | A confirming event on that lane (re-key supersede or no-id frame) |
| Private OTK halves in `DeviceKeys` pools | Key generation | Confirming event — deleted together with the pending entry, unless still pending for a sibling lane |

Implementation points:

- `TaskProcessor.updateOneTimeKey(remove:)` (`TaskProcessor+Ratchet.swift`)
  handles the consumption *request*: prune the spent signed public key,
  mint + publish the replacement, keep the private half. Replay-idempotent.
  `loadKeys` also re-supplies a pool key when a reminted lane starts a
  sending handshake with a cleared state copy.
- `noteAcceptedInboundForDeferredOneTimeKeyConsumption`
  (`TaskProcessor+RatchetInbound.swift`) records and confirms pending
  consumptions. It runs inside `finalizeAcceptedInbound`, i.e. only for
  frames whose accepted-ledger write succeeded — a rolled-back decrypt can
  neither record nor confirm.
- The MLKEM one-time key cited by the hybrid PQXDH bootstrap follows the
  same lifecycle and is deleted on the same confirming event. The final
  (last-resort) MLKEM key is never consumed. MLKEM pool replenishment stays
  with the existing batch-rotation flow.

### Replay behavior

- Bootstrap replay **before** confirmation: the decrypt preflight
  re-hydrates the state OTK from the retained pool key — recovery flows
  (lane repair, archived-identity fallback, ensured blank lanes) are
  unaffected.
- Bootstrap replay **after** confirmation: the pool key is gone, so the
  preflight fails fast under strict enforcement — *correct*, because the
  initiator provably advanced; a bootstrap replay at that point is an
  attacker or a bug.

### Crash and idempotency safety

- The pending record is persisted in the encrypted session context in the
  same write that mutates the pools, so a crash cannot separate them.
- An unrecorded pending entry is re-recorded by the next committed frame
  citing the id; an unconfirmed one is re-confirmed by the next committed
  frame after the lane's confirming event. Both directions self-heal
  without timers.
- Deletion is keyed by key id (`removeAll { $0.id == id }`) and idempotent.
- Pending entries whose lane never confirms (abandoned handshake) are
  bounded by normal batch key rotation, which replaces the pools wholesale;
  a stale entry then confirms as a no-op.

### Persistence compatibility

`DeviceKeys.pendingOneTimeKeyConsumptions` is optional with an additive
coding key and resets to `nil` when the last entry clears, so:

- session contexts persisted before 4.1.0 decode unchanged;
- encodes are byte-identical to 4.0.0 whenever nothing is pending (golden
  fixtures unaffected).

## Verification results (was: implementation-phase checklist)

1. **Archived/blank-lane replays** — verified in code: the decrypt preflight
   hydrates from the pool, and `initializeRecipient` additionally falls back
   to the OTK retained inside archived ratchet state
   (`props.ratchetOneTimePrivateKey`). No snapshot path re-requires a
   deleted pool key before confirmation.
2. **Replay tests** — `DeferredOTKConsumptionTests` covers pending-record on
   bootstrap, retention before confirmation, deletion + clearing on
   confirmation, and mint-once idempotency of the consumption request.
3. **Golden fixtures** — unchanged; the new field only appears in encodes
   while a consumption is actually pending.

## See also

- <doc:MultideviceDecryptRecovery>
- <doc:ControlEventCoalescing>
- ``PQSSession``

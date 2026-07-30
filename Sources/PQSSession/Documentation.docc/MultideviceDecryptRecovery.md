# Multi-device decrypt recovery

Per-device session inventory failure modes for inbound
decrypt, resend-request (NACK) delivery, and sender orphan-resend.

## Overview

Messaging is **device-scoped**: each remote device has its own Double
Ratchet session. Fan-out encrypts to every known device of the
recipient. Recovery must also be device-scoped.

Two identities must stay separate:

| Identity | Scope | Changes on resend? |
| -------- | ----- | ------------------ |
| `logicalSharedId` | Chat / UI / media / plaintext lookup | No |
| `envelopeMessageId` | Envelope MessageID: one per encrypted send to one recipient device | Yes — new ID every encrypt/resend |

Retry requests are **out-of-band** (not Double Ratchet encrypted). They
cite the failed **envelope** MessageID and the requester device. The
sender owns the MessageRecord, may insert a new initiating session only
when its active SessionID still equals the orphaned one, and resends
under a **new** envelope MessageID.

**Legacy (pre-strict):** encrypted NACK riding a surgical control lane
(`ControlDeliveryLanePolicy` / episode reuse). Emission and inbound
servicing of encrypted `TransportEvent.requestMessageResend` /
`messageResendUnavailable` are **commented out / stubbed** (`DEAD LEGACY`
markers) pending dogfood confirmation, then delete. Wire enum cases and
codecs stay only so leftover ciphertext cannot crash decode.

Related path: undecryptable inbound → OOB `requestMessageResend` →
sender orphan-resend.

## Spec conformance matrix


| Requirement | Spec | NeedleTails target | Test |
| ----------- | ------ | ------------------ | ---- |
| Receive by `(senderUserID, senderDeviceID)` | §3.4 | Device-scoped try-all | S16 / `EnvelopeMessageIdTests` |
| Activate inactive session only on decrypt success | §3.4 | `activateSessionIdentityAfterInboundDecrypt` | S16 |
| Discard all state changes on decrypt failure | §3.4 | Snapshot rollback | S16 |
| Retry request is unencrypted | §4.1 | `SessionTransport.sendOutOfBandResendRequest` | S1, S7, S13 |
| Retry cites unique MessageID of failed envelope | §4.1 | `failedEnvelopeMessageIds` | S11–S13 |
| MessageRecord per (device, envelope), new ID on resend | §4.1 | `OutboundDeviceSendRecord` envelope index | S11, S12 |
| Remint only when active SessionID matches MessageRecord | §4.1 | `OrphanResendRemintPolicy` | S15 |
| Bounded resend attempts | §4.1 | peer-resend / honor caps | S15 |
| Offline spool / replay waves | out of scope | Transport extension (T11–T18) | Offline coordinator tests |


## Success signals (dogfood)

For a poison cross-account lane on a **capable** peer, expect:

1. `pqs.recovery.resendRequestSubmittedOutOfBand` citing `envelopeMessageId`
2. **Zero** `controlDeliveryFreshLane` / DR encrypt jobs for the retry
3. `pqs.recovery.resendRequestReceived` via `serviceAuthenticatedResendRequest` on the original sender device
4. `pqs.recovery.orphanResend*` with a **new** `envelopeMessageId`, same `logicalSharedId`
5. New content decrypts on **that** device id only
6. Optional: delivery receipt clears the exact MessageRecord by envelope ID

Healthy sibling devices of the same user must stay untouched.

Write-path invariant: `resolveSessionIdentityForOutbound` must honor an
explicit heal/initiating `recipientIdentity` for **content** orphan
resend. Retry *requests* must not select a DR session at all.

## Strict-release status

| Gate | Status |
| ---- | ------ |
| Capable clients emit OOB only (`requestMessageResend` → `sendOutOfBandResendRequest`) | Done |
| Encrypted NACK **emission** / surgical mint for retry | Disabled (`DEAD LEGACY` stubs) |
| Encrypted NACK **inbound service** | Disabled (`DEAD LEGACY` stubs; ignore after decode) |
| OOB path services via `serviceAuthenticatedResendRequest` | Done |
| `post-quantum-solace` full suite | Green |
| Focused nudge-kit offline/replay suites | Green |
| Delete encrypted retry stubs / TransportEvent cases | Pending dogfood unused confirmation |

## Scenario catalog

Likelihood and blast radius below are qualitative (1–10) from dogfood
and policy review, not measured frequencies.

### S1 — Poison preferred rides encrypted NACK (legacy)

|                             |                                       |
| --------------------------- | ------------------------------------- |
| **Topology**                | A-parent ↔ B-parent (1:1 device pair) |
| **Severity**                | Critical                              |
| **Likelihood / blast**      | 9 / 10                                |
| **Heals without surgical?** | N/A under strict target               |
| **Behavioral test**         | `StrictOOBRetryTests.undecryptableEmitsOOBWithoutDRMint` |

**Failure mode (legacy).** Try-all inbound fails. Encrypted NACK rides
the poison outbound active → `resendRequestTransported`, never
`resendRequestReceived`.

**Target recovery.** OOB retry — poisoned DR lane cannot block the request.

**Forbidden.** Receive-side DR encrypt, lane mint, demote, promote, or
preference write for the retry.

### S2 — Bidirectional dead lane (mutual blindness)

|                             |                                   |
| --------------------------- | --------------------------------- |
| **Topology**                | A-device ↔ B-device both desynced |
| **Severity**                | Critical                          |
| **Likelihood / blast**      | 8 / 10                            |
| **Heals without surgical?** | Yes via mutual OOB + orphan resend |

**Failure mode.** Each side’s preferred session encrypts outbound the
peer cannot decrypt.

**Recovery.** Both sides emit OOB retries; sender orphan-resend heals
each direction independently.

### S3 — Same-account sibling poison (linked devices)

|                             |                                                  |
| --------------------------- | ------------------------------------------------ |
| **Topology**                | User U: parent ↔ child (personal / sibling sync) |
| **Severity**                | Critical                                         |
| **Likelihood / blast**      | 6 / 8                                            |
| **Behavioral test**         | `OrphanOwnershipHealTests` + OOB path            |

**Failure mode.** Sibling sync rides a maxSkipped lane.

**Recovery.** OOB retry to the exact sibling device; orphan remint on
sender when MessageRecord SessionID is still active.

### S4 — Per-device fan-out: one device dead, peer healthy

|                             |                                               |
| --------------------------- | --------------------------------------------- |
| **Topology**                | A → B with devices B1 (poison) + B2 (healthy) |
| **Severity**                | High                                          |
| **Behavioral test**         | `EnvelopeMessageIdTests.fanoutMintsDistinctEnvelopes` |

**Failure mode.** Fan-out reaches all B devices. B2 decrypts; B1 fails.

**Recovery.** OOB retry only for B1’s failed envelope; never demote B2.

### S5 — `blankForHeaderExists` trap

|                             |                                                                   |
| --------------------------- | ----------------------------------------------------------------- |
| **Topology**                | Receiver has archived / state-less blank for exact LTK+OTK header |
| **Severity**                | High                                                              |

**Failure mode.** Active-first fails; inbound blank ensure skipped.

**Recovery.** Sender orphan remint with **new** OTK material (new
envelope). Receiver retry remains OOB.

### S6 — Archive dirt / retention-cap eviction

|                             |                                             |
| --------------------------- | ------------------------------------------- |
| **Topology**                | Peer-device with many archived session rows |
| **Severity**                | High                                        |

**Failure mode.** Try-all walks huge archives; demote thrash evicts live
snapshots.

**Recovery.** No preference-on-fail; fingerprint/envelope-scoped archive
pass; bounded inactive retention.

### S7 — NACK-of-NACK control storm

|                             |                                           |
| --------------------------- | ----------------------------------------- |
| **Topology**                | Failed resend envelope treated as content |
| **Severity**                | High                                      |
| **Behavioral test**         | `StrictOOBRetryTests`               |

**Failure mode (legacy).** Peer cannot decrypt encrypted
`requestMessageResend` → issues another resend for that control id.

**Target recovery.** Retry is OOB; it cannot become DR content.

### S8 — Orphan-resend missing plaintext

|                             |                                                 |
| --------------------------- | ----------------------------------------------- |
| **Topology**                | Retry lands; sender has no MessageRecord        |
| **Severity**                | Medium                                          |
| **Behavioral test**         | `TaskProcessorSequenceTests` OOB unavailable    |

**Recovery.** Mark envelope unrecoverable via OOB unavailable notice;
no receive-side ASR.

### S9 — New device join mid-conversation

|                             |                                   |
| --------------------------- | --------------------------------- |
| **Topology**                | B links B3 while A↔B1 is desynced |
| **Severity**                | Medium                            |

**Recovery.** Heal B1 via OOB + orphan resend; B3 must not inherit B1’s
preferred poison.

### S10 — Healthy lane single-frame miss

|                             |                                           |
| --------------------------- | ----------------------------------------- |
| **Topology**                | Normal 1:1; transient AEAD / reorder miss |
| **Severity**                | Medium                                    |

**Recovery.** Bounded OOB retry; no session replace on the receiver.

### S11 — Fan-out unique envelope MessageIDs

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | A → B1 + B2 same logical message     |
| **Severity**                | Critical (spec correctness)        |
| **Behavioral test**         | `EnvelopeMessageIdTests.fanoutMintsDistinctEnvelopes` |

**Invariant.** One `logicalSharedId`, distinct `envelopeMessageId` per
recipient device. Wire `MessagePacket.id` = envelope;
`logicalMessageId` = logical.

**Forbidden.** Sharing one wire MessageID across fan-out devices.

### S12 — Resend replaces envelope MessageID

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Orphan resend after OOB retry        |
| **Severity**                | Critical                             |
| **Behavioral test**         | `EnvelopeMessageIdTests.resendSupersedesEnvelope` |

**Invariant.** Resend keeps logical ID, mints new envelope, supersedes
old MessageRecord; never overwrites old envelope ID in place.

### S13 — OOB retry names exact envelope + requester device

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Undecryptable inbound                |
| **Severity**                | Critical                             |
| **Behavioral test**         | `StrictOOBRetryTests`          |

**Invariant.** Request carries failed envelope IDs and authenticated
requester device; routes to original sender device only.

### S14 — Forged / wrong-device / malformed / replayed retry

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Attacker or duplicate OOB ingress    |
| **Severity**                | High                                 |
| **Behavioral test**         | Server + stream OOB validation tests |

**Invariant.** Reject forged/wrong-device/malformed controls and duplicate
authenticated `requestId`s. Encrypted retry controls are decoded only so they
can be rejected without changing ratchet or recovery state.

### S15 — Missing / superseded MessageRecord / exhausted budget

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Retry for gone or superseded envelope |
| **Severity**                | Medium                               |

**Invariant.** Unavailable notice; bounded attempts; no unbounded remint.

### S16 — Activate on success; rollback every failed candidate

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Try-all across active + inactive     |
| **Severity**                | Critical                             |

**Invariant.** Only the decrypting session activates. Failed candidate
snapshots are discarded. Preference is never written on failure.

### T11 — Duplicate offline replay waves

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Registration + isOnline before boundary |
| **Severity**                | Critical (dogfood)                   |
| **Behavioral test**         | `OfflineReplayCoordinatorPolicyTests` / OfflineMessagePacketTests |

**Invariant.** One request per connection generation until
`offlineReplayComplete`, write failure, or matching disconnect.

### T12 — Stale completion / disconnect vs newer generation

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Reconnect during prior wave          |
| **Severity**                | High                                 |

**Invariant.** Stale boundary cannot release a newer generation.

### T13 — Accepted non-persisted envelope redelivered

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | `nudgeLocal` metadata decode success, then spool redelivery |
| **Severity**                | Critical (dogfood D638…)             |
| **Behavioral test**         | `AcceptedEnvelopeLedgerPolicyTests`  |

**Invariant.** Second copy ACK/drops before ratchet; no NACK/remint;
host delivery once.

### T14 — Failed decrypt must not enter accepted ledger

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | First copy fails AEAD / decode       |
| **Severity**                | Critical                             |

**Invariant.** Only success after decrypt + decode + host handling marks
accepted.

### T15 — Accepted marker survives ACK loss / relaunch

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Crash after accept before spool delete |
| **Severity**                | High                                 |

**Invariant.** Durable ledger; retention ≥ spool retention + margin.

### T16 — Cross-device ID collision cannot dedupe

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Same logical/envelope string, different sender device |
| **Severity**                | High                                 |

**Invariant.** Ledger key is `(senderUserID, senderDeviceID, envelopeMessageId)`.

### T17 — Archive pass vs fresh fingerprint race (both orders)

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Old archive job + new orphan fingerprint same logical id |
| **Severity**                | High                                 |
| **Behavioral test**         | `InboundRecoveryStormPolicy` token tests |

**Invariant.** Pass token is
`(sender, device, envelopeMessageId, fingerprint)`. Sibling tokens never
clear each other.

### T18 — Mixed-version packet / store migration / rollback

|                             |                                      |
| --------------------------- | ------------------------------------ |
| **Topology**                | Old client ↔ new client / DB migrate |
| **Severity**                | High                                 |

**Invariant.** Dual-read: `logicalMessageId ?? id`. Backfill
`envelopeMessageId = sharedId`. Rollback leaves old clients readable.

## Policy summary


| Question                          | Answer                                                                                    |
| --------------------------------- | ----------------------------------------------------------------------------------------- |
| Unit of session / recovery        | Peer **device**, not user                                                                 |
| Content heal                      | Sender **orphan-resend** (MessageRecord owner)                                            |
| Retry transport                   | Authenticated **OOB**, not Double Ratchet                                                 |
| MessageID                         | Unique **envelope** per device encrypt; logical ID separate                               |
| Demote-all on retry?              | **Never**                                                                                 |
| Preference write on try-all fail? | **Never**                                                                                 |
| Encrypted NACK / retry control    | Rejected after decode; never emitted or serviced                                           |


## Explicit non-goals

- Receive-side `peerRefresh` / ASR as the primary content heal for
`maxSkipped` / body decrypt failure.
- Preference-on-fail cascades that demote unique session ids under
`blankForHeader` storms.
- Claiming exactly-once host delivery across independent stores
(accepted ledger is at-least-once with idempotent host keys).

## See also

- [doc:ControlEventCoalescing](doc:ControlEventCoalescing)
- [doc:AccountIdentityRecovery](doc:AccountIdentityRecovery)
- `EnvelopeMessageIdentityPolicy`
- `OfflineReplayCoordinatorPolicy`
- `AcceptedEnvelopeLedgerPolicy`
- `InboundRecoveryStormPolicy`
- `OrphanResendRemintPolicy`
- `PQSAuditLog`

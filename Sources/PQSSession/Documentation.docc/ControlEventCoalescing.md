# Control event coalescing

How the SDK throttles outbound session-control emissions and
deduplicates inbound ones to stop notification storms after a single
underlying problem.

## Overview

Failures in distributed messaging (a child device losing trust, a
peer rotating keys, a temporarily wedged ratchet) tend to fire many
overlapping signals: one per inflight message, one per offline
backlog entry, one per UI retry. Without throttling, a single
divergence between two devices would result in tens of identical
"please rotate" or "please re-link" envelopes flying across the
wire — and being processed redundantly on the other side after the
fact.

Control event coalescing is the SDK's solution. Every session-control
emission is described by a `(kind, scope)` pair and is gated by an
in-memory **episode** that:

- collapses repeated emissions inside a per-kind cooldown window,
- mints a stable `intentId` so receivers can deduplicate,
- bumps a monotonically increasing `epoch` so receivers can drop
  stale, out-of-order replays.

## Sender-side episodes

| Type                            | Role                                                         |
| ------------------------------- | ------------------------------------------------------------ |
| ``ControlEventScope``           | Audience: `personal` (own devices) or `peer(secretName:)`.   |
| ``ControlEventEpisodeKey``      | `(kind, scope)` lookup key for the episode table.            |
| ``ControlEventEpisode``         | Per-episode state: `intentId`, `epoch`, timestamps.          |
| ``SessionReestablishmentKind``  | What kind of control envelope is being emitted.              |
| ``SessionReestablishmentEnvelope`` | The envelope actually sent over the wire.                  |

The cooldown window is per-kind and pulls from
``PQSSessionConstants``:

- ``PQSSessionConstants/peerRefreshCooldownSeconds`` (peer key
  refresh nudges).
- ``PQSSessionConstants/linkedDeviceRepairCooldownSeconds`` (linked
  device repair requests).
- ``PQSSessionConstants/linkedDeviceCompromiseObservedCooldownSeconds``
  (compromise observations).
- ``PQSSessionConstants/forcedIdentityRefreshCoalesceWindowSeconds``
  (forced identity refresh nudges).

If a re-emission arrives within the cooldown window, the SDK suppresses
the wire send and logs at `debug` level. If it arrives past the
cooldown but inside
``PQSSessionConstants/controlEventEpisodeMaxLifetimeSeconds`` (24h by
default), the episode is reused: the same `intentId` is returned with
a freshly bumped `epoch`. Past the lifetime, a brand-new episode is
minted.

## Receiver-side dedup

| Type                              | Role                                                 |
| --------------------------------- | ---------------------------------------------------- |
| ``ProcessedControlEventKey``      | `(senderDeviceId, kind)` lookup.                     |
| ``ProcessedControlEventState``    | The latest acted-upon envelope's `intentId` + epoch. |
| ``ProcessedControlEventDecision`` | `process` / `skipDuplicate` / `skipStale`.           |

When a control envelope is received, the SDK compares its
`(intentId, epoch)` against the last one acted on for this
`(senderDeviceId, kind)`:

- **`process`** — first time we've seen this episode. Act on it and
  record state.
- **`skipDuplicate`** — same `intentId` (or same epoch) already
  processed. Drop silently.
- **`skipStale`** — strictly older epoch than the latest. Drop as an
  out-of-order replay (e.g. an offline backlog).

## Why this matters

- **Saves bandwidth and battery.** The pre-coalescing baseline
  emitted up to dozens of envelopes per failure; under load this
  caused visible UI churn.
- **Makes recovery user-readable.** A single divergence becomes a
  single notification that can be acknowledged (see
  <doc:AccountIdentityRecovery>) instead of a flood.
- **Tolerates offline backlogs.** The receiver-side `epoch` ordering
  means a master device coming online after a long absence does not
  re-process every stale request on the queue.

## Tunables

All knobs live on ``PQSSessionConstants``. They are SDK-wide compile-time
defaults; do not mutate them at runtime. If a deployment needs different
windows, fork the constants file or add a build configuration and
rebuild — the SDK reads them directly from the type's static storage.

## See also

- ``ControlEventScope``
- ``ControlEventEpisodeKey``
- ``ControlEventEpisode``
- ``ProcessedControlEventKey``
- ``ProcessedControlEventState``
- ``ProcessedControlEventDecision``
- ``SessionReestablishmentKind``
- ``SessionReestablishmentEnvelope``
- ``PQSSessionConstants``
- ``TaskProcessor``

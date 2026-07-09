# ``TaskProcessor``

Internal `actor` that owns the SDK's cryptographic and message-processing
work queues. You do not interact with it directly — `PQSSession` enqueues
all heavy work here so that public API calls remain responsive and
in-flight cryptographic work proceeds on a dedicated executor.

## Overview

`TaskProcessor`:

- Maintains separate queues for outbound (encrypt) and inbound (decrypt)
  cryptographic operations so that a busy inbox never blocks sending.
- Coalesces and deduplicates control events (key rotation, OTK refresh,
  identity-change probes) using the windows defined in
  ``PQSSessionConstants``.
- Restarts itself across `start`/`shutdown` cycles via
  ``PQSSession/resumeJobQueue()``.

## Friendship / OTK bootstrap (3.2.0)

When encrypting ``TransportEvent/synchronizeOneTimeKeys`` (OTK handshake
notify) for a peer nickname:

- Identities are filtered to the **bootstrap-target** device from
  `peerMasterDevice(for:)` (online / OTK-capable), not every master-flagged
  or preserved ghost row in the published account config.
- That control event is treated as **recovery-critical** so a single failed
  encrypt does not burn the outbound repair cooldown and leave
  delete → re-add stranded.

Friendship identity gather also forces prune against published devices so
ghost rows do not receive friendship fan-out. Host integration details:
<doc:FriendshipContactBootstrap>.

## Topics

### Related coalescing constants

- ``PQSSessionConstants/peerRefreshCooldownSeconds``
- ``PQSSessionConstants/linkedDeviceRepairCooldownSeconds``
- ``PQSSessionConstants/linkedDeviceCompromiseObservedCooldownSeconds``
- ``PQSSessionConstants/controlEventEpisodeMaxLifetimeSeconds``
- ``PQSSessionConstants/forcedIdentityRefreshCoalesceWindowSeconds``

## See also

- <doc:ControlEventCoalescing>
- <doc:FriendshipContactBootstrap>
- ``PQSSession``
- ``SessionCache``

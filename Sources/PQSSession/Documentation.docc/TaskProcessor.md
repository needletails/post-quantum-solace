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

## Topics

### Related coalescing constants

- ``PQSSessionConstants/peerRefreshCooldownSeconds``
- ``PQSSessionConstants/linkedDeviceRepairCooldownSeconds``
- ``PQSSessionConstants/linkedDeviceCompromiseObservedCooldownSeconds``
- ``PQSSessionConstants/controlEventEpisodeMaxLifetimeSeconds``
- ``PQSSessionConstants/forcedIdentityRefreshCoalesceWindowSeconds``

## See also

- <doc:ControlEventCoalescing>
- ``PQSSession``
- ``SessionCache``

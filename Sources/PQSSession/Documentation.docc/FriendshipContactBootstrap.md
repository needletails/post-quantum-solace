# Friendship contact bootstrap

How hosts establish (and re-establish) a peer Double Ratchet session before
friendship traffic, including delete → re-add on multi-device accounts that
still list offline ghost devices.

## Overview

Friendship packets (`.requested`, `.accepted`, and defensive `.pending`) are
encrypted with the peer’s outbound ratchet. A `SessionIdentity` row alone is
**not** enough — the peer must receive an OTK handshake
(``TransportEvent/synchronizeOneTimeKeys``) and this device must finish outbound
sender init before the friendship payload encrypts.

``PQSSession/bootstrapPeerContactSession(secretName:purpose:)`` is the public
entry point. Call it before the first friendship send when
``PQSSession/peerNeedsOutboundBootstrap(_:)`` is `true` (or when the host knows
crypto was wiped after delete).

Published account configs can still list **ghost** devices after reinstall or
device rotation. Those rows are often still flagged master. Blanket OTK notify
to every published device leaves the live peer without a usable inbound session
and this device with `ratchet.stateUninitialized` on re-add. 3.2.0 scopes the
handshake to a **bootstrap-target** device chosen by
``PQSSession`` (see below) and optional host presence via
``PQSSessionDelegate/preferredOnlinePeerDeviceId(for:)``.

## Purposes

``PeerContactBootstrapPurpose`` selects the lane:

| Purpose | When | Behavior |
| ------- | ---- | -------- |
| ``PeerContactBootstrapPurpose/newOutbound`` | Requester sending the first friendship packet (add / re-add) | Prepare state-less identity, send OTK notify to the bootstrap-target device, drain outbound jobs, verify outbound ratchet ready |
| ``PeerContactBootstrapPurpose/friendshipReply`` | Acceptor sending `.accepted` | Reuse a live outbound ratchet when present; otherwise open a fresh OTK reply lane |

Accept must **not** always reset and re-notify. After a live inbound request
decrypt, this device often already has outbound state (e.g. from
`contactCreated` / sibling sync). Forcing a fresh OTK races the peer’s inbound
state and can drop `.accepted`.

## Bootstrap-target device selection

Internal `peerMasterDevice(for:)` preference order:

1. Host-reported online device (``PQSSessionDelegate/preferredOnlinePeerDeviceId(for:)``) that can supply a curve OTK
2. Master-flagged device that can supply a curve OTK
3. Any peer device that can supply a curve OTK
4. Online / master / first peer as a last resort

Outbound-ready checks
(``PQSSession/peerNeedsOutboundBootstrap(_:)`` /
`hasInitializedOutboundRatchetForPeer`) evaluate that **same** target device.
A ghost master row must not veto a live device that already has ratchet state.

## Friendship `blockData` and server delivery

``SessionEvents/requestFriendshipStateChange(state:contact:cache:receiver:sessionDelegate:symmetricKey:logger:)``
derives the server block/unblock flag from the **requested transition**:

- `.blocked` → `blockData=true`
- `.unblocked` (when previously blocked) → `blockData=false`
- `.requested`, `.accepted`, `.pending` → always `blockData=false`

`blockData=false` on re-establish clears a stale server `blockedUsers` entry for
the peer **before** the relationship packet is routed. Hosts/servers must apply
that unblock **before** `canDeliver` / routing; applying it after a failed route
leaves the desync permanently.

Delete alone does not “mean unblock.” Unblock is carried on friendship
re-establish packets so delivery can proceed.

## Host responsibilities

### 1. Prefer the live online peer device

```swift
func preferredOnlinePeerDeviceId(for secretName: String) async -> UUID? {
    // Return the ISON / presence device id for this secretName when known.
    onlinePresence.deviceId(for: secretName)
}
```

Default is `nil`. Multi-device hosts should override this.

### 2. Bootstrap before request / accept

```swift
if try await session.peerNeedsOutboundBootstrap(peerSecretName) {
    try await session.bootstrapPeerContactSession(
        secretName: peerSecretName,
        purpose: .newOutbound) // or .friendshipReply on accept
}
try await session.requestFriendshipStateChange(state: .requested, contact: contact)
```

### 3. Delete / pending notify

If the host uses a **local delete tombstone** (ignore inbound friendship until
an explicit re-add), do **not** call `bootstrapPeerContactSession` solely for
`.pending` delete notify. A fresh OTK on the peer can wipe crypto in a way that
lifts or races the tombstone and recreates the contact (mutual-delete ping-pong).
Pending notify is best-effort on whatever ratchet already exists.

Inbound OTK after a local delete may wipe crypto for decrypt but should **keep**
the tombstone until the user explicitly advances (`.requested` / `.accepted` /
local re-add). Tombstone policy lives in the host (e.g. NudgeKit) and should be
persisted in ``SessionContext/hostLocalPolicyData`` (app-key encrypted with the
session context DB row), not plaintext `UserDefaults`. PQS supplies the crypto
bootstrap primitives.

### 4. Suppress recovery for deleted peers (optional)

``PQSSessionDelegate/shouldSuppressInboundRecoveryFromSender(_:)`` (default
`false`) lets hosts drop inbound decrypt recovery for senders that were locally
deleted so late packets do not trigger OTK replacement storms.

## TaskProcessor behavior (3.2.0)

- `.synchronizeOneTimeKeys` encrypt jobs are filtered to the bootstrap-target
  device (not every master-flagged / preserved ghost row).
- That control event is **recovery-critical**: a single failed encrypt must not
  burn the outbound repair cooldown and leave delete→re-add stranded.
- Friendship identity gather forces prune against published devices so ghost
  rows do not receive friendship fan-out.

## Recommended delete → re-add sequence

1. **Delete** — host marks tombstone; send `.pending` without OTK bootstrap.
2. **Re-add** — clear tombstone locally; `bootstrapPeerContactSession(.newOutbound)`
   targeting the live peer; send `.requested` (with `blockData=false`).
3. **Peer** — inbound OTK may wipe crypto but keep tombstone until `.requested`
   advances; then create/update contact.
4. **Accept** — `bootstrapPeerContactSession(.friendshipReply)` (no-ops if
   outbound already ready); send `.accepted`.

## See also

- ``PQSSession/bootstrapPeerContactSession(secretName:purpose:)``
- ``PQSSession/peerNeedsOutboundBootstrap(_:)``
- ``PeerContactBootstrapPurpose``
- ``PQSSessionDelegate/preferredOnlinePeerDeviceId(for:)``
- ``PQSSessionDelegate/requestFriendshipStateChange(recipient:blockData:metadata:currentState:)``
- ``FriendshipMetadata``
- <doc:ControlEventCoalescing>

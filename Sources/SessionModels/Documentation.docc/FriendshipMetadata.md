# ``FriendshipMetadata``

Describes a friendship from both sides of the relationship and exposes
the state-machine transitions used by the SDK and apps.

## Overview

A `FriendshipMetadata` value carries three independent perspectives:

- ``FriendshipMetadata/myState`` — what *I* think of the relationship.
- ``FriendshipMetadata/theirState`` — what the SDK believes the *other*
  party thinks.
- ``FriendshipMetadata/ourState`` — the canonical, derived combination
  used by the rest of the system (computed by
  ``FriendshipMetadata/updateOurState()``).

All transitions go through the methods documented below; never mutate
the raw `State` properties without calling
``FriendshipMetadata/updateOurState()`` afterward.

## Topics

### Initialization

- ``FriendshipMetadata/init(myState:theirState:ourState:)``

### State

- ``FriendshipMetadata/State``
- ``FriendshipMetadata/myState``
- ``FriendshipMetadata/theirState``
- ``FriendshipMetadata/ourState``

### Transitions

- ``FriendshipMetadata/setRequestedState()``
- ``FriendshipMetadata/setAcceptedState()``
- ``FriendshipMetadata/resetToPendingState()``
- ``FriendshipMetadata/rejectRequest()``
- ``FriendshipMetadata/setBlockState(isBlocking:)``
- ``FriendshipMetadata/unblockUser()``

### Utilities

- ``FriendshipMetadata/updateOurState()``
- ``FriendshipMetadata/swapUserPerspectives()``

## Sending state changes over the wire

Use ``PQSSession/requestFriendshipStateChange(state:contact:)`` to
publish a friendship state change to the remote party. The SDK
serializes the new `FriendshipMetadata` and routes it through the
configured ``SessionTransport``.

## State priority

`updateOurState()` resolves contradictory perspectives by collapsing
them to a single canonical state. The full priority list is:

1. Mutual block (canonical block + blocked-by-other) → `.blocked`.
2. `myState == .blocked` → no further changes from this side.
3. Both sides `.accepted` → `.accepted`.
4. `myState == .requested`, `theirState == .pending` → `.pending`.
5. Mutual rejection → `.mutuallyRejected`.
6. Both `.pending` → `.pending`.
7. `theirState == .blockedByOther` → `.blocked`.
8. `myState == .requested`, `theirState == .requested` → `.requested`.
9. Otherwise → `.pending`.

## See also

- ``Contact``
- ``ContactModel``
- ``PQSSession``
- ``SessionEvents``

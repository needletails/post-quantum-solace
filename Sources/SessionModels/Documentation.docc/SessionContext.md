# ``SessionContext``

The central container for all session-level state: the local
``SessionUser``, the database encryption key, the active
``UserConfiguration``, the device-scoped session id, the user's
``SessionContext/RegistrationState``, and an optional host-local
policy blob.

## Overview

`SessionContext` is created by ``PQSSession`` at session-open time,
encrypted into the secure store with the application-derived symmetric
key, and rehydrated on every cold start. You very rarely construct one
yourself — instead you read it back from inside the SDK during
operations such as identity recovery or device management.

Coding keys are intentionally single-letter for on-disk obfuscation.

``SessionContext/hostLocalPolicyData`` is an opaque optional blob for
host SDKs (e.g. NudgeKit delete tombstones). It is encrypted with the
same app-password–derived key as the rest of this row. Older contexts
omit the field; treat missing data as empty.

## Topics

### Initialization

- ``SessionContext/init(sessionUser:databaseEncryptionKey:sessionContextId:activeUserConfiguration:registrationState:hostLocalPolicyData:)``

`hostLocalPolicyData` defaults to `nil`.

### State

- ``SessionContext/sessionUser``
- ``SessionContext/databaseEncryptionKey``
- ``SessionContext/sessionContextId``
- ``SessionContext/activeUserConfiguration``
- ``SessionContext/registrationState``
- ``SessionContext/hostLocalPolicyData``

### Mutation

- ``SessionContext/updateSessionUser(_:)``

### Companion types

- ``SessionUser``
- ``UserConfiguration``
- ``RegistrationState``
- ``LinkDeviceInfo``
- ``LinkedDeviceReprovisioningBundle``
- ``DeviceLinkingDelegate``

## Trust model

`activeUserConfiguration.signingPublicKey` is the **account-level**
TOFU-pinned key on this device. It is updated only through
``PQSSession/adoptVerifiedUserConfiguration(_:)`` (which enforces the
local pin) or after the user explicitly acknowledges an identity
change with ``PQSSession/acknowledgeAccountIdentityChange(_:)``. Direct
in-place mutation of this property bypasses TOFU and should be avoided.

## Linked devices

When a master device rotates the account-level signing key it pushes
the new ``UserConfiguration`` to each linked device wrapped in a
``LinkedDeviceReprovisioningBundle``. The bundle never contains private
key material — every device retains its per-device signing private key
for the lifetime of its `DeviceID`.

Implementations of ``DeviceLinkingDelegate`` are responsible for
producing a ``LinkDeviceInfo`` payload during the initial linking
exchange.

## See also

- ``PQSSession``
- ``UserConfiguration``
- ``SecurityIdentity``

# ``UserConfiguration``

The user's published cryptographic identity: an account-level signing
public key plus signed device descriptors and signed one-time keys.

## Overview

A `UserConfiguration` is what the server distributes to peers so they
can talk to a user's devices. It contains:

- ``UserConfiguration/signingPublicKey`` — the account-level Curve25519
  signing public key (the TOFU-pinned key).
- ``UserConfiguration/signedDevices`` — for each device the user owns,
  a ``UserConfiguration/SignedDeviceConfiguration`` whose payload is a
  ``UserDeviceConfiguration`` signed by the account-level key.
- ``UserConfiguration/signedOneTimePublicKeys`` — Curve25519 one-time
  prekeys (``UserConfiguration/SignedOneTimePublicKey``).
- ``UserConfiguration/signedMLKEMOneTimePublicKeys`` — post-quantum
  ML-KEM one-time prekeys (``UserConfiguration/SignedMLKEMOneTimeKey``).

Every "signed" container verifies the inner payload against
``UserConfiguration/signingPublicKey`` before returning it.

## Topics

### Initialization

- ``UserConfiguration/init(signingPublicKey:signedDevices:signedOneTimePublicKeys:signedMLKEMOneTimePublicKeys:)``

### Identity & devices

- ``UserConfiguration/signingPublicKey``
- ``UserConfiguration/signedDevices``
- ``UserConfiguration/getVerifiedDevices()``
- ``UserDeviceConfiguration``

### One-time keys

- ``UserConfiguration/signedOneTimePublicKeys``
- ``UserConfiguration/signedMLKEMOneTimePublicKeys``
- ``UserConfiguration/getVerifiedCurveKeys(deviceId:)``
- ``UserConfiguration/getVerifiedMLKEMKeys(deviceId:)``
- ``OneTimeKeys``
- ``RotatedPublicKeys``
- ``KeysType``

### Signed containers

- ``UserConfiguration/SignedDeviceConfiguration``
- ``UserConfiguration/SignedOneTimePublicKey``
- ``UserConfiguration/SignedMLKEMOneTimeKey``

## Verifying a peer's configuration

```swift
let config = try await transport.findConfiguration(for: "alice")

// Devices are verified against config.signingPublicKey internally.
let devices = try config.getVerifiedDevices()

// Per-device prekey buckets.
for device in devices {
    let curveKeys = try config.getVerifiedCurveKeys(deviceId: device.deviceId)
    let kemKeys = try config.getVerifiedMLKEMKeys(deviceId: device.deviceId)
    // ... pick a key, send a message
}
```

## Trust model

The account-level ``UserConfiguration/signingPublicKey`` is the trust
root of a user. Rotating it is what causes the ``SecurityIdentity``
fingerprint and safety number to change. The SDK pins this key locally
on first sight (TOFU). To change it later you must either:

- prove the rotation through an authenticated rotation channel
  (``PQSSession/rotateKeysOnPotentialCompromise()`` /
  ``PQSSession/updateUserConfiguration(_:)``); or
- have the user explicitly acknowledge the change via
  ``PQSSession/acknowledgeAccountIdentityChange(_:)``.

## See also

- ``UserDeviceConfiguration``
- ``SecurityIdentity``
- ``PQSSession``

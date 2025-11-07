# ``UserConfiguration``

A model representing a user's cryptographic configuration and device information.

## Overview

`UserConfiguration` contains all the public cryptographic information for a user, including signed device configurations, one-time public keys, and signing keys. This configuration is shared publicly and used by other users to establish secure communications.

## Topics

### Essentials

- ``UserConfiguration/init(signingPublicKey:signedDevices:signedOneTimePublicKeys:signedMLKEMOneTimePublicKeys:)``
- ``UserConfiguration/signingPublicKey``
- ``UserConfiguration/signedDevices``
- ``UserConfiguration/signedOneTimePublicKeys``
- ``UserConfiguration/signedMLKEMOneTimePublicKeys``

### Device Management

- ``UserConfiguration/SignedDeviceConfiguration``
- ``UserConfiguration/SignedOneTimePublicKey``
- ``UserConfiguration/SignedMLKEMOneTimeKey``

### Key Verification

- ``UserConfiguration/getVerifiedCurveKeys(deviceId:)``
- ``UserConfiguration/getVerifiedMLKEMKeys(deviceId:)``

## Key Features

- **Public Configuration**: Contains only public cryptographic information
- **Signed Devices**: All device configurations are cryptographically signed
- **One-Time Keys**: Pre-generated one-time keys for immediate communication
- **Post-Quantum Support**: Includes both classical and post-quantum keys
- **Device Verification**: Methods to verify and extract keys for specific devices

## Security Considerations

- **Public Data**: This configuration contains only public information and can be shared safely
- **Signed Content**: All device configurations and keys are cryptographically signed
- **Key Verification**: Keys are verified against the signing public key before use
- **No Private Keys**: Private keys are never included in this configuration

## Usage

### Creating a User Configuration

```swift
// Create signed device configurations
let signedDevices = try devices.map { device in
    try UserConfiguration.SignedDeviceConfiguration(
        device: device,
        signingKey: signingPrivateKey
    )
}

// Create signed one-time public keys
let signedOneTimeKeys = try oneTimeKeys.map { key in
    try UserConfiguration.SignedOneTimePublicKey(
        key: key,
        deviceId: deviceId,
        signingKey: signingPrivateKey
    )
}

// Create signed PQ-KEM one-time keys
let signedMLKEMKeys = try mlKEMKeys.map { key in
    try UserConfiguration.SignedMLKEMOneTimeKey(
        key: key,
        deviceId: deviceId,
        signingKey: signingPrivateKey
    )
}

// Create the user configuration
let userConfig = UserConfiguration(
    signingPublicKey: signingPublicKey.rawRepresentation,
    signedDevices: signedDevices,
    signedOneTimePublicKeys: signedOneTimeKeys,
    signedMLKEMOneTimePublicKeys: signedMLKEMKeys
)
```

### Verifying and Extracting Keys

```swift
// Get verified Curve25519 keys for a specific device
let curveKeys = userConfig.getVerifiedCurveKeys(deviceId: deviceId)

// Get verified PQ-KEM keys for a specific device
let mlKEMKeys = userConfig.getVerifiedMLKEMKeys(deviceId: deviceId)

// Use the keys for cryptographic operations
for key in curveKeys {
    // Verify the key signature
    guard key.verified(using: signingPublicKey) != nil else {
        continue // Skip invalid keys
    }
    
    // Use the key for encryption
    let encrypted = try encrypt(data: messageData, with: key)
}
```

### Working with Device Configurations

```swift
// Access device configurations
for signedDevice in userConfig.signedDevices {
    // Verify the device signature
    guard let device = signedDevice.verified(using: signingPublicKey) else {
        continue // Skip invalid devices
    }
    
    // Access device information
    let deviceId = device.deviceId
    let deviceName = device.deviceName
    let isMaster = device.isMasterDevice
    
    // Use device for communication
    if isMaster {
        // Handle master device
        await establishCommunication(with: device)
    }
}
```

### Key Management

```swift
// Access one-time keys
let oneTimeKeys = userConfig.signedOneTimePublicKeys
let mlKEMKeys = userConfig.signedMLKEMOneTimePublicKeys

// Filter keys by device
let deviceKeys = oneTimeKeys.filter { key in
    key.deviceId == targetDeviceId
}

// Use keys for key exchange
for key in deviceKeys {
    guard let verifiedKey = key.verified(using: signingPublicKey) else {
        continue
    }
    
    // Perform key exchange
    let sharedSecret = try performKeyExchange(with: verifiedKey)
}
```

## Data Structure

### SignedDeviceConfiguration

```swift
public struct SignedDeviceConfiguration: Codable & Sendable {
    public let device: UserDeviceConfiguration
    public let signature: Data
    
    public init(device: UserDeviceConfiguration, signingKey: Curve25519SigningPrivateKey) throws
    public func verified(using publicKey: Curve25519SigningPublicKey) throws -> UserDeviceConfiguration?
}
```

### SignedOneTimePublicKey

```swift
public struct SignedOneTimePublicKey: Codable & Sendable {
    public let key: CurvePublicKey
    public let deviceId: UUID
    public let signature: Data
    
    public init(key: CurvePublicKey, deviceId: UUID, signingKey: Curve25519SigningPrivateKey) throws
    public func verified(using publicKey: Curve25519SigningPublicKey) throws -> CurvePublicKey?
}
```

### SignedMLKEMOneTimeKey

```swift
public struct SignedMLKEMOneTimeKey: Codable & Sendable {
    public let key: MLKEMPublicKey
    public let deviceId: UUID
    public let signature: Data
    
    public init(key: MLKEMPublicKey, deviceId: UUID, signingKey: Curve25519SigningPrivateKey) throws
    public func verified(using publicKey: Curve25519SigningPublicKey) throws -> MLKEMPublicKey?
}
```

## Key Verification Process

### Device Verification

1. **Extract Device**: Get the device configuration from the signed structure
2. **Verify Signature**: Check the signature against the signing public key
3. **Validate Device**: Ensure the device configuration is valid
4. **Return Device**: Return the verified device configuration

### Key Verification

1. **Extract Key**: Get the public key from the signed structure
2. **Verify Signature**: Check the signature against the signing public key
3. **Validate Key**: Ensure the key is valid and not expired
4. **Return Key**: Return the verified public key

## Integration with Session

The `UserConfiguration` is used throughout the session system:

```swift
// Store user configuration
sessionContext.activeUserConfiguration = userConfig

// Publish configuration to network
try await transportDelegate.publishUserConfiguration(userConfig, recipient: deviceId)

// Find configuration for other users
let otherUserConfig = try await transportDelegate.findConfiguration(for: secretName)
```

## Best Practices

### Security
- Always verify signatures before using keys or devices
- Never include private keys in the configuration
- Use strong signing keys for device and key signatures
- Regularly rotate signing keys

### Key Management
- Generate sufficient one-time keys
- Monitor key usage and regenerate when needed
- Implement proper key expiration
- Handle key conflicts gracefully

### Device Management
- Sign all device configurations
- Validate device information before signing
- Implement device revocation mechanisms
- Monitor device activity

### Performance
- Cache verified configurations
- Implement efficient key lookup
- Use batch operations for key verification
- Monitor verification performance

## Error Handling

Implement proper error handling for verification:

```swift
func getVerifiedKeys(for deviceId: UUID) -> [CurvePublicKey] {
    var verifiedKeys: [CurvePublicKey] = []
    
    for signedKey in signedOneTimePublicKeys {
        do {
            if let key = try signedKey.verified(using: signingPublicKey) {
                verifiedKeys.append(key)
            }
        } catch {
            logger.warning("Failed to verify key: \(error)")
            continue
        }
    }
    
    return verifiedKeys
}
```

## Thread Safety

The `UserConfiguration` struct is designed for concurrent access:
- **Sendable Conformance**: Safe to pass between concurrent contexts
- **Immutable Design**: All properties are immutable after creation
- **Thread-Safe Verification**: Verification methods are thread-safe
- **No Mutable State**: No internal mutable state that could cause race conditions 

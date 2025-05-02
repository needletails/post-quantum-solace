//
//  CryptoSession+SessionIdentity.swift
//  crypto-session
//
//  Created by Cole M on 2/9/25.
//
import Foundation
import NeedleTailCrypto
import DoubleRatchetKit
import SessionModels

// MARK: - CryptoSession Extension for Identity Management

extension CryptoSession {
    
    /// Refreshes the session identities associated with a given secret name.
    /// This method ensures that the identities are up to date by filtering and refreshing them.
    /// - Parameter secretName: The secret name for which to refresh identities.
    /// - Returns: An array of updated `SessionIdentity` objects.
    /// - Throws: An error if the identity refresh fails.
    public func refreshIdentities(secretName: String) async throws -> [SessionIdentity] {
        let filtered = try await getSessionIdentities(with: secretName)
        // Always make sure the identities are up to date
        return try await refreshSessionIdentities(for: secretName, from: filtered)
    }
    
    /// Creates a new encryptable session identity model.
    /// - Parameters:
    ///   - device: The user device configuration for the new identity.
    ///   - secretName: The secret name associated with the identity.
    ///   - deviceId: The unique identifier of the device.
    ///   - sessionContextId: A new session context identifier.
    /// - Returns: A newly created `SessionIdentity` object.
    /// - Throws: An error if the identity creation fails.
    public func createEncryptableSessionIdentityModel(
        with device: UserDeviceConfiguration,
        for secretName: String,
        associatedWith deviceId: UUID,
        new sessionContextId: Int
    ) async throws -> SessionIdentity {
        guard let cache = cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        
        let identity = try await SessionIdentity(
            id: UUID(),
            props: .init(
                secretName: secretName,
                deviceId: deviceId,
                sessionContextId: sessionContextId,
                publicLongTermKey: device.publicLongTermKey,
                publicSigningKey: device.publicSigningKey,
                kyber1024PublicKey: device.kyber1024PublicKey,
                state: nil,
                deviceName: determinDeviceName(),
                isMasterDevice: device.isMasterDevice
            ),
            symmetricKey: getDatabaseSymmetricKey()
        )
        try await cache.createSessionIdentity(identity)
        return identity
    }
    
    /// Determines a unique device name for the current device.
    /// This method checks existing device names and increments a count if necessary to ensure uniqueness.
    /// - Returns: A unique device name as a `String`.
    /// - Throws: An error if the device name determination fails.
    func determinDeviceName() async throws -> String {
        guard let cache else { return "Unknown Device" }
        var existingNames: [String] = []
        
        // Fetch existing device names
        for context in try await cache.fetchSessionIdentities() {
            guard let props = try await context.props(symmetricKey: getDatabaseSymmetricKey()) else { continue }
            existingNames.append(props.deviceName)
        }
        
        let baseName = getDeviceName() // e.g., "mac16"
        var count = 1
        var newDeviceName = baseName
        
        // Check for existing names and increment the count if necessary
        while existingNames.contains(newDeviceName) {
            newDeviceName = "\(baseName) (\(count))"
            count += 1
        }
        
        return newDeviceName.isEmpty ? "Unknown Device" : newDeviceName
    }
    
    /// Retrieves session identities associated with a specified recipient name.
    /// This method filters out identities that do not match the recipient name or are the current user's identities.
    /// - Parameter recipientName: The name of the recipient for which to retrieve identities.
    /// - Returns: An array of `SessionIdentity` objects associated with the recipient.
    /// - Throws: An error if the retrieval fails.
    public func getSessionIdentities(with recipientName: String) async throws -> [SessionIdentity] {
        guard let sessionContext = await sessionContext else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        guard let cache = cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        
        let identities = try await cache.fetchSessionIdentities()
        return await identities.asyncFilter { identity in
            do {
                let symmetricKey = try await getDatabaseSymmetricKey()
                let props = try await identity.makeDecryptedModel(of: _SessionIdentity.self, symmetricKey: symmetricKey)
                // Check if the identity is not the current user's identity
                let myChildIdentity = props.secretName == sessionContext.sessionUser.secretName && props.deviceId != sessionContext.sessionUser.deviceId
                // Return true if the secret name matches the recipient name or if it's a different identity
                return (props.secretName == recipientName) || myChildIdentity
            } catch {
                return false
            }
        }
    }
    
    /// Refreshes the session identities for a specified recipient name based on the provided filtered identities.
    /// This method verifies the devices and removes any stale identities that are no longer valid.
    /// - Parameters:
    ///   - recipientName: The name of the recipient for whom to refresh identities.
    ///   - filtered: An array of previously filtered `SessionIdentity` objects.
    /// - Returns: An updated array of `SessionIdentity` objects.
    /// - Throws: An error if the refresh operation fails.
    func refreshSessionIdentities(for recipientName: String, from filtered: [SessionIdentity]) async throws -> [SessionIdentity] {
        
        var filtered = filtered
        guard let transportDelegate = transportDelegate else {
            throw CryptoSession.SessionErrors.transportNotInitialized
        }
        
        guard let currentDeviceId = await sessionContext?.sessionUser.deviceId else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }
        
        // Get the user configuration for the recipient
        let configuration = try await transportDelegate.findConfiguration(for: recipientName)
        var verifiedDevices = try configuration.getVerifiedDevices()
        var collected = [UserDeviceConfiguration]()
        
        // Create a set of existing device IDs from the filtered identities for quick lookup
        let existingDeviceIds = await Set(filtered.asyncCompactMap {
            try? await $0.props(symmetricKey: getDatabaseSymmetricKey())?.deviceId })
        
        for device in verifiedDevices {
            // Only collect devices that are not already in the filtered identities
            if !existingDeviceIds.contains(device.deviceId) && device.deviceId != currentDeviceId {
                collected.append(device)
            }
        }
        
        // Ensure that the identities of the user configuration are legitimate
        let publicSigningKey = try Curve25519SigningPublicKey(rawRepresentation: configuration.publicSigningKey)
        
        for device in configuration.signedDevices {
            if try (device.verified(using: publicSigningKey) != nil) == false {
                throw CryptoSession.SessionErrors.invalidSignature
            }
        }
        
        var generatedSessionContextIds = Set<Int>()
        
        for device in collected {
            // Check if the device ID is already in the filtered identities
            if !existingDeviceIds.contains(device.deviceId) && device.deviceId != currentDeviceId {
                var sessionContextId: Int
                repeat {
                    sessionContextId = Int.random(in: 1 ..< Int.max)
                } while generatedSessionContextIds.contains(sessionContextId)
                
                generatedSessionContextIds.insert(sessionContextId)
                let identity = try await createEncryptableSessionIdentityModel(
                    with: device,
                    for: recipientName,
                    associatedWith: device.deviceId,
                    new: sessionContextId)
                filtered.append(identity)
            }
        }
        
        // This will get all identities that are the recipient name and a child device.
        let newfilter = try await getSessionIdentities(with: recipientName)
        let newDeviceIds = await Set(newfilter.asyncCompactMap {
            try? await $0.props(symmetricKey: getDatabaseSymmetricKey())?.deviceId })
        
        guard let myDevices = try await sessionContext?.lastUserConfiguration.getVerifiedDevices() else { return [] }
        
        verifiedDevices.append(contentsOf: myDevices)
        
        for deviceId in newDeviceIds {
            let isVerified = verifiedDevices.contains { verifiedDevice in
                verifiedDevice.deviceId == deviceId
            }
            
            if !isVerified {
                logger.log(level: .info, message: "Will remove stale session identity for recipient: \(recipientName)")
                // If our current list in the DB contains a session identity that is not in the master list, we need to remove it.
                if let identityToRemove = await filtered.asyncFirst(where: { element in
                    // Try to get the properties for each element.
                    guard let props = try? await element.props(symmetricKey: getDatabaseSymmetricKey()) else {
                        return false
                    }
                    // Compare the deviceIds; make sure deviceId is available in this scope.
                    return props.deviceId == deviceId
                }) {
                    try await cache?.removeSessionIdentity(identityToRemove.id)
                    logger.log(level: .info, message: "Did remove stale session identity for recipient: \(recipientName)")
                    
                    // Remove the identity from the filtered array.
                    if let index = filtered.firstIndex(where: { identity in
                        identity.id == identityToRemove.id
                    }) {
                        filtered.remove(at: index)
                    }
                }
            }
        }
        return filtered
    }
}

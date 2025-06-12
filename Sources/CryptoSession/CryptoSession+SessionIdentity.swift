//
//  CryptoSession+SessionIdentity.swift
//  post-quantum-solace
//
//  Created by Cole M on 2/9/25.
//
import Foundation
import NeedleTailCrypto
import DoubleRatchetKit
import SessionModels
import BSON

// MARK: - CryptoSession Extension for Identity Management

extension CryptoSession {
    
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
        publicOneTimeKey: Curve25519PublicKeyRepresentable?,
        publicKyber1024Key: Kyber1024PublicKeyRepresentable,
        for secretName: String,
        associatedWith deviceId: UUID,
        new sessionContextId: Int
    ) async throws -> SessionIdentity {
        guard let cache = cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        let determindedDeviceName = try await determineDeviceName()
        let deviceName = device.deviceName ?? determindedDeviceName
        let identity = try await SessionIdentity(
            id: UUID(),
            props: .init(
                secretName: secretName,
                deviceId: deviceId,
                sessionContextId: sessionContextId,
                publicLongTermKey: device.publicLongTermKey,
                publicSigningKey: device.publicSigningKey,
                kyber1024PublicKey: publicKyber1024Key,
                publicOneTimeKey: publicOneTimeKey,
                state: nil,
                deviceName: deviceName,
                isMasterDevice: device.isMasterDevice
            ),
            symmetricKey: getDatabaseSymmetricKey())
        try await cache.createSessionIdentity(identity)
        return identity
    }
    
    /// Determines a unique device name for the current device.
    /// This method checks existing device names and increments a count if necessary to ensure uniqueness.
    /// - Returns: A unique device name as a `String`.
    /// - Throws: An error if the device name determination fails.
    func determineDeviceName() async throws -> String {
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
    
    
    /// Refreshes the session identities associated with a given secret name.
    /// This method ensures that the identities are up to date by filtering and refreshing them.
    /// - Parameter secretName: The secret name for which to refresh identities.
    /// - Returns: An array of updated `SessionIdentity` objects.
    /// - Throws: An error if the identity refresh fails.
    public func refreshIdentities(secretName: String, forceRefresh: Bool = false) async throws -> [SessionIdentity] {
        let filtered = try await getSessionIdentities(with: secretName)
        // Always make sure the identities are up to date
        do {
            return try await refreshSessionIdentities(
                for: secretName,
                from: filtered,
                forceRefresh: forceRefresh)
        } catch {
            return filtered
        }
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
        guard let cache = cache else {
            throw CryptoSession.SessionErrors.databaseNotInitialized
        }
        
        let identities = try await cache.fetchSessionIdentities()
        return await identities.asyncFilter { identity in
            do {
                let symmetricKey = try await getDatabaseSymmetricKey()
                guard let props = await identity.props(symmetricKey: symmetricKey) else { return false }
                
                // Check if the identity is not the current user's identity
                let myChildIdentity = props.secretName == sessionContext.sessionUser.secretName && props.deviceId != sessionContext.sessionUser.deviceId
                // Return true if the secret name matches the recipient name or if it's a different identity
                return (props.secretName == recipientName) || myChildIdentity
            } catch {
                return false
            }
        }
    }
    
    private func refreshIdentities(secretName: String, forceRefresh: Bool) async -> Bool {
        if forceRefresh || sessionIdentities.isEmpty || !sessionIdentities.contains(secretName) {
            return true
        } else {
            return false
        }
    }
    
    /// Refreshes the session identities for a specified recipient name based on the provided filtered identities.
    /// This method verifies the devices and removes any stale identities that are no longer valid.
    /// - Parameters:
    ///   - recipientName: The name of the recipient for whom to refresh identities.
    ///   - filtered: An array of previously filtered `SessionIdentity` objects.
    /// - Returns: An updated array of `SessionIdentity` objects.
    /// - Throws: An error if the refresh operation fails.
    func refreshSessionIdentities(
        for recipientName: String,
        from filtered: [SessionIdentity],
        forceRefresh: Bool) async throws -> [SessionIdentity] {
        
        var filtered = filtered
        guard let transportDelegate = transportDelegate else {
            throw CryptoSession.SessionErrors.transportNotInitialized
        }
        
        guard let sessionUser = await sessionContext?.sessionUser else {
            throw CryptoSession.SessionErrors.sessionNotInitialized
        }

        if await refreshIdentities(secretName: recipientName, forceRefresh: forceRefresh) {
            // Get the user configuration for the recipient
            let configuration = try await transportDelegate.findConfiguration(for: recipientName)
            var verifiedDevices = try configuration.getVerifiedDevices()
            var collected = [UserDeviceConfiguration]()
            // Create a set of existing device IDs from the filtered identities for quick lookup
            let existingDeviceIds = await Set(filtered.asyncCompactMap {
                try? await $0.props(symmetricKey: getDatabaseSymmetricKey())?.deviceId })
            
            for device in verifiedDevices {
                // Only collect devices that are not already in the filtered identities
                if !existingDeviceIds.contains(device.deviceId) && device.deviceId != sessionUser.deviceId {
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
                if !existingDeviceIds.contains(device.deviceId) && device.deviceId != sessionUser.deviceId {
                    var sessionContextId: Int
                    repeat {
                        sessionContextId = Int.random(in: 1 ..< Int.max)
                    } while generatedSessionContextIds.contains(sessionContextId)
                    
                    generatedSessionContextIds.insert(sessionContextId)
                    
                    let keys = try await transportDelegate.fetchOneTimeKeys(for: recipientName, deviceId: device.deviceId.uuidString)

                    let signedPublicOneTimeKey = try configuration.signedPublicOneTimeKeys.first(where: { $0.id == keys.curve?.id })?.verified(using: publicSigningKey)
                    
                    var publicKyber1024Key: Kyber1024PublicKeyRepresentable
                    if let signedKey = try configuration.signedPublicKyberOneTimeKeys.first(where: { $0.id == keys.kyber?.id })?.kyberVerified(using: publicSigningKey) {
                        publicKyber1024Key = signedKey
                    } else if let verifiedDevice = configuration.signedDevices.first(where: {
                        (try? $0.verified(using: publicSigningKey))?.deviceId == device.deviceId
                    }),
                    let finalKey = try? verifiedDevice.verified(using: publicSigningKey)?.finalKyber1024PublicKey {
                        publicKyber1024Key = finalKey
                    } else {
                        throw CryptoSession.SessionErrors.drainedKeys
                    }
                    
                    let identity = try await createEncryptableSessionIdentityModel(
                        with: device,
                        publicOneTimeKey: signedPublicOneTimeKey,
                        publicKyber1024Key: publicKyber1024Key,
                        for: recipientName,
                        associatedWith: device.deviceId,
                        new: sessionContextId)
                    logger.log(level: .info, message: "Created Session Identity: \(identity)")
                    filtered.append(identity)
                    
                    try await transportDelegate.notifyIdentityCreation(for: recipientName, keys: keys)
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
            sessionIdentities.insert(recipientName)
        }
        return filtered
    }
}

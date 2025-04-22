//
//  CryptoSession+SessionIdentity.swift
//  crypto-session
//
//  Created by Cole M on 2/9/25.
//
import Foundation
import NeedleTailCrypto
import DoubleRatchetKit
import Crypto
import BSON
import SessionModels

extension CryptoSession {
    
    public func refreshIdentities(secretName: String) async throws -> [SessionIdentity] {
        let filtered = try await getSessionIdentities(with: secretName)
        //Allways make sure the identities are up to date
        return try await refreshSessionIdentities(for: secretName, from: filtered)
    }
    
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
                publicKeyRepesentable: device.publicKey,
                publicSigningRepresentable: device.publicSigningKey,
                state: nil,
                deviceName: determinDeviceName(),
                isMasterDevice: device.isMasterDevice
            ),
            symmetricKey: getDatabaseSymmetricKey()
        )
        try await cache.createSessionIdentity(identity)
        return identity
    }
    
    
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
    
    
    ///This is only used to get get recipient identites, none of our Device Configuration information.
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
        
        // Make sure that the identities of the user configuration are legit
        let publicSigningKey = try Curve25519SigningPublicKey(rawRepresentation: configuration.publicSigningKey)
        if try configuration.signed.verifySignature(publicKey: publicSigningKey) == false {
            throw CryptoSession.SessionErrors.invalidSignature
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
        
        //This will get all identities that are the recipient name and a child device.
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
                // If our current list on the DB contains a session identity that is not in the master list, we need to remove it.
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

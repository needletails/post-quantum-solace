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

extension CryptoSession {
    
    public func refreshIdentities(secretName: String) async throws {
        let filtered = try await getSessionIdentities(with: secretName)
        //Allways make sure the identities are up to date
        try await refreshSessionIdentities(for: secretName, from: filtered)
    }
    
    public func createEncryptableSessionIdentityModel(
        with device: UserDeviceConfiguration,
        for secretName: String,
        associatedWith deviceId: UUID,
        new sessionContextId: Int
    ) async throws -> SessionIdentity {
        guard let sessionContext = await sessionContext else { throw CryptoSession.SessionErrors.sessionNotInitialized }
        guard let cache = await cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        
        let identity = try await SessionIdentity(
            id: UUID(),
            props: .init(
                secretName: secretName,
                deviceId: deviceId,
                sessionContextId: sessionContextId,
                publicKeyRepesentable: device.publicKey,
                publicSigningRepresentable: device.publicSigningKey,
                state: nil,
                deviceName: device.deviceName ?? "Unknown Device Name",
                isMasterDevice: device.isMasterDevice
            ),
            symmetricKey: getDatabaseSymmetricKey()
        )
        try await cache.createSessionIdentity(identity)
        return identity
    }
    
    
    ///This is only used to get get recipient identites, none of our Device Configuration information.
    public func getSessionIdentities(with recipientName: String) async throws -> [SessionIdentity] {
        
        guard let sessionContext = await sessionContext else { throw CryptoSession.SessionErrors.sessionNotInitialized }
        guard let cache = await cache else { throw CryptoSession.SessionErrors.databaseNotInitialized }
        
        let identities = try await cache.fetchSessionIdentities()
        let symmetricKey = try await getDatabaseSymmetricKey()
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
        let verifiedDevices = try await configuration.getVerifiedDevices()
        var collected = [UserDeviceConfiguration]()

        // Create a set of existing device IDs from the filtered identities for quick lookup
        let existingDeviceIds = await Set(filtered.asyncCompactMap {
            try? await $0.props(symmetricKey: getDatabaseSymmetricKey())?.deviceId }
        )
        
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
        return filtered
    }
    
}

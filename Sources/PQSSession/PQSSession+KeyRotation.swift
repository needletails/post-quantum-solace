//
//  PQSSession+KeyRotation.swift
//  post-quantum-solace
//
//  Created by Cole M on 6/20/25.
//
import Foundation
import SessionModels
import BSON
import NeedleTailCrypto
import DoubleRatchetKit

extension PQSSession {
    
    /// Rotates the Long-Term Curve, Final PQKem and Signing Key when a user suspects that their keys may have been compromised.
    ///
    /// This method replaces and publishes the current device's keys. The API consumer, likely the transport layer,
    /// is responsible for publishing the rotated keys by conforming to the `publishRotatedKeys` method.
    ///
    /// The following steps are required when invoking this method:
    /// 1. Send the new signed device information and the new `signingPublicKey` to the remote store.
    /// 2. Notify the recipient that the keys have been rotated due to a potential compromise.
    ///
    /// After receiving the notification, the recipient must manually verify the fingerprint of the rotated keys
    /// by using the `fingerprint(from:_)` method. Therefore, when the sender (the one rotating the keys)
    /// notifies the receiver of the rotated keys, the `signingPublicKey` data should be included for verification.
    ///
    /// - Throws: An error if the key rotation fails.
    public func rotateKeysOnPotentialCompromise() async throws {
        await setRotatingKeys(true)
        
        let longTerm = try createLongTermKeys()
        let kyberId = UUID()
        let kyberPrivateKey = try PQKemPrivateKey(id: kyberId, longTerm.kyber.encode())
        let kyberPublicKey = try PQKemPublicKey(id: kyberId, longTerm.kyber.publicKey.rawRepresentation)
        
        var sessionContext = try await getSessionContext()
        
        let oldSigningKeyData = sessionContext.lastUserConfiguration.signingPublicKey
        let oldSigningKey = try Curve25519SigningPublicKey(rawRepresentation: oldSigningKeyData)
        
        guard let index = sessionContext
            .lastUserConfiguration
            .signedDevices
            .firstIndex(where: { signed in
                guard let verified = try? signed.verified(using: oldSigningKey) else { return false }
                return verified.deviceId == sessionContext.sessionUser.deviceId
            }) else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }
        guard var device = try sessionContext.lastUserConfiguration.signedDevices[index]
            .verified(using: oldSigningKey) else {
            throw SessionErrors.invalidSignature
        }
        
        await device.updateSigningPublicKey(longTerm.signing.publicKey.rawRepresentation)
        await device.updateLongTermPublicKey(longTerm.curve.publicKey.rawRepresentation)
        await device.updateFinalPQKemPublicKey(kyberPublicKey)
        
        let reSigned = try UserConfiguration.SignedDeviceConfiguration(device: device, signingKey: longTerm.signing)
        
        sessionContext.sessionUser.deviceKeys.signingPrivateKey = longTerm.signing.rawRepresentation
        sessionContext.lastUserConfiguration.signingPublicKey = longTerm.signing.publicKey.rawRepresentation
        sessionContext.sessionUser.deviceKeys.longTermPrivateKey = longTerm.curve.rawRepresentation
        sessionContext.sessionUser.deviceKeys.finalPQKemPrivateKey = kyberPrivateKey
        sessionContext.lastUserConfiguration.signedDevices[index] = reSigned
        
        try await updateRotatedKeySessionContext(sessionContext: sessionContext)
        
        //Send Public Keys to server
        try await transportDelegate?.publishRotatedKeys(
            for: sessionContext.sessionUser.secretName,
            deviceId: sessionContext.sessionUser.deviceId.uuidString,
            rotated: .init(pskData: device.signingPublicKey, signedDevice: reSigned))
    }
    
    func setRotatingKeys(_ rotating: Bool) async {
        rotatingKeys = rotating
    }
}

extension PQSSession {
    func rotatePQKemKeysIfNeeded() async throws -> Bool {
        if let rotateKeyDate = await sessionContext?.sessionUser.deviceKeys.rotateKeysDate {
            // Get the current date
            let currentDate = Date()
            
            // Create a Calendar instance
            let calendar = Calendar.current
            
            // Calculate the date one week ago from the current date
            if let oneWeekAgo = calendar.date(byAdding: .weekOfYear, value: -1, to: currentDate) {
                // Check if rotateKeyDate is older than or equal to one week ago
                if rotateKeyDate <= oneWeekAgo {
                    
                    try await rotatePQKemFinalKey()
                    
                    guard let cache else {
                        throw SessionErrors.databaseNotInitialized
                    }
                    let data = try await cache.findLocalSessionContext()
                    
                    guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
                        throw SessionErrors.sessionDecryptionError
                    }
                    
                    // Decode the session context from the decrypted data
                    var sessionContext = try BSONDecoder().decodeData(SessionContext.self, from: configurationData)
                    await sessionContext.sessionUser.deviceKeys.updateRotateKeysDate(Date())
                    try await updateRotatedKeySessionContext(sessionContext: sessionContext)
                    return true
                } else {
                    logger.log(level: .trace, message: "Not time to rotate keys")
                    return false
                }
            }
        }
        return false
    }
}

extension PQSSession {
    
    fileprivate func getSessionContext() async throws -> SessionContext {
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        
        let config = try await cache.findLocalSessionContext()
        
        // Decrypt the session context data using the app's symmetric key
        guard let configurationData = try await crypto.decrypt(data: config, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }
        
        // Decode the session context from the decrypted data
        return try BSONDecoder().decodeData(SessionContext.self, from: configurationData)
    }
    
    fileprivate func updateRotatedKeySessionContext(sessionContext: SessionContext) async throws {
        var sessionContext = sessionContext
        
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        
        sessionContext.updateSessionUser(sessionContext.sessionUser)
        await setSessionContext(sessionContext)
        
        // Encrypt and persist
        let encodedData = try BSONEncoder().encode(sessionContext)
        guard let encryptedConfig = try await self.crypto.encrypt(data: encodedData.makeData(), symmetricKey: getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }
        
        try await cache.updateLocalSessionContext(encryptedConfig)
    }

    fileprivate func rotatePQKemFinalKey() async throws {
        let kyber = try crypto.generateKyber1024PrivateSigningKey()
        
        var sessionContext = try await getSessionContext()
        
        let kyberId = UUID()
        let kyberPrivateKey = try PQKemPrivateKey(id: kyberId, kyber.encode())
        let kyberPublicKey = try PQKemPublicKey(id: kyberId, kyber.publicKey.rawRepresentation)
        
        sessionContext.sessionUser.deviceKeys.finalPQKemPrivateKey = kyberPrivateKey
        
        let signingKeyData = sessionContext.lastUserConfiguration.signingPublicKey
        let signingKey = try Curve25519SigningPublicKey(rawRepresentation: signingKeyData)
        let signingPrivateKeyData = sessionContext.sessionUser.deviceKeys.signingPrivateKey
        let signingPrivateKey = try Curve25519SigningPrivateKey(rawRepresentation: signingPrivateKeyData)
        
        guard let index = sessionContext
            .lastUserConfiguration
            .signedDevices
            .firstIndex(where: { signed in
                guard let verified = try? signed.verified(using: signingKey) else { return false }
                return verified.deviceId == sessionContext.sessionUser.deviceId
            }) else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }
        
        guard var device = try sessionContext.lastUserConfiguration.signedDevices[index]
            .verified(using: signingKey) else {
            throw SessionErrors.invalidSignature
        }
        
        await device.updateFinalPQKemPublicKey(kyberPublicKey)
        let reSigned = try UserConfiguration.SignedDeviceConfiguration(device: device, signingKey: signingPrivateKey)
        sessionContext.lastUserConfiguration.signedDevices[index] = reSigned
        
        try await updateRotatedKeySessionContext(sessionContext: sessionContext)
        
        //Send Public Keys to server
        try await transportDelegate?.publishRotatedKeys(
            for: sessionContext.sessionUser.secretName,
            deviceId: sessionContext.sessionUser.deviceId.uuidString,
            rotated: .init(pskData: device.signingPublicKey, signedDevice: reSigned))
    }
}

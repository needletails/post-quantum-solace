//
//  CryptoSession+KeyRotation.swift
//  post-quantum-solace
//
//  Created by Cole M on 6/20/25.
//
import Foundation
import SessionModels
import BSON
import NeedleTailCrypto
import DoubleRatchetKit

extension CryptoSession {
    
    public func rotateKeysOnPotentialCompromise() async throws {
        await setRotatingKeys(true)
        
        let longTerm = try createLongTermKeys()
        let kyberId = UUID()
        let kyberPrivateKey = try Kyber1024PrivateKeyRepresentable(id: kyberId, longTerm.kyber.encode())
        let kyberPublicKey = try Kyber1024PublicKeyRepresentable(id: kyberId, longTerm.kyber.publicKey.rawRepresentation)
        
        var sessionContext = try await getSessionContext()
        
        let oldSigningKeyData = sessionContext.lastUserConfiguration.publicSigningKey
        let oldSigningKey = try Curve25519SigningPublicKey(rawRepresentation: oldSigningKeyData)
        
        guard let index = sessionContext
            .lastUserConfiguration
            .signedDevices
            .firstIndex(where: { signed in
                guard let verified = try? signed.verified(using: oldSigningKey) else { return false }
                return verified.deviceId == sessionContext.sessionUser.deviceId
            }) else {
            throw CryptoSession.SessionErrors.invalidDeviceIdentity
        }
        guard var device = try sessionContext.lastUserConfiguration.signedDevices[index]
            .verified(using: oldSigningKey) else {
            throw SessionErrors.invalidSignature
        }
        
        await device.updatePublicSigningKey(longTerm.signing.publicKey.rawRepresentation)
        await device.updatePublicLongTermKey(longTerm.curve.publicKey.rawRepresentation)
        await device.updateFinalKyberTermKey(kyberPublicKey)
        
        let reSigned = try UserConfiguration.SignedDeviceConfiguration(device: device, signingKey: longTerm.signing)
        
        sessionContext.sessionUser.deviceKeys.privateSigningKey = longTerm.signing.rawRepresentation
        sessionContext.lastUserConfiguration.publicSigningKey = longTerm.signing.publicKey.rawRepresentation
        sessionContext.sessionUser.deviceKeys.privateLongTermKey = longTerm.curve.rawRepresentation
        sessionContext.sessionUser.deviceKeys.finalKyberPrivateKey = kyberPrivateKey
        sessionContext.lastUserConfiguration.signedDevices[index] = reSigned
        
        try await updateRotatedKeySessionContext(sessionContext: sessionContext)
        
        //Send Public Keys to server
        try await transportDelegate?.rotateLongTermKeys(
            for: sessionContext.sessionUser.secretName,
            deviceId: sessionContext.sessionUser.deviceId.uuidString,
            pskData: device.publicSigningKey,
            signedDevice: reSigned)
    }
    
    func setRotatingKeys(_ rotating: Bool) async {
        rotatingKeys = rotating
    }
}

extension CryptoSession {
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

extension CryptoSession {
    
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
            throw CryptoSession.SessionErrors.sessionEncryptionError
        }
        
        try await cache.updateLocalSessionContext(encryptedConfig)
    }

    fileprivate func rotatePQKemFinalKey() async throws {
        let kyber = try crypto.generateKyber1024PrivateSigningKey()
        
        var sessionContext = try await getSessionContext()
        
        let kyberId = UUID()
        let kyberPrivateKey = try Kyber1024PrivateKeyRepresentable(id: kyberId, kyber.encode())
        let kyberPublicKey = try Kyber1024PublicKeyRepresentable(id: kyberId, kyber.publicKey.rawRepresentation)
        
        sessionContext.sessionUser.deviceKeys.finalKyberPrivateKey = kyberPrivateKey
        
        let signingKeyData = sessionContext.lastUserConfiguration.publicSigningKey
        let signingKey = try Curve25519SigningPublicKey(rawRepresentation: signingKeyData)
        let privateSigningKeyData = sessionContext.sessionUser.deviceKeys.privateSigningKey
        let privateSigningKey = try Curve25519SigningPrivateKey(rawRepresentation: privateSigningKeyData)
        
        guard let index = sessionContext
            .lastUserConfiguration
            .signedDevices
            .firstIndex(where: { signed in
                guard let verified = try? signed.verified(using: signingKey) else { return false }
                return verified.deviceId == sessionContext.sessionUser.deviceId
            }) else {
            throw CryptoSession.SessionErrors.invalidDeviceIdentity
        }
        
        guard var device = try sessionContext.lastUserConfiguration.signedDevices[index]
            .verified(using: signingKey) else {
            throw SessionErrors.invalidSignature
        }
        
        await device.updateFinalKyberTermKey(kyberPublicKey)
        let reSigned = try UserConfiguration.SignedDeviceConfiguration(device: device, signingKey: privateSigningKey)
        sessionContext.lastUserConfiguration.signedDevices[index] = reSigned
        
        try await updateRotatedKeySessionContext(sessionContext: sessionContext)
        
        //Send Public Keys to server
        try await transportDelegate?.rotateLongTermKeys(
            for: sessionContext.sessionUser.secretName,
            deviceId: sessionContext.sessionUser.deviceId.uuidString,
            pskData: device.publicSigningKey,
            signedDevice: reSigned)
    }
}

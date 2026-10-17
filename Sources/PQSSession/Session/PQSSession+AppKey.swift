//
//  PQSSession+AppKey.swift
//  post-quantum-solace
//
//  The app-password key protects the encrypted session context (every private
//  key of the device). Generation 2 derives it with PBKDF2-HMAC-SHA512 over the
//  device salt; generation 1 (`deriveStrictSymmetricKey`) was a salt-less HKDF.
//  Blobs stay raw AES-GCM: an existing generation-1 blob opens on its first
//  unlock and is re-sealed under generation 2. Hosts that seal the blob
//  themselves with `getAppSymmetricKey()` therefore keep working unchanged.
//

import BinaryCodable
import Crypto
import Foundation
import NeedleTailCrypto
import SessionModels

extension PQSSessionConstants {
    /// PBKDF2 iteration count for the app-password key. Debug builds (the test
    /// suite unlocks hundreds of sessions) use a small count; release builds pay
    /// the full work factor once per unlock thanks to the in-session key cache.
    #if DEBUG
    package static let appPasswordKDFIterations = 2_048
    #else
    package static let appPasswordKDFIterations = 210_000
    #endif
}

extension PQSSession {
    /// Generation-2 key for (password, salt), cached so routine commits do not
    /// repeat the work factor.
    func deriveAppSymmetricKey(passwordData: Data, salt: Data) -> SymmetricKey {
        if let cached = appSymmetricKeyCache,
           cached.password == passwordData,
           cached.salt == salt {
            return cached.key
        }
        let key = crypto.derivePasswordSymmetricKey(
            password: passwordData,
            salt: salt,
            iterations: PQSSessionConstants.appPasswordKDFIterations)
        appSymmetricKeyCache = (passwordData, salt, key)
        return key
    }

    /// Generation-1 key (salt-less HKDF), accepted only to open blobs written
    /// before generation 2 so they can be re-sealed.
    func legacyAppSymmetricKey(passwordData: Data, salt: Data) async -> SymmetricKey {
        await crypto.deriveStrictSymmetricKey(data: passwordData, salt: salt)
    }

    /// Opens a session-context blob with the current key, falling back to the
    /// legacy key. Returns whether the blob still needs re-sealing.
    func openSessionContextBlob(
        _ data: Data,
        passwordData: Data,
        salt: Data
    ) async throws -> (context: SessionContext, needsRekey: Bool) {
        let current = deriveAppSymmetricKey(passwordData: passwordData, salt: salt)
        if let plaintext = try? crypto.decrypt(data: data, symmetricKey: current) {
            return (try BinaryDecoder().decode(SessionContext.self, from: plaintext), false)
        }
        let legacy = await legacyAppSymmetricKey(passwordData: passwordData, salt: salt)
        guard let plaintext = try crypto.decrypt(data: data, symmetricKey: legacy) else {
            throw PQSError.sessionDecryptionError
        }
        return (try BinaryDecoder().decode(SessionContext.self, from: plaintext), true)
    }

    /// Decrypted bytes of a blob, current key first, then legacy.
    func openSessionContextPlaintext(_ data: Data) async throws -> Data {
        guard let cache else { throw PQSError.databaseNotInitialized }
        guard let passwordData = _appPassword.data(using: .utf8) else {
            throw PQSError.invalidPassword
        }
        let salt = try await cache.fetchLocalDeviceSalt(keyData: passwordData)
        let current = deriveAppSymmetricKey(passwordData: passwordData, salt: salt)
        if let plaintext = try? crypto.decrypt(data: data, symmetricKey: current) {
            return plaintext
        }
        let legacy = await legacyAppSymmetricKey(passwordData: passwordData, salt: salt)
        guard let plaintext = try crypto.decrypt(data: data, symmetricKey: legacy) else {
            throw PQSError.sessionDecryptionError
        }
        return plaintext
    }

    /// Decrypted bytes of the persisted blob (see `openSessionContextPlaintext`).
    func openPersistedSessionContextPlaintext() async throws -> Data {
        guard let cache else { throw PQSError.databaseNotInitialized }
        return try await openSessionContextPlaintext(cache.fetchLocalSessionContext())
    }

    /// Opens the persisted blob with the live password (current key, then legacy).
    func openPersistedSessionContext() async throws -> SessionContext {
        guard let cache else { throw PQSError.databaseNotInitialized }
        guard let passwordData = _appPassword.data(using: .utf8) else {
            throw PQSError.invalidPassword
        }
        let data = try await cache.fetchLocalSessionContext()
        let salt = try await cache.fetchLocalDeviceSalt(keyData: passwordData)
        return try await openSessionContextBlob(data, passwordData: passwordData, salt: salt).context
    }
}

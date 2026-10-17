//
//  PQSSession+AppKey.swift
//  post-quantum-solace
//
//  The app-password key protects the encrypted session context (every private
//  key of the device). It is derived with PBKDF2-HMAC-SHA512 over the device
//  salt. Blobs are raw AES-GCM, so hosts that seal the blob themselves with
//  `getAppSymmetricKey()` keep working unchanged.
//

import BinaryCodable
import Crypto
import Foundation
import NeedleTailCrypto
import SessionModels

extension PQSSessionConstants {
    /// PBKDF2 iteration count for the app-password key, identical in every build
    /// configuration: the blob does not record it, so a count that differs between
    /// Debug and Release makes data sealed by one unreadable by the other.
    package static let appPasswordKDFIterations = 210_000
}

/// Test-only work-factor override. `package` scope: hosts cannot set it.
package enum AppPasswordKDFTestOverride {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var value: Int?

    package static var iterations: Int? {
        get { lock.withLock { value } }
        set { lock.withLock { value = newValue } }
    }
}

extension PQSSession {
    /// App key for (password, salt), cached so routine commits do not repeat
    /// the work factor. `remember: false` derives without replacing the cache,
    /// so a rejected guess does not evict the real password's key.
    func deriveAppSymmetricKey(
        passwordData: Data,
        salt: Data,
        remember: Bool = true
    ) -> SymmetricKey {
        if let cached = appSymmetricKeyCache,
           cached.password == passwordData,
           cached.salt == salt {
            return cached.key
        }
        let key = crypto.derivePasswordSymmetricKey(
            password: passwordData,
            salt: salt,
            iterations: AppPasswordKDFTestOverride.iterations ?? PQSSessionConstants.appPasswordKDFIterations)
        if remember {
            appSymmetricKeyCache = (passwordData, salt, key)
        }
        return key
    }

    /// Caches a key derived with `remember: false` once it has proven correct,
    /// so success does not pay the work factor twice.
    func rememberAppSymmetricKey(passwordData: Data, salt: Data, key: SymmetricKey) {
        appSymmetricKeyCache = (passwordData, salt, key)
    }

    /// Kept for source compatibility only. There is no legacy key left to migrate
    /// from, so this is ``verifyAppPassword(_:)``.
    @available(*, deprecated, renamed: "verifyAppPassword(_:)", message: "No legacy app key remains; call verifyAppPassword(_:).")
    public func migrateLegacyAppPasswordKey(_ appPassword: String) async -> Bool {
        await verifyAppPassword(appPassword)
    }

    /// Opens a session-context blob with the app key for (password, salt).
    func openSessionContextBlob(
        _ data: Data,
        passwordData: Data,
        salt: Data
    ) throws -> SessionContext {
        let key = deriveAppSymmetricKey(passwordData: passwordData, salt: salt)
        guard let plaintext = try crypto.decrypt(data: data, symmetricKey: key) else {
            throw PQSError.sessionDecryptionError
        }
        return try BinaryDecoder().decode(SessionContext.self, from: plaintext)
    }

    /// Decrypted bytes of a blob under the live password's app key.
    func openSessionContextPlaintext(_ data: Data) async throws -> Data {
        guard let cache else { throw PQSError.databaseNotInitialized }
        guard let passwordData = _appPassword.data(using: .utf8) else {
            throw PQSError.invalidPassword
        }
        let salt = try await cache.fetchLocalDeviceSalt(keyData: passwordData)
        let key = deriveAppSymmetricKey(passwordData: passwordData, salt: salt)
        guard let plaintext = try crypto.decrypt(data: data, symmetricKey: key) else {
            throw PQSError.sessionDecryptionError
        }
        return plaintext
    }

    /// Decrypted bytes of the persisted blob (see `openSessionContextPlaintext`).
    func openPersistedSessionContextPlaintext() async throws -> Data {
        guard let cache else { throw PQSError.databaseNotInitialized }
        return try await openSessionContextPlaintext(cache.fetchLocalSessionContext())
    }

    /// Opens the persisted blob with the live password.
    func openPersistedSessionContext() async throws -> SessionContext {
        try await BinaryDecoder().decode(SessionContext.self, from: openPersistedSessionContextPlaintext())
    }
}

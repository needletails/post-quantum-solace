//
//  PQSSession+ExternalWrites.swift
//  post-quantum-solace
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  A second process (an iOS notification service extension) may write the same store while
//  this one is suspended: new session identities, advanced ratchet state, contacts and
//  communications. The in-memory `SessionCache` would then be stale, and decrypting with a
//  stale ratchet state breaks the chain. The host calls this before the session next uses the
//  store after such a write.
//

import Foundation

extension PQSSession {
    /// Reloads the in-memory cache from the persistent store. No-op before the cache exists.
    /// - Throws: An error if any fetch operation from the store fails.
    public func refreshSessionCache() async throws {
        try await cache?.refreshCache()
    }
}

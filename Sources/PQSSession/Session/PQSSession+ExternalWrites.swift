//
//  PQSSession+ExternalWrites.swift
//  post-quantum-solace
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  A second process (an iOS notification service extension) may write the same store while
//  this one is suspended: new session identities, advanced ratchet state, contacts and
//  communications. The in-memory `SessionCache` and the ratchet manager's per-lane snapshots
//  would then be stale, and encrypting or decrypting with a stale ratchet state breaks the
//  chain. The host calls this before the session next uses the store after such a write.
//

import Foundation

extension PQSSession {
    /// Reloads the in-memory caches from the persistent store. No-op before the cache exists.
    /// - Throws: An error if any fetch operation from the store fails.
    public func refreshSessionCache() async throws {
        guard let cache else { return }
        try await cache.refreshCache()
        // The ratchet manager keeps its own snapshot per lane. Left in place, its cached
        // branch encrypts from the stale state and writes that back over the other
        // process's advance (dogfood 2026-10-24..27: the master's first frame after each
        // launch failed on its linked device while the extension's frames decrypted).
        for identity in try await cache.fetchSessionIdentities() {
            await messagePipeline.ratchetManager.discardCachedLane(identity.id)
        }
    }
}

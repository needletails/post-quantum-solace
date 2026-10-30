//
//  PQSSession+ExternalWrites.swift
//  post-quantum-solace
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  A second process (an iOS notification service extension) may write the same store while
//  this one is suspended: new session identities, advanced ratchet state, contacts and
//  communications, and the session context itself (a one-time key consumed and its
//  replacement minted, host state recorded). The in-memory `SessionCache`, the ratchet
//  manager's per-lane snapshots and the live `sessionContext` would then be stale:
//  encrypting or decrypting with a stale ratchet state breaks the chain, and a stale
//  context's next commit writes the other process's keys back out of existence while the
//  server still advertises them. The host calls this before the session next uses the
//  store after such a write.
//

import Foundation

extension PQSSession {
    /// Reloads the in-memory caches and the live session context from the persistent
    /// store. No-op before the cache exists.
    /// - Throws: An error if any fetch operation from the store fails.
    public func refreshSessionCache() async throws {
        guard let cache else { return }
        try await cache.refreshCache()
        // The context follows the store too, under the commit lock so no commit of this
        // process lands between the read and the re-install (dogfood 2026-10-28: the
        // iPhones' app processes failed `missingOneTimeKey` on peer lanes minted against
        // keys their extension had published).
        if _sessionContext != nil {
            try await withExclusiveSessionContextCommit {
                let persisted = try await cache.reloadLocalSessionContext()
                guard !persisted.isEmpty else { return }
                try await synchronizeLocalConfiguration(persisted)
            }
        }
        // The ratchet manager keeps its own snapshot per lane. Left in place, its cached
        // branch encrypts from the stale state and writes that back over the other
        // process's advance (dogfood 2026-10-24..27: the master's first frame after each
        // launch failed on its linked device while the extension's frames decrypted).
        for identity in try await cache.fetchSessionIdentities() {
            await messagePipeline.ratchetManager.discardCachedLane(identity.id)
        }
    }
}

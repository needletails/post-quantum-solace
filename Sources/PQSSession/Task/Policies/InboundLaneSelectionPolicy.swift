//
//  InboundLaneSelectionPolicy.swift
//  post-quantum-solace
//
//  Cost gates for inbound try-all lane selection. Dogfood 2026-10-21: 92
//  undecryptable frames from one peer each walked ~10 lanes (preferred +
//  archived ×8) inside two minutes. AEAD already rejects wrong lanes, so
//  accuracy is fine; these helpers cut the per-frame cost without changing
//  which lane wins:
//
//  - header-match ordering *within* a tier (preferred, stateful actives,
//    state-less actives, archives), so the common case decrypts on attempt one
//    or two;
//  - a bounded negative cache keyed by (lane id, frame fingerprint) and gated
//    on the lane's row bytes, so a redelivered copy of the same ciphertext skips
//    lanes that already rejected it under the same ratchet state;
//  - a restore gate so a failed attempt only writes the row back when the
//    attempt actually mutated it.
//

import Crypto
import DoubleRatchetKit
import Foundation

/// Pure helpers for ordering inbound decrypt candidates and gating rollbacks.
enum InboundLaneSelectionPolicy: Sendable {
    /// Cheap comparison of a lane's stored remote keys against the frame header.
    struct HeaderMatch: Sendable, Equatable {
        let longTermKeyMatches: Bool
        let oneTimeKeyIdMatches: Bool
        let mlKEMKeyIdMatches: Bool

        /// Long-term key dominates: it identifies the peer epoch. One-time and
        /// ML-KEM ids only break ties within that epoch.
        var rank: Int {
            (longTermKeyMatches ? 4 : 0) + (oneTimeKeyIdMatches ? 2 : 0) + (mlKEMKeyIdMatches ? 1 : 0)
        }
    }

    /// Compares a lane's stored remote key material against the frame header.
    /// Optional ids compare as optionals: `nil == nil` is a match, mirroring
    /// the blank-for-header dedupe.
    static func headerMatch(
        laneLongTermPublicKey: Data,
        laneOneTimeKeyId: UUID?,
        laneMLKEMKeyId: UUID?,
        headerLongTermPublicKey: Data,
        headerOneTimeKeyId: UUID?,
        headerMLKEMKeyId: UUID?
    ) -> HeaderMatch {
        HeaderMatch(
            longTermKeyMatches: laneLongTermPublicKey == headerLongTermPublicKey,
            oneTimeKeyIdMatches: laneOneTimeKeyId == headerOneTimeKeyId,
            mlKEMKeyIdMatches: laneMLKEMKeyId == headerMLKEMKeyId)
    }

    /// Stable partition: higher rank first, original order preserved among
    /// equal ranks. Callers apply this *within* a tier only, never across the
    /// preferred → stateful → state-less → archived precedence.
    static func orderedByHeaderMatch<T>(_ candidates: [T], rank: (T) -> Int) -> [T] {
        candidates
            .enumerated()
            .map { (index: $0.offset, rank: rank($0.element), element: $0.element) }
            .sorted { lhs, rhs in
                if lhs.rank != rhs.rank { return lhs.rank > rhs.rank }
                return lhs.index < rhs.index
            }
            .map(\.element)
    }

    /// A failed attempt that left the row bytes untouched has nothing to roll
    /// back in the store; only the ratchet manager's in-memory lane is evicted.
    static func shouldRestoreIdentityData(before: Data, after: Data) -> Bool {
        before != after
    }

    /// Whether a state-less row that just bootstrapped from a frame's header may
    /// become the lane. A header carries PQXDH material until the sender has
    /// processed a reply, so a blank can decrypt any frame of that initial
    /// chain, including one whose session this device already holds (a replay,
    /// or a row the sender's epoch outran). Adopting it then splits the lane.
    /// A blank opens a lane with a session's first frame (received count 1), or
    /// when no stateful row for the device exists to be split.
    static func blankMayBecomeLane(receivedMessagesCount: Int, statefulRowExists: Bool) -> Bool {
        !statefulRowExists || receivedMessagesCount == 1
    }

    /// What decides whether a frame can decrypt on a lane: whether a ratchet
    /// snapshot exists, how far its receiving side advanced, and the local and
    /// remote key material PQXDH would use. Row bytes are not usable here: a
    /// directory refresh re-encrypts the row under a fresh nonce without
    /// touching the ratchet. Sends do not move the receiving chain.
    static func ratchetStateToken(for props: SessionIdentity.UnwrappedProps) -> Data {
        let fields: [String] = [
            props.hasRatchetState ? "1" : "0",
            String(props.ratchetReceivedMessagesCount),
            props.ratchetOneTimePrivateKey?.id.uuidString ?? "-",
            props.ratchetMLKEMPrivateKey?.id.uuidString ?? "-",
            props.longTermPublicKey.base64EncodedString(),
            props.oneTimePublicKey?.id.uuidString ?? "-",
            props.mlKEMPublicKey.id.uuidString,
        ]
        return Data(fields.joined(separator: "|").utf8)
    }
}

/// Bounded negative cache: `(lane id, frame fingerprint)` → failure recorded
/// under a digest of the lane's ratchet-state token at attempt time.
///
/// A lookup hits only when the lane's current token still digests to the
/// recorded value, so any receiving-side change on that lane (successful
/// decrypt, responder init, key refresh) expires its entries without a hook.
/// `invalidate(laneId:)` drops a healed lane's entries eagerly. FIFO eviction
/// keeps the table at `maxEntries`.
struct InboundNegativeDecryptCache: Sendable {
    private struct Key: Hashable, Sendable {
        let laneId: UUID
        let fingerprint: Data
    }

    private struct Entry: Sendable {
        let laneStateDigest: Data
        let failure: any Error
    }

    private var entries: [Key: Entry] = [:]
    private var insertionOrder: [Key] = []
    let maxEntries: Int

    init(maxEntries: Int) {
        self.maxEntries = max(1, maxEntries)
    }

    var count: Int { entries.count }

    mutating func recordFailure(
        laneId: UUID,
        fingerprint: Data,
        laneState: Data,
        error: any Error
    ) {
        let key = Key(laneId: laneId, fingerprint: fingerprint)
        let entry = Entry(laneStateDigest: Self.digest(laneState), failure: error)
        if entries.updateValue(entry, forKey: key) == nil {
            insertionOrder.append(key)
            while entries.count > maxEntries, !insertionOrder.isEmpty {
                let evicted = insertionOrder.removeFirst()
                entries.removeValue(forKey: evicted)
            }
        }
    }

    func cachedFailure(laneId: UUID, fingerprint: Data, laneState: Data) -> (any Error)? {
        guard let entry = entries[Key(laneId: laneId, fingerprint: fingerprint)] else {
            return nil
        }
        guard entry.laneStateDigest == Self.digest(laneState) else {
            return nil
        }
        return entry.failure
    }

    mutating func invalidate(laneId: UUID) {
        let stale = insertionOrder.filter { $0.laneId == laneId }
        guard !stale.isEmpty else { return }
        for key in stale {
            entries.removeValue(forKey: key)
        }
        insertionOrder.removeAll { $0.laneId == laneId }
    }

    private static func digest(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}

/// A peer row with its props decrypted once for the frame, plus the cheap
/// header comparison every tier orders by.
struct InboundLane: Sendable {
    let identity: SessionIdentity
    let props: SessionIdentity.UnwrappedProps
    let headerMatch: InboundLaneSelectionPolicy.HeaderMatch

    init(identity: SessionIdentity, props: SessionIdentity.UnwrappedProps, header: EncryptedHeader) {
        self.identity = identity
        self.props = props
        headerMatch = InboundLaneSelectionPolicy.headerMatch(
            laneLongTermPublicKey: props.longTermPublicKey,
            laneOneTimeKeyId: props.oneTimePublicKey?.id,
            laneMLKEMKeyId: props.mlKEMPublicKey.id,
            headerLongTermPublicKey: header.remoteLongTermPublicKey,
            headerOneTimeKeyId: header.remoteOneTimePublicKey?.id,
            headerMLKEMKeyId: header.remoteMLKEMPublicKey.id)
    }

    var isArchived: Bool {
        props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
    }

    var hasRatchetState: Bool { props.hasRatchetState }

    /// Blank-for-header dedupe key: remote LTK + OTK id.
    var matchesHeaderKeys: Bool {
        headerMatch.longTermKeyMatches && headerMatch.oneTimeKeyIdMatches
    }

    /// Negative-cache gate for this lane (see `ratchetStateToken(for:)`).
    var ratchetStateToken: Data {
        InboundLaneSelectionPolicy.ratchetStateToken(for: props)
    }
}

/// Per-frame accounting for inbound lane selection. Test seam and audit input;
/// never drives behaviour.
struct InboundLaneSelectionStats: Sendable {
    enum Pass: String, Sendable {
        case activeFirst
        case archived
    }

    enum AttemptOutcome: String, Sendable {
        case decrypted
        case failed
        case skippedNegativeCache
    }

    struct Attempt: Sendable {
        let laneId: UUID
        let kind: String
        let outcome: AttemptOutcome
        /// Failure description for `.failed` / `.skippedNegativeCache`.
        var failure: String? = nil
    }

    let sharedId: String
    var pass: Pass
    let fingerprint: Data
    /// Rows read from the identity store for this frame.
    var identityRowsScanned = 0
    /// `props(symmetricKey:)` calls made by lane selection for this frame.
    var propsDecrypts = 0
    var attempts: [Attempt] = []
    /// Row restores that reached the store after a failed attempt.
    var restoreStoreWrites = 0
    /// Failed attempts whose row bytes were unchanged, so no store write ran.
    var restoresSkippedUnchanged = 0
    var winningLaneId: UUID?

    init(sharedId: String, pass: Pass, fingerprint: Data) {
        self.sharedId = sharedId
        self.pass = pass
        self.fingerprint = fingerprint
    }

    var decryptAttempts: Int {
        attempts.filter { $0.outcome != .skippedNegativeCache }.count
    }

    var negativeCacheSkips: Int {
        attempts.filter { $0.outcome == .skippedNegativeCache }.count
    }

    var attemptedLaneIds: [UUID] {
        attempts.filter { $0.outcome != .skippedNegativeCache }.map(\.laneId)
    }

    var skippedLaneIds: [UUID] {
        attempts.filter { $0.outcome == .skippedNegativeCache }.map(\.laneId)
    }

    var candidateOrder: [String] {
        attempts.map { "\($0.kind):\($0.laneId.uuidString.prefix(8))" + ($0.failure.map { " ✗ \($0)" } ?? "") }
    }
}

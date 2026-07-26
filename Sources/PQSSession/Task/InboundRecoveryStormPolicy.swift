//
//  InboundRecoveryStormPolicy.swift
//  post-quantum-solace
//
//  Event-driven gates that stop dogfood recovery storms (CHILD_DEVICE_2):
//  same sharedId archive-deferred thousands of times.
//
//  Exhaustion is per ciphertext fingerprint: reminted orphan material keeps the
//  same sharedId but changes the signed payload — that must re-arm one archive
//  pass (Active→Archives contract) without reopening same-fp spool storms.
//

import Foundation

/// Recovery storm gates: one archive fallback per ciphertext until a heal event
/// or a new inbound fingerprint clears exhaustion.
public enum InboundRecoveryStormPolicy: Sendable {
    /// Whether to enqueue a `.background` archive try-all for this sharedId.
    public static func shouldDeferArchivedFallback(
        sharedId: String,
        exhausted: Set<String>,
        pendingPass: Set<String>
    ) -> Bool {
        !exhausted.contains(sharedId) && !pendingPass.contains(sharedId)
    }

    /// After one completed archive pass (success or total failure), further
    /// redeliveries of the *same* ciphertext must not re-walk archives until a
    /// heal event or a new fingerprint clears exhaustion.
    public static func exhaustedAfterArchivePassCompleted(
        current: Set<String>,
        sharedId: String
    ) -> Set<String> {
        var next = current
        next.insert(sharedId)
        return next
    }

    /// Reminted / new orphan material: same sharedId, different signed payload.
    /// Clear exhaustion so Active→Archives can run once for the new frame.
    public static func shouldClearExhaustionForNewFingerprint(
        sharedId: String,
        exhausted: Set<String>,
        exhaustedFingerprint: Data?,
        currentFingerprint: Data
    ) -> Bool {
        guard exhausted.contains(sharedId) else { return false }
        guard let exhaustedFingerprint else {
            // Exhausted without a recorded fingerprint (legacy / peer clear race):
            // treat unknown prior frame as stale so remint can re-arm once.
            return true
        }
        return exhaustedFingerprint != currentFingerprint
    }
}

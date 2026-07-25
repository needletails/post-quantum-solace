//
//  InboundRecoveryStormPolicy.swift
//  post-quantum-solace
//
//  Event-driven gates that stop dogfood recovery storms (CHILD_DEVICE_2):
//  same sharedId archive-deferred thousands of times.
//

import Foundation

/// Recovery storm gates: one archive fallback per ciphertext until a heal event
/// clears exhaustion.
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
    /// redeliveries must not re-walk archives until a heal event clears exhaustion.
    public static func exhaustedAfterArchivePassCompleted(
        current: Set<String>,
        sharedId: String
    ) -> Set<String> {
        var next = current
        next.insert(sharedId)
        return next
    }
}

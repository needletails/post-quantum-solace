//
//  OrphanReplayRearmPolicy.swift
//  post-quantum-solace
//
//  Receiver rearm gate. After a transport-confirmed NACK, stay in
//  resendAwaitingSender until inbound proves *new* sender orphan material (different
//  ciphertext fingerprint). Same-frame backlog redelivery must not burn
//  peerResendRequestMaxSubmissions.
//

import Foundation

/// Pure policy for whether a failed orphan replay may re-arm a bounded NACK.
public enum OrphanReplayRearmPolicy: Sendable {
    /// - Parameters:
    ///   - priorFingerprint: fingerprint stored when the last NACK was transport-confirmed.
    ///   - currentFingerprint: fingerprint of the undecryptable frame being handled now.
    ///   - attempts: transport-confirmed NACK submissions for this sharedId.
    ///   - maxSubmissions: hard cap (`peerResendRequestMaxSubmissions`).
    /// - Returns: `true` only when material changed and attempts remain under the cap.
    public static func shouldRearm(
        priorFingerprint: Data?,
        currentFingerprint: Data,
        attempts: Int,
        maxSubmissions: Int = PQSSessionConstants.peerResendRequestMaxSubmissions
    ) -> Bool {
        guard attempts > 0, attempts < maxSubmissions else {
            return false
        }
        guard let priorFingerprint else {
            // First post-NACK undecryptable with no stored fingerprint: treat as
            // unknown material and allow one rearm (lost-fingerprint safety).
            return true
        }
        return priorFingerprint != currentFingerprint
    }
}

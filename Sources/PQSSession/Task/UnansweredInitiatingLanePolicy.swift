//
//  UnansweredInitiatingLanePolicy.swift
//  post-quantum-solace
//
//  Local missingOneTimeKey toward a same-account sibling is bilateral control
//  deadlock when the outbound lane is already "answered": unanswered remint
//  no-ops, peerRefresh rides the poison pin, and the sibling's body-fail NACKs
//  never decrypt. Force remint only for that episode trigger + same account.
//

import Foundation

public enum UnansweredInitiatingLanePolicy: Sendable {
    /// When true, `resetUnansweredInitiatingLane` remints even if the peer has
    /// already decrypted on this lane (`receivedMessagesCount > 0`).
    public static func shouldForceRemintEvenIfAnswered(
        isSameAccount: Bool,
        trigger: String
    ) -> Bool {
        isSameAccount && trigger == "missingOneTimeKeyEpisode"
    }
}

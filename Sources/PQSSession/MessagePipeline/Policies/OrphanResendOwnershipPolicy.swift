//
//  OrphanResendOwnershipPolicy.swift
//  post-quantum-solace
//
//  Only the device that owns MessageRecord / plaintext may service orphan-resend.
//  Same-account NACKs can be observed by siblings; non-owners must defer without
//  markResendUnavailable or remint.
//

import Foundation

/// Pure policy for whether this device may service a `requestMessageResend` id.
public enum OrphanResendOwnershipPolicy: Sendable {
    public enum Decision: Sendable, Equatable {
        /// Proceed with orphan remint / retransport / replay.
        case serviceAsContentOwner
        /// Same-account non-owner: skip without markUnavailable or remint.
        case deferNotContentOwner
        /// Cross-account (or unknown): continue normal lookup / unavailable path.
        case continueCrossAccountLookup
    }

    /// - Parameters:
    ///   - isSameAccount: requester secretName equals local account.
    ///   - hasRecentOutboundReplay: in-memory recent control replay source.
    ///   - hasLocalMessage: persisted local message for the sharedId.
    ///   - hasOutboundDeviceSendRecord: MessageRecord for (sharedId, requesterDevice).
    public static func decision(
        isSameAccount: Bool,
        hasRecentOutboundReplay: Bool,
        hasLocalMessage: Bool,
        hasOutboundDeviceSendRecord: Bool
    ) -> Decision {
        let isOwner =
            hasRecentOutboundReplay
            || hasLocalMessage
            || hasOutboundDeviceSendRecord
        if isOwner {
            return .serviceAsContentOwner
        }
        if isSameAccount {
            return .deferNotContentOwner
        }
        return .continueCrossAccountLookup
    }
}

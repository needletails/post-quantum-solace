//
//  PriorLaneRetirement.swift
//  post-quantum-solace
//
//  Which active rows a lane reset archives. A lane the peer has answered leaves the
//  active set only when a sibling decrypts a frame from that device, or when a replay
//  on that exact row was NACKed. Other NACKs, prove-fails and mints change outbound
//  choice only (dogfood 2026-10-28: a mint archived 9900FA06 mid-burst).
//

import DoubleRatchetKit
import Foundation
import SessionModels

/// Pure policy for the rows a fresh mint replaces.
enum PriorLaneRetirement: Sendable {
    /// Every active row: friendship, rotation, outbound repair, the same-account force.
    case all
    /// Rows the peer has not answered, or whose keys the device no longer advertises.
    case unanswered
    /// No row: surgical control insert.
    case none

    func retires(
        _ props: SessionIdentity.UnwrappedProps,
        currentDevice device: UserDeviceConfiguration
    ) -> Bool {
        switch self {
        case .all:
            true
        case .unanswered:
            props.ratchetReceivedMessagesCount == 0
                || props.longTermPublicKey != device.longTermPublicKey
                || props.signingPublicKey != device.signingPublicKey
        case .none:
            false
        }
    }
}

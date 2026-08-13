//
//  BroadcastRecipientDiscovery.swift
//  post-quantum-solace
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//

import Crypto
import DoubleRatchetKit
import Foundation
import SessionModels

/// Collects distinct peer `secretName`s for broadcast fan-out from local session identities and contacts.
enum BroadcastRecipientDiscovery: Sendable {
    /// Union of peers derived from ratchet identity rows and address-book contacts, excluding `sender`.
    static func collectPeerSecretNames(
        sender: String,
        sessionIdentities: [SessionIdentity],
        contacts: [ContactModel],
        symmetricKey: SymmetricKey
    ) async -> Set<String> {
        var peerNames = Set<String>()

        for identity in sessionIdentities {
            guard let props = await identity.props(symmetricKey: symmetricKey) else { continue }
            guard props.secretName != sender else { continue }
            peerNames.insert(props.secretName)
        }

        for contact in contacts {
            guard let props = await contact.props(symmetricKey: symmetricKey) else { continue }
            guard props.secretName != sender else { continue }
            peerNames.insert(props.secretName)
        }

        return peerNames
    }

    /// Groups session identities by peer `secretName` for broadcast fan-out (one encrypt pass per peer bucket).
    static func groupIdentitiesByPeerSecretName(
        _ identities: [SessionIdentity],
        symmetricKey: SymmetricKey
    ) async -> [String: [SessionIdentity]] {
        var map: [String: [SessionIdentity]] = [:]
        for identity in identities {
            guard let name = await identity.props(symmetricKey: symmetricKey)?.secretName else { continue }
            map[name, default: []].append(identity)
        }
        return map
    }
}

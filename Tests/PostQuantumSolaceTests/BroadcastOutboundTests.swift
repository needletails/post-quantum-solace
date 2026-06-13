//
//  BroadcastOutboundTests.swift
//  post-quantum-solace
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//

import Crypto
import DoubleRatchetKit
import Foundation
@testable import PQSSession
import SessionModels
import Testing

@Suite("Broadcast recipient discovery")
struct BroadcastOutboundTests {

    private let symmetricKey = SymmetricKey(size: .bits256)

    private func identity(secretName: String, deviceId: UUID = UUID()) throws -> SessionIdentity {
        try SessionIdentity(
            id: UUID(),
            props: .init(
                secretName: secretName,
                deviceId: deviceId,
                sessionContextId: 0,
                longTermPublicKey: .init(),
                signingPublicKey: .init(),
                mlKEMPublicKey: .init(.init(count: 1568)),
                oneTimePublicKey: nil,
                deviceName: "\(secretName)-device",
                isMasterDevice: true
            ),
            symmetricKey: symmetricKey
        )
    }

    private func contact(secretName: String) throws -> ContactModel {
        try ContactModel(
            id: UUID(),
            props: .init(
                secretName: secretName,
                configuration: .init(
                    signingPublicKey: Data(),
                    signedDevices: [],
                    signedOneTimePublicKeys: [],
                    signedMLKEMOneTimePublicKeys: []
                ),
                metadata: [:]
            ),
            symmetricKey: symmetricKey
        )
    }

    @Test("collectPeerSecretNames excludes sender and gathers identity peers")
    func identityPeersExcludeSender() async throws {
        let sender = "self_user"
        let bob = try identity(secretName: "bob")
        let selfId = try identity(secretName: sender)
        let names = await BroadcastRecipientDiscovery.collectPeerSecretNames(
            sender: sender,
            sessionIdentities: [bob, selfId],
            contacts: [],
            symmetricKey: symmetricKey
        )
        #expect(names == Set(["bob"]))
    }

    @Test("collectPeerSecretNames unions contacts with no duplicate secret names")
    func unionContactsAndIdentities() async throws {
        let sender = "alice"
        let bobIdentity = try identity(secretName: "bob")
        let bobContact = try contact(secretName: "bob")
        let carolContact = try contact(secretName: "carol")
        let names = await BroadcastRecipientDiscovery.collectPeerSecretNames(
            sender: sender,
            sessionIdentities: [bobIdentity],
            contacts: [bobContact, carolContact],
            symmetricKey: symmetricKey
        )
        #expect(names.count == 2)
        #expect(names.contains("bob"))
        #expect(names.contains("carol"))
    }

    @Test("collectPeerSecretNames skips contacts and identities with nil props")
    func skipsUndecryptableEntries() async throws {
        let sender = "alice"
        let bob = try identity(secretName: "bob")
        let contactWrongKey = try ContactModel(
            id: UUID(),
            props: .init(
                secretName: "ghost",
                configuration: .init(
                    signingPublicKey: Data(),
                    signedDevices: [],
                    signedOneTimePublicKeys: [],
                    signedMLKEMOneTimePublicKeys: []
                ),
                metadata: [:]
            ),
            symmetricKey: SymmetricKey(size: .bits256)
        )
        let names = await BroadcastRecipientDiscovery.collectPeerSecretNames(
            sender: sender,
            sessionIdentities: [bob],
            contacts: [contactWrongKey],
            symmetricKey: symmetricKey
        )
        #expect(names == Set(["bob"]))
    }

    @Test("collectPeerSecretNames returns empty when only sender is present")
    func emptyWhenNoPeers() async throws {
        let sender = "only_me"
        let selfId = try identity(secretName: sender)
        let names = await BroadcastRecipientDiscovery.collectPeerSecretNames(
            sender: sender,
            sessionIdentities: [selfId],
            contacts: [],
            symmetricKey: symmetricKey
        )
        #expect(names.isEmpty)
    }

    @Test("groupIdentitiesByPeerSecretName buckets multiple devices per peer")
    func groupIdentitiesByPeer() async throws {
        let bobA = try identity(secretName: "bob", deviceId: UUID())
        let bobB = try identity(secretName: "bob", deviceId: UUID())
        let carol = try identity(secretName: "carol", deviceId: UUID())
        let grouped = await BroadcastRecipientDiscovery.groupIdentitiesByPeerSecretName(
            [bobA, bobB, carol],
            symmetricKey: symmetricKey
        )
        #expect(grouped["bob"]?.count == 2)
        #expect(grouped["carol"]?.count == 1)
        #expect(grouped.count == 2)
    }

    @Test("groupIdentitiesByPeerSecretName drops identities with nil props")
    func groupIdentitiesSkipsNilProps() async throws {
        let bob = try identity(secretName: "bob")
        let wrongKey = try SessionIdentity(
            id: UUID(),
            props: .init(
                secretName: "ghost",
                deviceId: UUID(),
                sessionContextId: 0,
                longTermPublicKey: .init(),
                signingPublicKey: .init(),
                mlKEMPublicKey: .init(.init(count: 1568)),
                oneTimePublicKey: nil,
                deviceName: "x",
                isMasterDevice: true
            ),
            symmetricKey: SymmetricKey(size: .bits256)
        )
        let grouped = await BroadcastRecipientDiscovery.groupIdentitiesByPeerSecretName(
            [bob, wrongKey],
            symmetricKey: symmetricKey
        )
        #expect(grouped.count == 1)
        #expect(grouped["bob"]?.count == 1)
    }
}

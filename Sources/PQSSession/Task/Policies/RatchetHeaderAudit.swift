//
//  RatchetHeaderAudit.swift
//  post-quantum-solace
//
//  Key ids a ratchet frame's header names, formatted for audit lines. Ids only,
//  never key material. `cites` are the recipient's keys and `embeds` the sender's
//  own, so a line cannot be misread for the other role.
//

import DoubleRatchetKit
import Foundation
import SessionModels

struct RatchetHeaderAudit: Equatable {
    let citesOneTimeKeyId: UUID?
    let citesMLKEMKeyId: UUID?
    let embedsOneTimeKeyId: UUID?
    let embedsMLKEMKeyId: UUID

    init(_ header: EncryptedHeader) {
        citesOneTimeKeyId = header.oneTimeKeyId
        citesMLKEMKeyId = header.mlKEMOneTimeKeyId
        embedsOneTimeKeyId = header.remoteOneTimePublicKey?.id
        embedsMLKEMKeyId = header.remoteMLKEMPublicKey.id
    }

    /// Reads the header of a frame that has not been verified; a caller that logs
    /// these ids must say so. Nil when the frame carries no readable ratchet message.
    init?(signedMessage: SignedRatchetMessage) {
        guard let data = signedMessage.signed?.data,
              let message = try? BinaryDecoder().decode(RatchetMessage.self, from: data)
        else { return nil }
        self.init(message.header)
    }

    var sendFields: String {
        "citesOtk=\(citesOneTimeKeyId.auditId) citesMlkem=\(citesMLKEMKeyId.auditId) embedsOtk=\(embedsOneTimeKeyId.auditId) embedsMlkem=\(embedsMLKEMKeyId.uuidString)"
    }

    var inboundFields: String {
        "hdrCitesOtk=\(citesOneTimeKeyId.auditId) hdrCitesMlkem=\(citesMLKEMKeyId.auditId) hdrEmbedsOtk=\(embedsOneTimeKeyId.auditId) hdrEmbedsMlkem=\(embedsMLKEMKeyId.uuidString)"
    }

    var unverifiedCitedFields: String {
        "hdrCitesOtk=\(citesOneTimeKeyId.auditId) hdrCitesMlkem=\(citesMLKEMKeyId.auditId) hdrUnverified=true"
    }

    /// Where this device holds the cited keys, so a failure says which lookup missed
    /// (`missingOneTimeKey` is thrown for both kinds). `rows` are the peer's lanes.
    func heldFields(deviceKeys: DeviceKeys, rows: [SessionIdentity.UnwrappedProps]) -> String {
        let otkHeld = Self.otkHeld(
            citedId: citesOneTimeKeyId,
            poolIds: deviceKeys.oneTimePrivateKeys.map(\.id),
            rowIds: rows.compactMap(\.ratchetOneTimePrivateKey?.id))
        let mlkemHeld = Self.mlkemHeld(
            citedId: citesMLKEMKeyId,
            poolIds: deviceKeys.mlKEMOneTimePrivateKeys.map(\.id),
            finalHolds: citesMLKEMKeyId.flatMap(deviceKeys.finalMLKEMPrivateKey(matching:)) != nil,
            rowIds: rows.compactMap(\.ratchetMLKEMPrivateKey?.id))
        return "otkHeld=\(otkHeld) mlkemHeld=\(mlkemHeld)"
    }

    /// Same order as `initializeRecipient`: pool, then the row's pinned copy.
    static func otkHeld(citedId: UUID?, poolIds: [UUID], rowIds: [UUID]) -> String {
        guard let citedId else { return "none" }
        if poolIds.contains(citedId) { return "pool" }
        return rowIds.contains(citedId) ? "row" : "none"
    }

    /// Same order as `initializeRecipient`: pool, final key, then the row's pinned
    /// copy. A header citing no ML-KEM key resolves to the final key there too.
    static func mlkemHeld(citedId: UUID?, poolIds: [UUID], finalHolds: Bool, rowIds: [UUID]) -> String {
        guard let citedId else { return "final" }
        if poolIds.contains(citedId) { return "pool" }
        if finalHolds { return "final" }
        return rowIds.contains(citedId) ? "row" : "none"
    }
}

private extension Optional<UUID> {
    var auditId: String { self?.uuidString ?? "nil" }
}

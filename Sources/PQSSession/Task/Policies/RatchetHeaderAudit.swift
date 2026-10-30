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
    let epochDigest: Data

    init(_ header: EncryptedHeader) {
        citesOneTimeKeyId = header.oneTimeKeyId
        citesMLKEMKeyId = header.mlKEMOneTimeKeyId
        embedsOneTimeKeyId = header.remoteOneTimePublicKey?.id
        embedsMLKEMKeyId = header.remoteMLKEMPublicKey.id
        epochDigest = header.ratchetEpochDigest
    }

    /// Reads the header of a frame that has not been verified; a caller that logs
    /// these ids must say so. Nil when the frame carries no readable ratchet message.
    init?(signedMessage: SignedRatchetMessage) {
        guard let data = signedMessage.signed?.data,
              let message = try? BinaryDecoder().decode(RatchetMessage.self, from: data)
        else { return nil }
        self.init(message.header)
    }

    /// Eight bytes of the epoch digest: enough to link a lane's frames across log lines.
    private var auditEpoch: String {
        epochDigest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    var sendFields: String {
        "citesOtk=\(citesOneTimeKeyId.auditId) citesMlkem=\(citesMLKEMKeyId.auditId) embedsOtk=\(embedsOneTimeKeyId.auditId) embedsMlkem=\(embedsMLKEMKeyId.uuidString) epoch=\(auditEpoch)"
    }

    var inboundFields: String {
        "hdrCitesOtk=\(citesOneTimeKeyId.auditId) hdrCitesMlkem=\(citesMLKEMKeyId.auditId) hdrEmbedsOtk=\(embedsOneTimeKeyId.auditId) hdrEmbedsMlkem=\(embedsMLKEMKeyId.uuidString) hdrEpoch=\(auditEpoch)"
    }

    var unverifiedCitedFields: String {
        "hdrCitesOtk=\(citesOneTimeKeyId.auditId) hdrCitesMlkem=\(citesMLKEMKeyId.auditId) hdrEpoch=\(auditEpoch) hdrUnverified=true"
    }

    /// The row that owns this frame's epoch and the state it failed from, including the
    /// header stash a legacy row carries. Clones share an epoch, so this reports the most
    /// advanced one and how many hold it. `none` means no row's current epoch matches,
    /// which a sender-driven re-key can cause while a row could still open the frame.
    func epochHolderFields(rows: [(id: UUID, props: SessionIdentity.UnwrappedProps)]) -> String {
        let holders = rows.filter { $0.props.ratchetEpochDigest == epochDigest }
        guard let holder = holders.max(by: { $0.props.ratchetReceivedMessagesCount < $1.props.ratchetReceivedMessagesCount }) else {
            return "epochHolder=none"
        }
        return "epochHolder=\(holder.id.uuidString) holderReceived=\(holder.props.ratchetReceivedMessagesCount) holderSkippedHeaders=\(holder.props.ratchetSkippedHeaderCount) holderCount=\(holders.count)"
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

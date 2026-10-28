//
//  ChannelInfoTitleTests.swift
//  post-quantum-solace
//
//  `ChannelInfo.title` is the creator's human title for a channel, carried to every member
//  with the synchronized core. It is optional on the wire so older clients keep decoding.
//

import BinaryCodable
import Foundation
import SessionModels
import Testing

@Suite("ChannelInfo title coding")
struct ChannelInfoTitleTests {
    @Test("title survives a round trip, inside the stored metadata too")
    func roundTrip() throws {
        let info = ChannelInfo(
            name: "#family_0f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8",
            administrator: "alice",
            members: ["alice", "bob"],
            operators: ["alice"],
            title: "Family")
        let decoded = try BinaryDecoder().decode(ChannelInfo.self, from: BinaryEncoder().encode(info))
        #expect(decoded == info)
        #expect(decoded.title == "Family")

        let stored = ChannelStoredMetadata(core: info, overlay: ChannelLocalOverlay(displayTitle: "Mine"))
        let decodedStored = try BinaryDecoder().decode(ChannelStoredMetadata.self, from: BinaryEncoder().encode(stored))
        #expect(decodedStored.core.title == "Family")
        #expect(decodedStored.overlay?.displayTitle == "Mine")
    }

    @Test("a channel without a title encodes exactly as before, and decodes with none")
    func absentTitleIsWireCompatible() throws {
        let untitled = ChannelInfo(name: "#design", administrator: "alice", members: ["alice"], operators: [])
        let bytes = try BinaryEncoder().encode(untitled)
        #expect(try BinaryDecoder().decode(ChannelInfo.self, from: bytes).title == nil)

        // The pre-title golden fixture (GoldenPersistedDataTests) still decodes.
        let pinned = "Ak5CVE4jAAAAU2Vzc2lvbk1vZGVscy5DaGFubmVsU3RvcmVkTWV0YWRhdGECAAAABAAAAGNvcmVvAAAAAQQAAAAEAAAAbmFtZQsAAAABBgAAAGRlc2lnbg0AAABhZG1pbmlzdHJhdG9yCgAAAAEFAAAAYWxpY2UHAAAAbWVtYmVycw8AAAABAQAAAAEFAAAAYWxpY2UJAAAAb3BlcmF0b3JzBQAAAAEAAAAABwAAAG92ZXJsYXkBAAAAAA=="
        let legacy = try BinaryDecoder().decode(ChannelStoredMetadata.self, from: try #require(Data(base64Encoded: pinned)))
        #expect(legacy.core.title == nil)
    }
}

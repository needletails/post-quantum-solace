//
//  ChannelInfoImageTests.swift
//  post-quantum-solace
//
//  `ChannelInfo.image` is the channel's picture, stored with the synchronized core. It is
//  optional on the wire so older clients keep decoding, and it rides a synchronization only
//  when it changes: an update of `nil` keeps the picture, empty data removes it.
//

import BinaryCodable
import Foundation
import SessionModels
import Testing

@Suite("ChannelInfo image coding")
struct ChannelInfoImageTests {
    private let picture = Data([0xFF, 0xD8, 0xFF, 0xE0, 0x01, 0x02, 0x03])

    private func info(image: Data? = nil) -> ChannelInfo {
        ChannelInfo(
            name: "#family_0f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8",
            administrator: "alice",
            members: ["alice", "bob"],
            operators: ["alice"],
            title: "Family",
            image: image)
    }

    @Test("image survives a round trip, inside the stored metadata too")
    func roundTrip() throws {
        let info = info(image: picture)
        let decoded = try BinaryDecoder().decode(ChannelInfo.self, from: BinaryEncoder().encode(info))
        #expect(decoded == info)
        #expect(decoded.image == picture)

        let stored = ChannelStoredMetadata(core: info, overlay: ChannelLocalOverlay(userMarkedPinned: true))
        let decodedStored = try BinaryDecoder().decode(ChannelStoredMetadata.self, from: BinaryEncoder().encode(stored))
        #expect(decodedStored.core.image == picture)
        #expect(decodedStored.core.title == "Family")
        #expect(decodedStored.overlay?.userMarkedPinned == true)
    }

    @Test("a channel without an image decodes with none, from the pre-image fixture too")
    func absentImageIsWireCompatible() throws {
        let bytes = try BinaryEncoder().encode(info())
        #expect(try BinaryDecoder().decode(ChannelInfo.self, from: bytes).image == nil)

        // The pre-title golden fixture (GoldenPersistedDataTests) still decodes.
        let pinned = "Ak5CVE4jAAAAU2Vzc2lvbk1vZGVscy5DaGFubmVsU3RvcmVkTWV0YWRhdGECAAAABAAAAGNvcmVvAAAAAQQAAAAEAAAAbmFtZQsAAAABBgAAAGRlc2lnbg0AAABhZG1pbmlzdHJhdG9yCgAAAAEFAAAAYWxpY2UHAAAAbWVtYmVycw8AAAABAQAAAAEFAAAAYWxpY2UJAAAAb3BlcmF0b3JzBQAAAAEAAAAABwAAAG92ZXJsYXkBAAAAAA=="
        let legacy = try BinaryDecoder().decode(ChannelStoredMetadata.self, from: try #require(Data(base64Encoded: pinned)))
        #expect(legacy.core.image == nil)
    }

    @Test("an image update of nil keeps the stored image, empty data removes it, data replaces it")
    func updatingImage() {
        let replacement = Data([0x89, 0x50, 0x4E, 0x47])
        #expect(info(image: picture).updatingImage(nil).image == picture)
        #expect(info(image: picture).updatingImage(Data()).image == nil)
        #expect(info(image: picture).updatingImage(replacement).image == replacement)
        #expect(info().updatingImage(nil).image == nil)
        #expect(info().updatingImage(Data()).image == nil)
        // Nothing else moves.
        #expect(info(image: picture).updatingImage(replacement) == info(image: replacement))
    }

    @Test("the wire copy carries the image update itself, never the stored image")
    func carryingImageUpdate() {
        let replacement = Data([0x89, 0x50, 0x4E, 0x47])
        // A roster-only synchronization stays small.
        #expect(info(image: picture).carryingImageUpdate(nil).image == nil)
        // Empty data is the removal marker and must reach the members.
        #expect(info(image: picture).carryingImageUpdate(Data()).image == Data())
        #expect(info(image: picture).carryingImageUpdate(replacement).image == replacement)
        #expect(info(image: picture).carryingImageUpdate(nil) == info())
    }
}

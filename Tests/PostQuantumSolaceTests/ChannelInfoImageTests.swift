//
//  ChannelInfoImageTests.swift
//  post-quantum-solace
//
//  `ChannelInfo.image` is the channel's picture, stored with the synchronized core. It is
//  optional on the wire so older clients keep decoding, and it rides a synchronization only
//  when it changes: an update of `nil` keeps the picture, empty data removes it.
//

import BinaryCodable
import Crypto
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
        // Nothing else moves but the image's version.
        let replaced = info(image: picture).updatingImage(replacement)
        #expect(replaced.imageVersion == 1)
        #expect(replaced.title == "Family")
        #expect(replaced.members == ["alice", "bob"])
        #expect(replaced.administrator == "alice")
    }

    @Test("the wire copy carries the image update itself, never the stored image")
    func carryingImageUpdate() {
        let replacement = Data([0x89, 0x50, 0x4E, 0x47])
        // A roster-only synchronization stays small.
        #expect(info(image: picture).carryingImageUpdate(nil).image == nil)
        // Empty data is the removal marker and must reach the members.
        #expect(info(image: picture).carryingImageUpdate(Data()).image == Data())
        #expect(info(image: picture).carryingImageUpdate(replacement).image == replacement)
    }

    /// Every synchronization says which image the sender holds, in 32 bytes, so a device
    /// that missed the image (or its removal) can tell and repair itself.
    @Test("the wire copy always carries the fingerprint of the sender's image; the stored copy never does")
    func wireCopyCarriesTheImageFingerprint() throws {
        let replacement = Data([0x89, 0x50, 0x4E, 0x47])
        func sha(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

        #expect(info(image: picture).carryingImageUpdate(nil).imageDigest == sha(picture))
        #expect(info(image: picture).carryingImageUpdate(replacement).imageDigest == sha(replacement))
        // Empty means "I hold no image", which is different from an older sender's nil.
        #expect(info().carryingImageUpdate(nil).imageDigest == Data())
        #expect(info(image: picture).carryingImageUpdate(Data()).imageDigest == Data())
        #expect(ChannelInfo.imageDigest(of: picture) == sha(picture))
        #expect(ChannelInfo.imageDigest(of: nil) == Data())

        #expect(info(image: picture).updatingImage(nil).imageDigest == nil)
        #expect(info(image: picture).carryingImageUpdate(nil).updatingImage(replacement).imageDigest == nil)

        let wire = info(image: picture).carryingImageUpdate(nil)
        let decoded = try BinaryDecoder().decode(ChannelInfo.self, from: BinaryEncoder().encode(wire))
        #expect(decoded.imageDigest == sha(picture))
        #expect(decoded.image == nil)
        // A sender from before fingerprints decodes with none.
        #expect(try BinaryDecoder().decode(ChannelInfo.self, from: BinaryEncoder().encode(info())).imageDigest == nil)
    }

    /// A group has one image. Each change takes the next version, the version is stored
    /// with the image and sent with every synchronization, and the higher version wins.
    @Test("an image change takes the next version unless one is given; keeping the image keeps its version")
    func imageVersion() throws {
        let replacement = Data([0x89, 0x50, 0x4E, 0x47])
        #expect(info().imageVersion == nil)

        // A change made on this device.
        let first = info().updatingImage(picture)
        #expect(first.imageVersion == 1)
        #expect(first.updatingImage(replacement).imageVersion == 2)
        // Removing the image is a change too.
        #expect(first.updatingImage(Data()).imageVersion == 2)
        #expect(first.updatingImage(Data()).image == nil)
        // No update keeps both.
        #expect(first.updatingImage(nil).imageVersion == 1)
        #expect(first.updatingImage(nil, version: 9).imageVersion == 1)

        // A change received from another device keeps the version it came with.
        #expect(first.updatingImage(replacement, version: 7).imageVersion == 7)

        // The wire copy carries the version of the image it describes.
        #expect(first.carryingImageUpdate(nil).imageVersion == 1)
        #expect(first.carryingImageUpdate(replacement).imageVersion == 2)
        #expect(first.carryingImageUpdate(replacement, version: 7).imageVersion == 7)

        // Stored and decoded with the image; absent on channels that never had one.
        let stored = ChannelStoredMetadata(core: first, overlay: nil)
        let decoded = try BinaryDecoder().decode(ChannelStoredMetadata.self, from: BinaryEncoder().encode(stored))
        #expect(decoded.core.imageVersion == 1)
        #expect(decoded.core.image == picture)
    }
}

import Foundation
import Testing
@testable import PQSSession

@Suite("Recent outbound replay store")
struct RecentOutboundReplayStoreTests {
    @Test("availability checks do not consume replay credit")
    func availabilityChecksDoNotConsumeReplayCredit() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        var store = RecentOutboundReplayStore<String>(
            ttl: 600,
            limit: 256,
            maxReplays: 5)
        store.remember("payload", sharedId: "control", now: now)

        for _ in 0..<10 {
            let isAvailable = store.contains(sharedId: "control", now: now)
            #expect(isAvailable)
        }

        let consumedReplay = store.consume(sharedId: "control", now: now)
        let replay = try #require(consumedReplay)
        #expect(replay.message == "payload")
        #expect(replay.replayCount == 1)
    }

    @Test("one service consumes one credit and the sixth is rejected")
    func oneServiceConsumesOneCredit() throws {
        let now = Date(timeIntervalSince1970: 2_000)
        var store = RecentOutboundReplayStore<String>(
            ttl: 600,
            limit: 256,
            maxReplays: 5)
        store.remember("payload", sharedId: "control", now: now)

        for expectedCount in 1...5 {
            let isAvailable = store.contains(sharedId: "control", now: now)
            #expect(isAvailable)
            let consumedReplay = store.consume(sharedId: "control", now: now)
            let replay = try #require(consumedReplay)
            #expect(replay.replayCount == expectedCount)
        }

        let isAvailableAfterFive = store.contains(sharedId: "control", now: now)
        let sixthReplay = store.consume(sharedId: "control", now: now)
        #expect(!isAvailableAfterFive)
        #expect(sixthReplay == nil)
    }

    @Test("ten minute expiry and FIFO capacity remain bounded")
    func expiryAndCapacityRemainBounded() {
        let now = Date(timeIntervalSince1970: 3_000)
        var store = RecentOutboundReplayStore<String>(
            ttl: 600,
            limit: 2,
            maxReplays: 5)

        store.remember("first", sharedId: "first", now: now)
        store.remember("second", sharedId: "second", now: now.addingTimeInterval(1))
        store.remember("third", sharedId: "third", now: now.addingTimeInterval(2))

        let hasFirst = store.contains(sharedId: "first", now: now.addingTimeInterval(2))
        let hasSecond = store.contains(sharedId: "second", now: now.addingTimeInterval(2))
        let hasThird = store.contains(sharedId: "third", now: now.addingTimeInterval(2))
        let hasExpiredSecond = store.contains(
            sharedId: "second",
            now: now.addingTimeInterval(601))
        #expect(!hasFirst)
        #expect(hasSecond)
        #expect(hasThird)
        #expect(!hasExpiredSecond)
    }
}

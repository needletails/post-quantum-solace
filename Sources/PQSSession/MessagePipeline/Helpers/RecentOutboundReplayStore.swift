import Foundation

/// Bounded, in-memory replay source for non-persistent control messages.
///
/// Availability checks are intentionally non-consuming. A replay credit is
/// consumed only when the caller takes a payload for a resend service.
struct RecentOutboundReplayStore<Message: Sendable>: Sendable {
    struct Replay: Sendable {
        let message: Message
        let createdAt: Date
        var replayCount: Int
    }

    private var replaysBySharedId: [String: Replay] = [:]
    private let ttl: TimeInterval
    private let limit: Int
    private let maxReplays: Int

    init(ttl: TimeInterval, limit: Int, maxReplays: Int) {
        self.ttl = ttl
        self.limit = limit
        self.maxReplays = maxReplays
    }

    mutating func remember(
        _ message: Message,
        sharedId: String,
        now: Date = Date()
    ) {
        cleanup(now: now)
        guard replaysBySharedId[sharedId] == nil else { return }

        replaysBySharedId[sharedId] = Replay(
            message: message,
            createdAt: now,
            replayCount: 0)

        guard replaysBySharedId.count > limit else { return }
        let overflow = replaysBySharedId.count - limit
        let oldestKeys = replaysBySharedId
            .sorted { $0.value.createdAt < $1.value.createdAt }
            .prefix(overflow)
            .map(\.key)
        for key in oldestKeys {
            replaysBySharedId.removeValue(forKey: key)
        }
    }

    mutating func contains(
        sharedId: String,
        now: Date = Date()
    ) -> Bool {
        cleanup(now: now)
        guard let replay = replaysBySharedId[sharedId] else { return false }
        guard replay.replayCount < maxReplays else {
            replaysBySharedId.removeValue(forKey: sharedId)
            return false
        }
        return true
    }

    mutating func consume(
        sharedId: String,
        now: Date = Date()
    ) -> (message: Message, replayCount: Int)? {
        cleanup(now: now)
        guard var replay = replaysBySharedId[sharedId] else { return nil }
        guard replay.replayCount < maxReplays else {
            replaysBySharedId.removeValue(forKey: sharedId)
            return nil
        }

        replay.replayCount += 1
        replaysBySharedId[sharedId] = replay
        return (replay.message, replay.replayCount)
    }

    private mutating func cleanup(now: Date) {
        let cutoff = now.addingTimeInterval(-ttl)
        replaysBySharedId = replaysBySharedId.filter { _, replay in
            replay.createdAt > cutoff
        }
    }
}

import Foundation

/// Bounded, in-memory replay source for non-persistent control messages.
///
/// Entries are keyed by `(recipientDeviceId, sharedId)`: a replay is only ever
/// handed back to the device the control was originally encrypted for, so a
/// requester citing another device's shared id finds nothing.
///
/// Availability checks are intentionally non-consuming. A replay credit is
/// consumed only when the caller takes a payload for a resend service.
struct RecentOutboundReplayStore<Message: Sendable>: Sendable {
    struct Replay: Sendable {
        let message: Message
        let createdAt: Date
        var replayCount: Int
    }

    private struct Key: Hashable, Sendable {
        let recipientDeviceId: UUID
        let sharedId: String
    }

    private var replaysByKey: [Key: Replay] = [:]
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
        recipientDeviceId: UUID,
        now: Date = Date()
    ) {
        cleanup(now: now)
        let key = Key(recipientDeviceId: recipientDeviceId, sharedId: sharedId)
        guard replaysByKey[key] == nil else { return }

        replaysByKey[key] = Replay(
            message: message,
            createdAt: now,
            replayCount: 0)

        guard replaysByKey.count > limit else { return }
        let overflow = replaysByKey.count - limit
        let oldestKeys = replaysByKey
            .sorted { $0.value.createdAt < $1.value.createdAt }
            .prefix(overflow)
            .map(\.key)
        for key in oldestKeys {
            replaysByKey.removeValue(forKey: key)
        }
    }

    mutating func contains(
        sharedId: String,
        recipientDeviceId: UUID,
        now: Date = Date()
    ) -> Bool {
        cleanup(now: now)
        let key = Key(recipientDeviceId: recipientDeviceId, sharedId: sharedId)
        guard let replay = replaysByKey[key] else { return false }
        guard replay.replayCount < maxReplays else {
            replaysByKey.removeValue(forKey: key)
            return false
        }
        return true
    }

    mutating func consume(
        sharedId: String,
        recipientDeviceId: UUID,
        now: Date = Date()
    ) -> (message: Message, replayCount: Int)? {
        cleanup(now: now)
        let key = Key(recipientDeviceId: recipientDeviceId, sharedId: sharedId)
        guard var replay = replaysByKey[key] else { return nil }
        guard replay.replayCount < maxReplays else {
            replaysByKey.removeValue(forKey: key)
            return nil
        }

        replay.replayCount += 1
        replaysByKey[key] = replay
        return (replay.message, replay.replayCount)
    }

    private mutating func cleanup(now: Date) {
        let cutoff = now.addingTimeInterval(-ttl)
        replaysByKey = replaysByKey.filter { _, replay in
            replay.createdAt > cutoff
        }
    }
}

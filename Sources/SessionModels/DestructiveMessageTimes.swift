//
//  DestructiveMessageTimes.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/25/24.
//
import Foundation

/// An enumeration representing various time intervals for destructive messages.
///
/// This enum defines different time intervals that can be used to specify how long a message should remain
/// before it is considered destructive (i.e., deleted or no longer accessible). Destructive messages are
/// automatically removed after the specified time interval has elapsed.
///
/// ## Overview
/// The `DestructiveMessageTimes` enum provides a type-safe way to configure message destruction intervals
/// in your application. It supports both predefined intervals for common use cases and custom intervals
/// for specific requirements.
///
/// ## Cases
/// - `off`: Disables the destructive message feature entirely
/// - `custom(TimeInterval)`: Allows specification of a custom time interval in seconds
/// - `thirtySeconds`: 30-second interval for very temporary messages
/// - `fiveMinutes`: 5-minute interval for short-term messages
/// - `oneHour`: 1-hour interval for medium-term messages
/// - `eightHours`: 8-hour interval for workday messages
/// - `oneDay`: 24-hour interval for daily messages
/// - `oneWeek`: 7-day interval for weekly messages
/// - `fourWeeks`: 28-day interval for monthly messages
///
/// ## Properties
/// - `id`: A unique identifier for the enum case (generates new UUID on each access)
/// - `description`: A human-readable string representation of the enum case
/// - `timeInterval`: The duration in seconds, or `nil` if destruction is disabled
///
/// ## Usage Examples
///
/// ### Basic Usage
/// ```swift
/// let destructionTime = DestructiveMessageTimes.oneHour
/// if let interval = destructionTime.timeInterval {
///     // Schedule message destruction after 1 hour
///     Timer.scheduledTimer(withTimeInterval: interval, repeats: false) { _ in
///         // Delete message logic
///     }
/// }
/// ```
///
/// ### Custom Interval
/// ```swift
/// let customTime = DestructiveMessageTimes.custom(1800) // 30 minutes
/// print(customTime.description) // "Custom Interval"
/// print(customTime.timeInterval) // Optional(1800.0)
/// ```
///
/// ### Disabled Destruction
/// ```swift
/// let disabled = DestructiveMessageTimes.off
/// print(disabled.timeInterval) // nil
/// print(disabled.description) // "Off"
/// ```
///
/// ### User Interface Integration
/// ```swift
/// let options: [DestructiveMessageTimes] = [
///     .off, .thirtySeconds, .fiveMinutes, .oneHour, .oneDay, .oneWeek
/// ]
///
/// // Display in picker or menu
/// for option in options {
///     print("\(option.description): \(option.timeInterval?.description ?? "Never")")
/// }
/// ```
///
/// ## Thread Safety
/// This enum is marked as `Sendable` and can be safely used across different threads.
///
/// ## Conformance
/// - `Codable`: Can be encoded/decoded for persistence
/// - `CustomStringConvertible`: Provides human-readable descriptions
/// - `Identifiable`: Supports SwiftUI list identification
/// - `Hashable`: Can be used in sets and as dictionary keys
/// - `Sendable`: Thread-safe for concurrent access
public enum DestructiveMessageTimes: Codable, CustomStringConvertible, Identifiable, Hashable, Sendable {
    // MARK: - Time Constants

    /// The number of seconds in one minute
    private static let secondsInMinute: TimeInterval = 60

    /// The number of seconds in one hour
    private static let secondsInHour: TimeInterval = 3600

    /// The number of seconds in one day (24 hours)
    private static let secondsInDay: TimeInterval = 86400

    /// The number of seconds in one week (7 days)
    private static let secondsInWeek: TimeInterval = 604_800

    // MARK: - Properties

    /// A unique identifier for the enum case.
    ///
    /// This property generates a new UUID each time it's accessed. If you need a stable
    /// identifier, consider storing the UUID or using a different identification strategy.
    public var id: UUID {
        UUID()
    }

    // MARK: - Enum Cases

    /// Disables the destructive message feature
    case off

    /// A custom time interval specified by the user
    /// - Parameter interval: The duration in seconds before message destruction
    case custom(TimeInterval)

    /// 30-second interval for very temporary messages
    case thirtySeconds

    /// 5-minute interval for short-term messages
    case fiveMinutes

    /// 1-hour interval for medium-term messages
    case oneHour

    /// 8-hour interval for workday messages
    case eightHours

    /// 24-hour interval for daily messages
    case oneDay

    /// 7-day interval for weekly messages
    case oneWeek

    /// 28-day interval for monthly messages
    case fourWeeks

    // MARK: - CustomStringConvertible

    /// A textual representation of the enum case.
    ///
    /// Returns a human-readable string that can be used in user interfaces
    /// to describe the selected destruction interval.
    public var description: String {
        switch self {
        case .off:
            "Off"
        case .custom:
            "Custom Interval"
        case .thirtySeconds:
            "30 Seconds"
        case .fiveMinutes:
            "5 Minutes"
        case .oneHour:
            "1 Hour"
        case .eightHours:
            "8 Hours"
        case .oneDay:
            "1 Day"
        case .oneWeek:
            "1 Week"
        case .fourWeeks:
            "4 Weeks"
        }
    }

    // MARK: - Time Interval Computation

    /// The time interval associated with the enum case, if applicable.
    ///
    /// Returns the duration in seconds that the message should remain before being destroyed.
    /// Returns `nil` for the `.off` case, indicating that message destruction is disabled.
    ///
    /// - Returns: The duration in seconds, or `nil` if destruction is disabled
    public var timeInterval: TimeInterval? {
        switch self {
        case .off:
            nil
        case let .custom(interval):
            interval
        case .thirtySeconds:
            Self.secondsInMinute * 0.5
        case .fiveMinutes:
            Self.secondsInMinute * 5
        case .oneHour:
            Self.secondsInHour
        case .eightHours:
            Self.secondsInHour * 8
        case .oneDay:
            Self.secondsInDay
        case .oneWeek:
            Self.secondsInWeek
        case .fourWeeks:
            Self.secondsInWeek * 4
        }
    }
}

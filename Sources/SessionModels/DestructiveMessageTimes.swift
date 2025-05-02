//
//  DestructiveMessageTimes.swift
//  crypto-session
//
//  Created by Cole M on 9/25/24.
//
import Foundation

/// An enumeration representing various time intervals for destructive messages.
///
/// This enum defines different time intervals that can be used to specify how long a message should remain
/// before it is considered destructive (i.e., deleted or no longer accessible).
///
/// ## Cases
/// - `off`: Indicates that the destructive message feature is turned off.
/// - `custom(TimeInterval)`: A custom time interval specified by the user.
/// - `thirtyseconds`: A predefined interval of 30 seconds.
/// - `fiveMinutes`: A predefined interval of 5 minutes.
/// - `oneHour`: A predefined interval of 1 hour.
/// - `eightHours`: A predefined interval of 8 hours.
/// - `oneDay`: A predefined interval of 1 day.
/// - `oneWeek`: A predefined interval of 1 week.
/// - `fourWeeks`: A predefined interval of 4 weeks.
///
/// ## Properties
/// - `id`: A unique identifier for the enum case, generated as a new `UUID`.
/// - `description`: A string representation of the enum case, providing a human-readable description.
/// - `timeInterval`: An optional `TimeInterval` representing the duration associated with the enum case.
public enum DestructiveMessageTimes: Codable, CustomStringConvertible, Identifiable, Hashable, Sendable {
    
    public var id: UUID {
        UUID()
    }
    
    case off
    case custom(TimeInterval)
    case thirtyseconds
    case fiveMinutes
    case oneHour
    case eightHours
    case oneDay
    case oneWeek
    case fourWeeks
    
    /// A textual representation of the enum case.
    public var description: String {
        switch self {
        case .off:
            return "Off"
        case .custom(_):
            return "Custom Interval"
        case .thirtyseconds:
            return "30 Seconds"
        case .fiveMinutes:
            return "5 Minutes"
        case .oneHour:
            return "1 Hour"
        case .eightHours:
            return "8 Hours"
        case .oneDay:
            return "1 Day"
        case .oneWeek:
            return "1 Week"
        case .fourWeeks:
            return "4 Weeks"
        }
    }
    
    /// The time interval associated with the enum case, if applicable.
    public var timeInterval: TimeInterval? {
        switch self {
        case .off:
            return nil
        case .custom(let interval):
            return interval
        case .thirtyseconds:
            return 30
        case .fiveMinutes:
            return 300
        case .oneHour:
            return 3600
        case .eightHours:
            return 3600 * 8
        case .oneDay:
            return 86400
        case .oneWeek:
            return 86400 * 7
        case .fourWeeks:
            return 604800 * 4
        }
    }
}

//
//  DestructiveMessageTimes.swift
//  crypto-session
//
//  Created by Cole M on 9/25/24.
//
import Foundation

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
    
    public var description: String {
        switch self {
        case .off:
            "Off"
        case .custom(_):
            "Custom Interval"
        case .thirtyseconds:
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
    
    public var timeInterval: TimeInterval? {
        switch self {
        case .off:
            nil
        case .custom(let interval):
            interval
        case .thirtyseconds:
            30
        case .fiveMinutes:
            300
        case .oneHour:
            3600
        case .eightHours:
            3600*8
        case .oneDay:
            86400
        case .oneWeek:
            86400*7
        case .fourWeeks:
            604800*4
        }
    }
    
}

//
//  MessageMetadata.swift
//  crypto-session
//
//  Created by Cole M on 9/29/24.
//
import Foundation

public struct MessageMetadata: Sendable, Codable {

    public var userMarkedPinned: Bool
    public var userMarkedRead: Bool
    
    public init(userMarkedPinned: Bool, userMarkedRead: Bool) {
        self.userMarkedPinned = userMarkedPinned
        self.userMarkedRead = userMarkedRead
    }
    
}

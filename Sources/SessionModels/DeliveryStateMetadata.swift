//
//  DeliveryStateMetadata.swift
//  crypto-session
//
//  Created by Cole M on 4/19/25.
//


public struct DeliveryStateMetadata: Codable, Sendable {
    public let state: DeliveryState
    public let sharedId: String
    
    public init(state: DeliveryState, sharedId: String) {
        self.state = state
        self.sharedId = sharedId
    }
}

public struct EditMessageMetadata<T: Codable & Sendable>: Codable, Sendable {
    public let value: T
    public let sharedId: String
    public let sender: String
    
    public init(value: T, sharedId: String, sender: String) {
        self.value = value
        self.sharedId = sharedId
        self.sender = sender
    }
}

public struct RevokeMessageMetadata: Codable, Sendable {
    public let sharedId: String
    
    public init(sharedId: String) {
        self.sharedId = sharedId
    }
}

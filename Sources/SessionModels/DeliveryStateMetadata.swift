//
//  DeliveryStateMetadata.swift
//  post-quantum-solace
//
//  Created by Cole M on 4/19/25.
//


/// A structure representing metadata for the delivery state of a message.
///
/// This struct contains information about the current delivery state and a shared identifier associated with it.
///
/// ## Properties
/// - `state`: The current delivery state of the message, represented as a `DeliveryState`.
/// - `sharedId`: A unique identifier shared across the communication context.
///
/// ## Initializer
/// - `init(state:sharedId:)`: Initializes a new instance of `DeliveryStateMetadata` with the specified delivery state and shared identifier.
public struct DeliveryStateMetadata: Codable, Sendable {
    public let state: DeliveryState
    public let sharedId: String
    
    public init(state: DeliveryState, sharedId: String) {
        self.state = state
        self.sharedId = sharedId
    }
}

/// A structure representing metadata for editing a message.
///
/// This struct contains information about the new value of the message, a shared identifier, and the sender's information.
///
/// ## Properties
/// - `value`: The new value of the message, which can be of any type conforming to `Codable` and `Sendable`.
/// - `sharedId`: A unique identifier shared across the communication context.
/// - `sender`: The identifier of the sender who is editing the message.
///
/// ## Initializer
/// - `init(value:sharedId:sender:)`: Initializes a new instance of `EditMessageMetadata` with the specified value, shared identifier, and sender.
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

/// A structure representing metadata for revoking a message.
///
/// This struct contains information about the shared identifier of the message that is being revoked.
///
/// ## Properties
/// - `sharedId`: A unique identifier shared across the communication context for the message being revoked.
///
/// ## Initializer
/// - `init(sharedId:)`: Initializes a new instance of `RevokeMessageMetadata` with the specified shared identifier.
public struct RevokeMessageMetadata: Codable, Sendable {
    public let sharedId: String
    
    public init(sharedId: String) {
        self.sharedId = sharedId
    }
}

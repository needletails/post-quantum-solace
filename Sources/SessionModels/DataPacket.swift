//
//  DataPacket.swift
//  post-quantum-solace
//
//  Created by Cole M on 6/29/25.
//
import Foundation

/// A structure representing a data packet for secure communication.
///
/// This struct encapsulates data that needs to be transmitted securely between parties.
/// It includes a unique identifier for tracking and the actual data payload. The struct
/// conforms to the `Codable` and `Sendable` protocols, allowing it to be easily encoded
/// and decoded for data transfer and to be safely used across concurrent tasks.
///
/// ## Usage
/// ```swift
/// let packet = DataPacket(
///     id: UUID(),
///     data: encryptedMessageData
/// )
/// ```
///
/// ## Properties
/// - `id`: A unique identifier for the data packet, used for tracking and deduplication
/// - `data`: The actual data contained in the packet, typically encrypted message content
///
/// ## Security Considerations
/// The data contained in this packet should be encrypted before transmission to ensure
/// confidentiality and integrity of the communication.
public struct DataPacket: Codable, Sendable {
    /// A unique identifier for the data packet.
    /// Used for tracking, deduplication, and correlation of related packets.
    public let id: UUID

    /// The actual data contained in the packet.
    /// This typically contains encrypted message content or other secure data.
    public var data: Data

    /// Initializes a new instance of `DataPacket`.
    ///
    /// Creates a data packet with the specified identifier and data payload.
    ///
    /// - Parameters:
    ///   - id: A unique identifier for the data packet. Should be a valid UUID.
    ///   - data: The data to be contained in the packet. Should be encrypted for security.
    public init(id: UUID, data: Data) {
        self.id = id
        self.data = data
    }
}

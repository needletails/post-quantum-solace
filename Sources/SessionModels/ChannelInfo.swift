//
//  ChannelInfo.swift
//  post-quantum-solace
//
//  Created by Cole M on 11/19/25.
//


/// A lightweight, on-the-wire description of a channel-style communication.
///
/// `ChannelInfo` is what gets sent when a channel is created, synchronized,
/// or advertised to a new participant. It carries the human-visible
/// channel name and the role assignments (administrator, members,
/// operators) but **no** persistent state — no message count, no
/// metadata blob, no encryption material. Persisted state lives on
/// ``BaseCommunication``.
public struct ChannelInfo: Codable, Sendable, Hashable {
    /// Display name / handle for the channel (e.g. `"design"`).
    public let name: String
    /// Secret name of the user with administrative privileges over the
    /// channel.
    public let administrator: String
    /// Secret names of every member currently in the channel.
    public let members: Set<String>
    /// Secret names of users with elevated (operator) privileges below
    /// administrator.
    public let operators: Set<String>

    public init(
        name: String,
        administrator: String,
        members: Set<String>,
        operators: Set<String>
    ) {
        self.name = name
        self.administrator = administrator
        self.members = members
        self.operators = operators
    }
}

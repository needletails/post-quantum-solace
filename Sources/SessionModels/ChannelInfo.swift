//
//  ChannelInfo.swift
//  post-quantum-solace
//
//  Created by Cole M on 11/19/25.
//

import Foundation

/// A lightweight, on-the-wire description of a channel-style communication.
///
/// `ChannelInfo` is what gets sent when a channel is created, synchronized,
/// or advertised to a new participant. It carries the human-visible
/// channel name and the role assignments (administrator, members,
/// operators) but **no** persistent state — no message count, no
/// metadata blob, no encryption material. Persisted state lives on
/// ``BaseCommunication``.
public struct ChannelInfo: Codable, Sendable, Hashable {
    private enum CodingKeys: String, CodingKey {
        case name
        case administrator
        case members
        case operators
        case enabledBotNames
        case botMemberWelcome
        case botOperatorWelcome
        case botIdleHint
        case title
        case image
    }

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
    /// Server bot identifiers persisted with the encrypted channel core.
    public let enabledBotNames: [String]?
    /// Optional ChanBot templates. These are channel-shared configuration, not local UI state.
    public let botMemberWelcome: String?
    public let botOperatorWelcome: String?
    public let botIdleHint: String?
    /// Human title the creator gave the channel (e.g. `"Family"`); `name` is the
    /// `#slug_<uuid>` wire identifier. Synchronized to every member; `nil` on channels
    /// created before titles were shared.
    public let title: String?
    /// The channel's picture (JPEG or PNG bytes). Stored on every member's device, but a
    /// synchronization carries it only when it changes: absent means "keep yours", empty
    /// data means "remove it". `nil` in storage on channels without a picture.
    public let image: Data?

    public init(
        name: String,
        administrator: String,
        members: Set<String>,
        operators: Set<String>,
        enabledBotNames: [String]? = nil,
        botMemberWelcome: String? = nil,
        botOperatorWelcome: String? = nil,
        botIdleHint: String? = nil,
        title: String? = nil,
        image: Data? = nil
    ) {
        self.name = name
        self.administrator = administrator
        self.members = members
        self.operators = operators
        self.enabledBotNames = enabledBotNames
        self.botMemberWelcome = botMemberWelcome
        self.botOperatorWelcome = botOperatorWelcome
        self.botIdleHint = botIdleHint
        self.title = title
        self.image = image
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        administrator = try container.decode(String.self, forKey: .administrator)
        members = try container.decode(Set<String>.self, forKey: .members)
        operators = try container.decode(Set<String>.self, forKey: .operators)
        enabledBotNames = try container.decodeIfPresent([String].self, forKey: .enabledBotNames)
        botMemberWelcome = try container.decodeIfPresent(String.self, forKey: .botMemberWelcome)
        botOperatorWelcome = try container.decodeIfPresent(String.self, forKey: .botOperatorWelcome)
        botIdleHint = try container.decodeIfPresent(String.self, forKey: .botIdleHint)
        title = try container.decodeIfPresent(String.self, forKey: .title)
        image = try container.decodeIfPresent(Data.self, forKey: .image)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(administrator, forKey: .administrator)
        try container.encode(members, forKey: .members)
        try container.encode(operators, forKey: .operators)
        if let enabledBotNames {
            try container.encode(enabledBotNames, forKey: .enabledBotNames)
        }
        if let botMemberWelcome {
            try container.encode(botMemberWelcome, forKey: .botMemberWelcome)
        }
        if let botOperatorWelcome {
            try container.encode(botOperatorWelcome, forKey: .botOperatorWelcome)
        }
        if let botIdleHint {
            try container.encode(botIdleHint, forKey: .botIdleHint)
        }
        if let title {
            try container.encode(title, forKey: .title)
        }
        if let image {
            try container.encode(image, forKey: .image)
        }
    }

    /// The copy to store after an image update: `nil` keeps the stored image, empty data
    /// removes it, anything else replaces it.
    public func updatingImage(_ update: Data?) -> ChannelInfo {
        guard let update else { return self }
        return replacingImage(update.isEmpty ? nil : update)
    }

    /// The copy to send after an image update. It carries the update itself, never the
    /// stored image: a synchronization is one encrypted copy per member device, so a
    /// roster-only change must stay small.
    public func carryingImageUpdate(_ update: Data?) -> ChannelInfo {
        replacingImage(update)
    }

    private func replacingImage(_ image: Data?) -> ChannelInfo {
        ChannelInfo(
            name: name,
            administrator: administrator,
            members: members,
            operators: operators,
            enabledBotNames: enabledBotNames,
            botMemberWelcome: botMemberWelcome,
            botOperatorWelcome: botOperatorWelcome,
            botIdleHint: botIdleHint,
            title: title,
            image: image)
    }
}

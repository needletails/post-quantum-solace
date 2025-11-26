//
//  ChannelInfo.swift
//  post-quantum-solace
//
//  Created by Cole M on 11/19/25.
//


public struct ChannelInfo: Codable {
    public let name: String
    public let administrator: String
    public let members: Set<String>
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

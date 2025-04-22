//
//  SharedContactInfo.swift
//  crypto-session
//
//  Created by Cole M on 4/19/25.
//
import Foundation
import struct BSON.Document

public struct SharedContactInfo: Codable, Sendable {
    public let secretName: String
    public let metadata: Document
    public let sharedCommunicationId: UUID?
    
    public init(secretName: String, metadata: Document, sharedCommunicationId: UUID?) {
        self.secretName = secretName
        self.metadata = metadata
        self.sharedCommunicationId = sharedCommunicationId
    }
}

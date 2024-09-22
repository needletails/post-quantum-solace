//
//  DeviceKeys.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation

/// A struct representing the cryptographic keys associated with a device.
public struct DeviceKeys: Codable, Sendable, Equatable {
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case deviceIdentity = "a"      // Key for the device identity
        case privateSigningKey = "b"    // Key for the private signing key
        case privateKey = "c"        // Key for the private key
    }
    
    /// Unique identifier for the device.
    let deviceIdentity: UUID
    /// Data representing the private signing identity of the device.
    let privateSigningKey: Data
    /// Data representing the private key of the device.
    let privateKey: Data
}

//
//  ContactMetadata.swift
//  post-quantum-solace
//
//  Created by Cole M on 6/29/25.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//
import Foundation

/// A structure representing metadata for a contact.
///
/// This struct contains detailed information about a contact including personal details,
/// communication preferences, and visual representation. It conforms to the `Codable` and
/// `Sendable` protocols, allowing it to be easily encoded and decoded for data transfer
/// and to be safely used across concurrent tasks.
///
/// ## Usage
/// ```swift
/// let metadata = ContactMetadata(
///     status: "Online",
///     nickname: "Bob",
///     firstName: "Robert",
///     lastName: "Smith",
///     email: "bob@example.com",
///     phone: "+1234567890",
///     image: profileImageData
/// )
/// ```
///
/// ## Properties
/// - `status`: An optional string representing the contact's status (e.g., "Online", "Away", "Busy")
/// - `nickname`: An optional string representing the contact's preferred display name
/// - `firstName`: An optional string representing the contact's first name
/// - `lastName`: An optional string representing the contact's last name
/// - `email`: An optional string representing the contact's email address
/// - `phone`: An optional string representing the contact's phone number
/// - `image`: An optional `Data` object representing the contact's profile image
///
/// ## Immutable Updates
/// The struct provides immutable update methods that return new instances with updated values,
/// following functional programming principles and ensuring thread safety.
public struct ContactMetadata: Codable, Sendable {
    /// The contact's current status or availability.
    /// Examples: "Online", "Away", "Busy", "Do Not Disturb"
    public var status: String?

    /// The contact's preferred display name or nickname.
    /// This is typically used in the UI instead of the full name.
    public var nickname: String?

    /// The contact's first name.
    public var firstName: String?

    /// The contact's last name.
    public var lastName: String?

    /// The contact's email address.
    public var email: String?

    /// The contact's phone number.
    public var phone: String?

    /// The contact's profile image data.
    /// Should contain image data in a common format (JPEG, PNG, etc.)
    public var image: Data?

    /// Initializes a new instance of `ContactMetadata`.
    ///
    /// Creates a contact metadata object with the specified values. All parameters are optional
    /// and default to `nil`, allowing for partial contact information.
    ///
    /// - Parameters:
    ///   - status: The contact's current status (optional)
    ///   - nickname: The contact's nickname (optional)
    ///   - firstName: The contact's first name (optional)
    ///   - lastName: The contact's last name (optional)
    ///   - email: The contact's email address (optional)
    ///   - phone: The contact's phone number (optional)
    ///   - image: The contact's profile image data (optional)
    public init(status: String? = nil, nickname: String? = nil, firstName: String? = nil, lastName: String? = nil, email: String? = nil, phone: String? = nil, image: Data? = nil) {
        self.status = status
        self.nickname = nickname
        self.firstName = firstName
        self.lastName = lastName
        self.email = email
        self.phone = phone
        self.image = image
    }

    /// Returns a new `ContactMetadata` instance with the updated status.
    ///
    /// Creates a copy of the current metadata with the specified status while preserving
    /// all other properties.
    ///
    /// - Parameter status: The new status to set
    /// - Returns: A new `ContactMetadata` instance with the updated status
    public func updating(status: String) -> ContactMetadata {
        ContactMetadata(
            status: status,
            nickname: nickname,
            firstName: firstName,
            lastName: lastName,
            email: email,
            phone: phone,
            image: image
        )
    }

    /// Returns a new `ContactMetadata` instance with the updated nickname.
    ///
    /// Creates a copy of the current metadata with the specified nickname while preserving
    /// all other properties.
    ///
    /// - Parameter nickname: The new nickname to set
    /// - Returns: A new `ContactMetadata` instance with the updated nickname
    public func updating(nickname: String) -> ContactMetadata {
        ContactMetadata(
            status: status,
            nickname: nickname,
            firstName: firstName,
            lastName: lastName,
            email: email,
            phone: phone,
            image: image
        )
    }

    /// Returns a new `ContactMetadata` instance with the updated first name.
    ///
    /// Creates a copy of the current metadata with the specified first name while preserving
    /// all other properties.
    ///
    /// - Parameter firstName: The new first name to set
    /// - Returns: A new `ContactMetadata` instance with the updated first name
    public func updating(firstName: String) -> ContactMetadata {
        ContactMetadata(
            status: status,
            nickname: nickname,
            firstName: firstName,
            lastName: lastName,
            email: email,
            phone: phone,
            image: image
        )
    }

    /// Returns a new `ContactMetadata` instance with the updated last name.
    ///
    /// Creates a copy of the current metadata with the specified last name while preserving
    /// all other properties.
    ///
    /// - Parameter lastName: The new last name to set
    /// - Returns: A new `ContactMetadata` instance with the updated last name
    public func updating(lastName: String) -> ContactMetadata {
        ContactMetadata(
            status: status,
            nickname: nickname,
            firstName: firstName,
            lastName: lastName,
            email: email,
            phone: phone,
            image: image
        )
    }

    /// Returns a new `ContactMetadata` instance with the updated email address.
    ///
    /// Creates a copy of the current metadata with the specified email address while preserving
    /// all other properties.
    ///
    /// - Parameter email: The new email address to set
    /// - Returns: A new `ContactMetadata` instance with the updated email address
    public func updating(email: String) -> ContactMetadata {
        ContactMetadata(
            status: status,
            nickname: nickname,
            firstName: firstName,
            lastName: lastName,
            email: email,
            phone: phone,
            image: image
        )
    }

    /// Returns a new `ContactMetadata` instance with the updated phone number.
    ///
    /// Creates a copy of the current metadata with the specified phone number while preserving
    /// all other properties.
    ///
    /// - Parameter phone: The new phone number to set
    /// - Returns: A new `ContactMetadata` instance with the updated phone number
    public func updating(phone: String) -> ContactMetadata {
        ContactMetadata(
            status: status,
            nickname: nickname,
            firstName: firstName,
            lastName: lastName,
            email: email,
            phone: phone,
            image: image
        )
    }

    /// Returns a new `ContactMetadata` instance with the updated image data.
    ///
    /// Creates a copy of the current metadata with the specified image data while preserving
    /// all other properties.
    ///
    /// - Parameter image: The new image data to set
    /// - Returns: A new `ContactMetadata` instance with the updated image data
    public func updating(image: Data) -> ContactMetadata {
        ContactMetadata(
            status: status,
            nickname: nickname,
            firstName: firstName,
            lastName: lastName,
            email: email,
            phone: phone,
            image: image
        )
    }
}

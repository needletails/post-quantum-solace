//
//  Document+Extension.swift
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
import BSON

/// Extension to `Document` providing convenient decoding capabilities.
///
/// This extension adds a generic decoding method to BSON documents, making it easier
/// to extract typed objects from document storage.
extension Document {
    /// Decodes a `Codable` object from the document using the specified key.
    ///
    /// This method provides a convenient way to extract typed objects from BSON documents.
    /// It handles the conversion from BSON primitive values to the target type.
    ///
    /// - Parameter key: The document key to find and decode
    /// - Returns: The decoded `Codable` object of the specified type
    /// - Throws: `DecodingError.dataCorrupted` if the key is not found, or `Errors.primitiveIsNil`
    ///   if the value cannot be converted to the target type
    public func decode<T: Codable>(forKey key: String) throws -> T {
        guard let value = self[key] else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: [], debugDescription: "Key \(key) not found in document"))
        }
        guard let data = try BSONEncoder().encodePrimitive(value) else { throw Errors.primitiveIsNil }
        return try BSONDecoder().decode(T.self, fromPrimitive: data)
    }

    /// An enumeration representing possible errors that can occur during document decoding.
    ///
    /// Defines the specific error types that can be thrown by the document decoding operations.
    enum Errors: Error {
        /// Indicates that a primitive value is nil and cannot be processed.
        /// This typically occurs when the BSON value cannot be converted to the expected type.
        case primitiveIsNil
    }
}

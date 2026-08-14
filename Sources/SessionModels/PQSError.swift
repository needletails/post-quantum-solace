//
//  PQSError.swift
//  post-quantum-solace
//

import Foundation

/// Session, persistence, and crypto failures. Cases are identifiers, not user-facing copy.
public enum PQSError: Error, Equatable, Sendable {
    case saltError
    case databaseNotInitialized
    case sessionNotInitialized
    case transportNotInitialized
    case sessionEncryptionError
    case sessionDecryptionError
    case connectionIsNonViable
    case invalidPassword
    case invalidSecretName
    case invalidDeviceIdentity
    case missingSessionIdentity
    case outboundEnqueueIncomplete
    case invalidSignature
    case missingSignature
    case configurationError
    case cannotFindCommunication
    case cannotFindContact
    case propsError
    case appPasswordError
    case registrationError
    case userExists
    case cannotFindUserConfiguration
    case cannotFindOneTimeKey
    case oneTimeKeyUploadFailed
    case oneTimeKeyDeletionFailed
    case unknownError
    case missingAuthInfo
    case userNotFound
    case accessDenied
    case userIsBlocked
    case missingMessage
    case missingMetadata
    case invalidDocument
    case receiverDelegateNotSet
    case invalidKeyId
    case drainedKeys
    case longTermKeyRotationFailed
    case signingKeyOutOfSync
    case peerSigningKeyOutOfSync
    case compromiseRotationRequiresMasterDevice
    case invalidOperatorCount
    case invalidMemberCount
    case signingKeyMismatchWithServer
    case deviceIdentityCorrupted
    case encryptionFailed
    case decryptionFailed
}

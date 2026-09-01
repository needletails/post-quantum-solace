//
//  SealedSenderPlaintext.swift
//  post-quantum-solace
//
//  AEAD-protected sealed-sender inner payload: certificate + message bytes.
//  Never placed on the routing envelope.
//

import Foundation

/// Inner plaintext wrapped by the double ratchet when sending a sealed DM.
public struct SealedSenderPlaintext: Codable, Sendable, Equatable {
    public let certificate: SenderCertificate
    public let innerMessage: Data

    public init(certificate: SenderCertificate, innerMessage: Data) {
        self.certificate = certificate
        self.innerMessage = innerMessage
    }
}

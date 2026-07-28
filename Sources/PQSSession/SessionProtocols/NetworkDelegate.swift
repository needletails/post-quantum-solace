//
//  NetworkDelegate.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-14.
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

/**
 * A protocol that defines the interface for network connectivity management
 * in the Post-Quantum Solace session system.
 *
 * The synchronous `isViable` requirement is retained for source compatibility.
 * `PQSSession` additionally exposes an actor-isolated `setViability(_:)` method,
 * without changing this protocol's requirements for existing SDK clients.
 */
public protocol NetworkDelegate: Sendable {
    /**
     * Indicates whether the current network connection is viable for
     * establishing and maintaining secure sessions.
     */
    var isViable: Bool { get set }
}

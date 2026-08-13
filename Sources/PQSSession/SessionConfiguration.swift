//
//  SessionConfiguration.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-01-XX.
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

import SessionEvents

/// Configuration for session initialization.
///
/// Pass this to `PQSSession(configuration:)` to wire transport, store, and
/// observer in one construction path. Hosts typically implement the split
/// protocols on one transport type and one store type.
public struct SessionConfiguration: Sendable {
    public let transport: any PQSNetworkHost
    public let store: any PQSPersistenceHost
    public let observer: any MessageStoreObserver
    public let hostDelegate: (any PQSHostDelegate)?
    public let auditSink: any PQSAuditSink

    public var messagingPolicy: (any MessagingPolicy)? { hostDelegate }
    public var recoveryObserver: (any RecoveryObserver)? { hostDelegate }

    /// Creates a new session configuration.
    ///
    /// - Parameters:
    ///   - transport: Send, key directory, and OOB recovery (often one object).
    ///   - store: Core CRUD and recovery ledgers (often one object).
    ///   - observer: Persist-mutation callbacks.
    ///   - delegate: Optional combined messaging policy and recovery observer.
    ///   - auditSink: Per-session audit sink. Defaults to a new file-backed sink.
    public init(
        transport: any PQSNetworkHost,
        store: any PQSPersistenceHost,
        observer: any MessageStoreObserver,
        delegate: (any PQSHostDelegate)? = nil,
        auditSink: any PQSAuditSink = FilePQSAuditSink()
    ) {
        self.transport = transport
        self.store = store
        self.observer = observer
        self.hostDelegate = delegate
        self.auditSink = auditSink
    }
}

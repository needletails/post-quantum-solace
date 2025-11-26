//
//  Configuration.swift
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

/// Configuration for session initialization
///
/// This struct allows you to configure all required delegates in a single call,
/// simplifying session setup and ensuring all dependencies are properly configured.
/// It's the recommended way to initialize a session, replacing the need for
/// multiple individual delegate setter calls.
///
/// ## Usage
///
/// ```swift
/// let config = SessionConfiguration(
///     transport: myTransport,
///     store: myStore,
///     receiver: myReceiver,
///     delegate: mySessionDelegate,        // Optional
///     eventDelegate: myEventDelegate      // Optional
/// )
///
/// try await session.configure(with: config)
/// ```
///
/// ## Benefits
///
/// - **Simplified Setup**: Configure all delegates in one call
/// - **Type Safety**: Compiler ensures all required delegates are provided
/// - **Clear Intent**: Makes the initialization process explicit and readable
/// - **Reduced Boilerplate**: Eliminates multiple setter calls
///
/// - See also: `PQSSession.configure(with:)`
public struct SessionConfiguration: Sendable {
    /// The transport delegate responsible for network communication
    public let transport: SessionTransport
    
    /// The store delegate responsible for persistent storage
    public let store: PQSSessionStore
    
    /// The receiver delegate for event notifications
    public let receiver: EventReceiver
    
    /// Optional session delegate for application-specific hooks
    public let delegate: PQSSessionDelegate?
    
    /// Optional event delegate for overriding default business logic
    public let eventDelegate: SessionEvents?
    
    /// Creates a new session configuration
    /// 
    /// - Parameters:
    ///   - transport: The transport delegate (required)
    ///   - store: The store delegate (required)
    ///   - receiver: The receiver delegate (required)
    ///   - delegate: Optional session delegate for custom behavior
    ///   - eventDelegate: Optional event delegate for overriding defaults
    public init(
        transport: SessionTransport,
        store: PQSSessionStore,
        receiver: EventReceiver,
        delegate: PQSSessionDelegate? = nil,
        eventDelegate: SessionEvents? = nil
    ) {
        self.transport = transport
        self.store = store
        self.receiver = receiver
        self.delegate = delegate
        self.eventDelegate = eventDelegate
    }
}


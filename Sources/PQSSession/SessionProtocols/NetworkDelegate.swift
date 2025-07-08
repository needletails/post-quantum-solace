//
//  NetworkDelegate.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
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
 * The `NetworkDelegate` protocol provides a standardized way to monitor
 * and report network connectivity status. Implementations of this protocol
 * can be used to determine whether the current network connection is viable
 * for establishing and maintaining secure post-quantum cryptographic sessions.
 *
 * ## Usage
 *
 * Conform to this protocol in your network monitoring classes to provide
 * real-time network status updates to the session management system:
 *
 * ```swift
 * class MyNetworkMonitor: NetworkDelegate {
 *     var isViable: Bool = false
 *
 *     func startMonitoring() {
 *         // Monitor network connectivity
 *         // Update isViable property based on connection status
 *     }
 * }
 * ```
 *
 * ## Thread Safety
 *
 * This protocol conforms to `Sendable`, ensuring thread-safe access
 * to network status information across concurrent operations.
 */
public protocol NetworkDelegate: Sendable {
    /**
     * Indicates whether the current network connection is viable for
     * establishing and maintaining secure sessions.
     *
     * This property should be updated in real-time to reflect the current
     * network connectivity status. A value of `true` indicates that the
     * network is available and suitable for cryptographic operations,
     * while `false` indicates network unavailability or instability.
     *
     * ## Implementation Notes
     *
     * - Set to `true` when network connectivity is established and stable
     * - Set to `false` when network is unavailable, unstable, or disconnected
     * - Should be updated immediately when network status changes
     * - Access to this property must be thread-safe
     */
    var isViable: Bool { get set }
}

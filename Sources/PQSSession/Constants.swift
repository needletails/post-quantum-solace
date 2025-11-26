//
//  Constants.swift
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

/// Constants used throughout the Post-Quantum Solace SDK
///
/// This enum provides centralized configuration values for the SDK, ensuring
/// consistent behavior across all components. All constants are `Sendable` and
/// can be safely accessed from any concurrent context.
///
/// ## Usage
///
/// ```swift
/// // Check if keys need refresh
/// if keyCount < PQSSessionConstants.oneTimeKeyLowWatermark {
///     await refreshKeys()
/// }
///
/// // Generate keys in batches
/// let batchSize = PQSSessionConstants.oneTimeKeyBatchSize
/// ```
///
/// - Note: These values are used internally by the SDK but can also be
///   referenced by applications for custom logic or validation.
public enum PQSSessionConstants: Sendable {
    /// The threshold below which one-time keys are automatically refreshed
    ///
    /// When the number of available keys drops to this value, the system
    /// will automatically generate a new batch of keys. This ensures continuous
    /// communication capability without manual intervention.
    ///
    /// - Default: `10`
    /// - See also: `PQSSession.refreshOneTimeKeysTask()`
    public static let oneTimeKeyLowWatermark = 10
    
    /// The number of one-time keys generated in each batch
    ///
    /// This ensures sufficient keys are available for immediate communication
    /// while balancing storage and generation overhead. Larger values provide
    /// more keys but require more storage and generation time.
    ///
    /// - Default: `100`
    /// - See also: `PQSSessionConstants.oneTimeKeyLowWatermark`
    public static let oneTimeKeyBatchSize = 100
    
    /// The interval (in days) after which MLKEM keys are automatically rotated
    ///
    /// This provides automatic key freshness without manual intervention,
    /// ensuring long-term security even if keys are not actively used.
    ///
    /// - Default: `7` (one week)
    /// - See also: `PQSSession.rotateMLKEMKeysIfNeeded()`
    public static let keyRotationIntervalDays = 7
    
    /// The minimum number of operators required for a channel
    ///
    /// Channels must have at least this many operators to be considered valid.
    /// Operators have elevated permissions compared to regular members.
    ///
    /// - Default: `1`
    /// - See also: `PQSSessionConstants.minimumChannelMembers`
    public static let minimumChannelOperators = 1
    
    /// The minimum number of members required for a channel
    ///
    /// Channels must have at least this many members to be considered valid.
    /// This ensures channels have sufficient participants for meaningful communication.
    ///
    /// - Default: `3`
    /// - See also: `PQSSessionConstants.minimumChannelOperators`
    public static let minimumChannelMembers = 3
}


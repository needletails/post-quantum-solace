//
//  PQSSession+Lifecycle.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-12.
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

import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
import NeedleTailLogger
import SessionEvents
import SessionModels

/// Credential access, password verification/change, job-queue resume,
/// peer bootstrap, and `shutdown`.
extension PQSSession {
    /// Retrieves the symmetric key for database encryption.
    public func getDatabaseSymmetricKey() async throws -> SymmetricKey {
        guard let data = await sessionContext?.databaseEncryptionKey else {
            throw PQSError.sessionNotInitialized
        }
        return SymmetricKey(data: data)
    }

    /// Derives the symmetric key from the application password.
    ///
    /// This key is used to encrypt/decrypt the session context. It's derived from
    /// the application password and device salt using a key derivation function.
    ///
    /// - Returns: The symmetric key derived from the application password
    /// - Throws:
    ///   - `PQSError.invalidPassword` if the password cannot be converted to data
    ///   - `PQSError.saltError` if the device salt cannot be retrieved
    public func getAppSymmetricKey() async throws -> SymmetricKey {
        guard let passwordData = await appPassword.data(using: .utf8) else {
            throw PQSError.invalidPassword
        }

        // Retrieve salt and derive symmetric key
        guard let saltData = try await cache?.fetchLocalDeviceSalt(keyData: passwordData) else { throw PQSError.saltError }

        return await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )
    }

    /// Verifies an input password against stored session context.
    ///
    /// This method attempts to decrypt the stored session context using the provided
    /// password. If decryption succeeds, the password is correct.
    ///
    /// - Parameter appPassword: The password to verify
    /// - Returns: `true` if the password is correct and can decrypt the session context,
    ///            `false` otherwise
    public func verifyAppPassword(_ appPassword: String) async -> Bool {
        do {
            guard let passwordData = appPassword.data(using: .utf8) else {
                throw PQSError.invalidPassword
            }

            guard let saltData = try await cache?.fetchLocalDeviceSalt(keyData: passwordData) else { throw PQSError.saltError }

            let appEncryptionKey = await crypto.deriveStrictSymmetricKey(
                data: passwordData,
                salt: saltData
            )

            await setAppPassword(appPassword)

            guard let data = try await cache?.fetchLocalSessionContext() else { return false }
            let box = try AES.GCM.SealedBox(combined: data)
            _ = try AES.GCM.open(box, using: appEncryptionKey)
            return true
        } catch {
            return false
        }
    }

    /// Changes the application password and re-encrypts the session context.
    ///
    /// This method decrypts the current session context, generates a new device salt,
    /// and re-encrypts the session context with the new password. All session data
    /// remains intact, only the encryption key changes.
    ///
    /// - Parameter newPassword: The new application password
    /// - Throws:
    ///   - `PQSError.databaseNotInitialized` if the cache is not available
    ///   - `PQSError.sessionDecryptionError` if the current session cannot be decrypted
    ///   - `PQSError.appPasswordError` if the new password cannot be converted to data
    ///   - `PQSError.sessionEncryptionError` if the session cannot be re-encrypted
    public func changeAppPassword(_ newPassword: String) async throws {
        guard let cache else {
            throw PQSError.databaseNotInitialized
        }

        let data = try await cache.fetchLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionDecryptionError
        }
        // Decode the session context from the decrypted data
        let sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)
        try await cache.deleteLocalDeviceSalt()

        guard let passwordData = newPassword.data(using: .utf8) else {
            throw PQSError.appPasswordError
        }

        // Retrieve salt and derive symmetric key
        let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)

        let symmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )

        let encodedData = try BinaryEncoder().encode(sessionContext)
        guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: symmetricKey) else {
            throw PQSError.sessionEncryptionError
        }

        await setAppPassword(newPassword)

        // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
        try await cache.updateLocalSessionContext(encryptedConfig)
    }

    /// Resumes processing of any pending tasks in the queue.
    ///
    /// This method loads all pending tasks from the cache and resumes their processing.
    /// Useful after session restoration or when tasks may have been paused.
    ///
    /// - Throws: `PQSError.databaseNotInitialized` if the cache is not available
    public func resumeJobQueue() async throws {
        guard let cache else {
            throw PQSError.databaseNotInitialized
        }
        try await messagePipeline.loadTasks(
            nil,
            cache: cache,
            symmetricKey: getDatabaseSymmetricKey(),
            session: self
        )
    }

    /// Blocks until pending encrypt/send jobs finish (used after OTK bootstrap notify).
    public func waitForOutboundJobDrain(timeout: TimeInterval = 8.0) async {
        guard let cache else { return }
        await messagePipeline.waitForOutboundJobDrain(cache: cache, session: self, timeout: timeout)
    }

    /// Sends OTK notify for a new peer session and waits for outbound encrypt jobs to drain.
    /// Call before the first friendship request so the receiver ratchet is ready.
    /// No-ops when the peer's master device already has initialized outbound ratchet state.
    public func bootstrapPeerContactSession(
        secretName: String,
        purpose: PeerContactBootstrapPurpose = .newOutbound
    ) async throws {
        switch purpose {
        case .newOutbound:
            let needsOutboundBootstrap = try await peerNeedsOutboundBootstrap(secretName)
            let needsHandshakeNotify = !deliveredOneTimeNotifyPeers.contains(secretName)

            guard needsOutboundBootstrap || needsHandshakeNotify else {
                logger.log(
                    level: .info,
                    message: "bootstrapPeerContactSession: outbound ratchet already ready for \(secretName) and OTK notify already delivered this session; skipping")
                return
            }

            if !needsOutboundBootstrap, needsHandshakeNotify {
                logger.log(
                    level: .warning,
                    message: "bootstrapPeerContactSession: local outbound state exists for \(secretName) but OTK notify was not confirmed this session; sending OTK handshake")
            } else {
                logger.log(
                    level: .info,
                    message: "bootstrapPeerContactSession: sending OTK bootstrap for \(secretName)")
            }

            // Master-targeted handshake only. A blanket refresh that notifies every
            // published peer device — including ghost rows left after reinstall —
            // leaves the live master without a usable outbound ratchet (delete→re-add).
            try await preparePeerIdentitiesForOutboundBootstrap(
                secretName: secretName,
                forceHandshakeReplay: !needsOutboundBootstrap && needsHandshakeNotify)

            guard let peerDevice = try await peerMasterDevice(for: secretName) else {
                throw PQSError.missingSessionIdentity
            }

            if try await !peerCanSupplyX25519OneTimeKey(
                secretName: secretName,
                deviceId: peerDevice.deviceId) {
                try await repairPeerPublishedOneTimeKeysIfPossible(
                    secretName: secretName,
                    deviceId: peerDevice.deviceId)
            }

            guard try await peerCanSupplyX25519OneTimeKey(
                secretName: secretName,
                deviceId: peerDevice.deviceId) else {
                logger.log(
                    level: .warning,
                    message: "bootstrapPeerContactSession: peer \(secretName) has no published curve OTK for outbound bootstrap")
                throw PQSError.cannotFindOneTimeKey
            }

            guard try await deliverPeerHandshakeNotifyBeforeOutboundSenderInit(secretName: secretName) else {
                throw PQSError.missingSessionIdentity
            }
            await waitForOutboundJobDrain()
            // Do not force-refresh after the handshake: a second refresh can recreate
            // ghost device rows and race the just-initialized master outbound ratchet.
            if try await peerNeedsOutboundBootstrap(secretName) {
                _ = try await refreshIdentities(
                    secretName: secretName,
                    createIdentity: true,
                    forceRefresh: true,
                    sendOneTimeIdentities: false)
                await waitForOutboundJobDrain()
            }

        case .friendshipReply:
            guard try await peerCanAcceptFriendship(secretName) else {
                logger.log(
                    level: .warning,
                    message: "bootstrapPeerContactSession: refusing accept bootstrap for \(secretName); inbound friendship not confirmed and no live inbound ratchet")
                throw PQSError.cannotFindOneTimeKey
            }

            // After a live inbound request decrypt, this device often already has an
            // outbound ratchet (e.g. contactCreated / sibling sync). Resetting and
            // sending a fresh OTK here races the peer's existing inbound state and
            // surfaces as `maxSkippedHeadersExceeded` on the accept packet — the
            // peer never applies `.accepted`. Reuse the live lane when present.
            if try await !peerNeedsOutboundBootstrap(secretName) {
                logger.log(
                    level: .info,
                    message: "bootstrapPeerContactSession: outbound ratchet already ready for \(secretName); skipping fresh OTK reply lane before friendship accept")
                return
            }

            logger.log(
                level: .info,
                message: "bootstrapPeerContactSession: establishing fresh OTK reply lane for \(secretName) before friendship accept")
            deliveredOneTimeNotifyPeers.remove(secretName)

            guard let peerDevice = try await peerMasterDevice(for: secretName) else {
                throw PQSError.missingSessionIdentity
            }

            if try await !peerCanSupplyX25519OneTimeKey(
                secretName: secretName,
                deviceId: peerDevice.deviceId) {
                try await repairPeerPublishedOneTimeKeysIfPossible(
                    secretName: secretName,
                    deviceId: peerDevice.deviceId)
            }

            guard try await peerCanSupplyX25519OneTimeKey(
                secretName: secretName,
                deviceId: peerDevice.deviceId) else {
                logger.log(
                    level: .warning,
                    message: "bootstrapPeerContactSession: peer \(secretName) has no published curve OTK for accept bootstrap")
                throw PQSError.cannotFindOneTimeKey
            }

            try await preparePeerIdentitiesForFriendshipReply(secretName: secretName)
            guard try await deliverPeerHandshakeNotifyBeforeOutboundSenderInit(secretName: secretName) else {
                throw PQSError.missingSessionIdentity
            }
            await waitForOutboundJobDrain()
            _ = try await refreshIdentities(
                secretName: secretName,
                createIdentity: true,
                forceRefresh: true,
                sendOneTimeIdentities: false)
            await waitForOutboundJobDrain()
        }

        guard try await hasInitializedOutboundRatchetForPeer(secretName) else {
            deliveredOneTimeNotifyPeers.remove(secretName)
            logger.log(
                level: .warning,
                message: "bootstrapPeerContactSession: outbound ratchet still not ready for \(secretName) after OTK drain")
            if let peerDevice = try await peerMasterDevice(for: secretName),
               try await !peerCanSupplyX25519OneTimeKey(
                secretName: secretName,
                deviceId: peerDevice.deviceId) {
                throw PQSError.cannotFindOneTimeKey
            }
            throw PQSError.missingSessionIdentity
        }

        deliveredOneTimeNotifyPeers.insert(secretName)
        logger.log(
            level: .info,
            message: "bootstrapPeerContactSession: OTK notify delivered and outbound job drain finished for \(secretName)")
    }

    /// Shuts down the session, clearing sensitive state.
    ///
    /// This method performs a complete shutdown of the session, including:
    /// - Shutting down the ratchet manager
    /// - Clearing all delegates
    /// - Resetting session state
    /// - Clearing sensitive data from memory
    ///
    /// After shutdown, the session is no longer viable and must be reconfigured
    /// with its delegates before use. All cached data remains in persistent
    /// storage. A successful ``unlock(appPassword:)`` replaces the terminal
    /// task processor/ratchet manager, reopens the session work lifecycle, and
    /// resumes durable jobs when transport viability permits.
    ///
    /// - Important: This method clears sensitive data from memory. Ensure all
    ///   operations are complete before calling this method.
    public func shutdown() async {
        // Close admission before the first suspension so scheduling cannot
        // recreate workers while teardown awaits cancellation.
        switch lifecyclePhase {
        case .shuttingDown, .shutDown:
            return
        case .idle, .running:
            lifecyclePhase = .shuttingDown
        }
        isViable = false
        jobQueueResumeCoalesced = false
        resumeAllPeerOneTimeReplenishWaiters()
        await cancelSessionWorkTree()
        await messagePipeline.prepareForShutdown()
        let x25519RefreshTask = refreshOTKeysTask
        let mlKEMRefreshTask = refreshMLKEMOTKeysTask
        let batchReplacementTask = otkBatchReplacementPairTask
        refreshOTKeysTask = nil
        refreshMLKEMOTKeysTask = nil
        otkBatchReplacementPairTask = nil
        x25519RefreshTask?.cancel()
        mlKEMRefreshTask?.cancel()
        batchReplacementTask?.cancel()
        _ = await x25519RefreshTask?.value
        _ = await mlKEMRefreshTask?.value
        _ = await batchReplacementTask?.value
        await messagePipeline.cancelBackgroundKeyTasks()
        do {
            try await messagePipeline.ratchetManager.flushAndClose()
        } catch {
            // Teardown can race with in-flight session cleanup; do not crash the app.
            logger.log(level: .warning, message: "Ratchet manager shutdown encountered non-fatal error: \(error)")
        }
        cache = nil
        transportDelegate = nil
        receiverDelegate = nil
        sessionDelegate = nil
        eventDelegate = nil
        linkDelegate = nil
        _sessionContext = nil
        _appPassword = ""
        await setDatabaseDelegate(conformer: nil)
        await setTransportDelegate(conformer: nil)
        setReceiverDelegate(conformer: nil)
        await setPQSSessionDelegate(conformer: nil)
        await setSessionEventDelegate(conformer: nil)
        sessionIdentities.removeAll()
        deliveredOneTimeNotifyPeers.removeAll()
        peerInboundFriendshipConfirmedPeers.removeAll()
        lastPeerOneTimeRefreshRequestAt.removeAll()
        peerOneTimeReplenishAcknowledgedPeers.removeAll()
        senderControlEpisodes.removeAll()
        senderControlEpochCounters.removeAll()
        processedControlEvents.removeAll()
        lastForcedIdentityRefresh.removeAll()
        otkUploadCircuitOpen = false
        otkUploadCircuitOpenedAt = nil
        lastReconciliationAtByPeer.removeAll()
        lastAutomaticRotationAtByPeer.removeAll()
        lastAutomaticRotationAt = nil
        lifecyclePhase = .shutDown
    }

    func resumePeerOneTimeReplenishWaiters(secretName: String) {
        let keys = peerOneTimeReplenishWaiters.keys.filter { $0.secretName == secretName }
        for key in keys {
            if let bucket = peerOneTimeReplenishWaiters.removeValue(forKey: key) {
                for (_, waiter) in bucket {
                    waiter.resume()
                }
            }
        }
    }

    private func resumeAllPeerOneTimeReplenishWaiters() {
        let buckets = peerOneTimeReplenishWaiters
        peerOneTimeReplenishWaiters.removeAll()
        for (_, bucket) in buckets {
            for (_, waiter) in bucket {
                waiter.resume()
            }
        }
    }

    /// Returns a human-readable device name for the current platform
    ///
    /// On iOS and macOS, this returns a friendly device name (e.g., "iPhone 15 Pro")
    /// by mapping model identifiers to readable names. On other platforms, it returns
    /// a generic identifier.
    ///
    /// - Returns: A string representing the device name
    public func getDeviceName() -> String {
        #if os(iOS) || os(macOS)
            let modelIdentifier = getModelIdentifier()

            // Mapping of model identifiers to friendly names
            let deviceNames: [String: String] = [
                // iPhones
                "iPhone11,2": "iPhone XS",
                "iPhone11,4": "iPhone XS Max",
                "iPhone11,6": "iPhone XS Max Global",
                "iPhone11,8": "iPhone XR",
                "iPhone12,1": "iPhone 11",
                "iPhone12,3": "iPhone 11 Pro",
                "iPhone12,5": "iPhone 11 Pro Max",
                "iPhone12,8": "iPhone SE 2nd Gen",
                "iPhone13,1": "iPhone 12 Mini",
                "iPhone13,2": "iPhone 12",
                "iPhone13,3": "iPhone 12 Pro",
                "iPhone13,4": "iPhone 12 Pro Max",
                "iPhone14,2": "iPhone 13 Pro",
                "iPhone14,3": "iPhone 13 Pro Max",
                "iPhone14,4": "iPhone 13 Mini",
                "iPhone14,5": "iPhone 13",
                "iPhone14,6": "iPhone SE 3rd Gen",
                "iPhone14,7": "iPhone 14",
                "iPhone14,8": "iPhone 14 Plus",
                "iPhone15,2": "iPhone 14 Pro",
                "iPhone15,3": "iPhone 14 Pro Max",
                "iPhone15,4": "iPhone 15",
                "iPhone15,5": "iPhone 15 Plus",
                "iPhone16,1": "iPhone 15 Pro",
                "iPhone16,2": "iPhone 15 Pro Max",
                "iPhone17,1": "iPhone 16 Pro",
                "iPhone17,2": "iPhone 16 Pro Max",
                "iPhone17,3": "iPhone 16",
                "iPhone17,4": "iPhone 16 Plus",

                // iPads
                "iPad11,1": "iPad mini 5th Gen (WiFi)",
                "iPad11,2": "iPad mini 5th Gen (WiFi+Cellular)",
                "iPad11,3": "iPad Air 3rd Gen (WiFi)",
                "iPad11,4": "iPad Air 3rd Gen (WiFi+Cellular)",
                "iPad11,6": "iPad 8th Gen (WiFi)",
                "iPad11,7": "iPad 8th Gen (WiFi+Cellular)",
                "iPad12,1": "iPad 9th Gen (WiFi)",
                "iPad12,2": "iPad 9th Gen (WiFi+Cellular)",
                "iPad14,1": "iPad mini 6th Gen (WiFi)",
                "iPad14,2": "iPad mini 6th Gen (WiFi+Cellular)",
                "iPad13,1": "iPad Air 4th Gen (WiFi)",
                "iPad13,2": "iPad Air 4th Gen (WiFi+Cellular)",
                "iPad13,4": "iPad Pro 11 inch 5th Gen",
                "iPad13,5": "iPad Pro 11 inch 5th Gen",
                "iPad13,6": "iPad Pro 11 inch 5th Gen",
                "iPad13,7": "iPad Pro 11 inch 5th Gen",
                "iPad13,8": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,9": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,10": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,11": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,16": "iPad Air 5th Gen (WiFi)",
                "iPad13,17": "iPad Air 5th Gen (WiFi+Cellular)",
                "iPad13,18": "iPad 10th Gen",
                "iPad13,19": "iPad 10th Gen",
                "iPad14,3": "iPad Pro 11 inch 4th Gen",
                "iPad14,4": "iPad Pro 11 inch 4th Gen",
                "iPad14,5": "iPad Pro 12.9 inch 6th Gen",
                "iPad14,6": "iPad Pro 12.9 inch 6th Gen",
                "iPad14,8": "iPad Air 6th Gen",
                "iPad14,9": "iPad Air 6th Gen",
                "iPad14,10": "iPad Air 7th Gen",
                "iPad14,11": "iPad Air 7th Gen",
                "iPad16,1": "iPad mini 7th Gen (WiFi)",
                "iPad16,2": "iPad mini 7th Gen (WiFi+Cellular)",
                "iPad16,3": "iPad Pro 11 inch 5th Gen",
                "iPad16,4": "iPad Pro 11 inch 5th Gen",
                "iPad16,5": "iPad Pro 12.9 inch 7th Gen",
                "iPad16,6": "iPad Pro 12.9 inch 7th Gen",

                // Macs
                // iMac (2019 and later)
                "iMac19,1": "iMac (2019)",
                "iMac19,2": "iMac (2019)",
                "iMac20,1": "iMac (2020)",
                "iMac21,1": "iMac (2021)",
                "iMac21,2": "iMac 24-inch (M1, 2021)",
                "iMac22,1": "iMac 24-inch (M3, 2024)",
                "iMac22,2": "iMac 24-inch (M3, 2024)",

                // iMac Pro
                "iMacPro1,1": "iMac Pro (2017)",

                // MacBook Air (2020 and later)
                "MacBookAir8,1": "MacBook Air (Retina, 2018)",
                "MacBookAir9,1": "MacBook Air (M1, 2020)",
                "Mac14,2": "MacBook Air (M2, 2022)",
                "Mac14,7": "MacBook Air (M3, 2023)",
                "Mac15,1": "MacBook Air (M4, 2024)",

                // MacBook Pro (2017 and later)
                "MacBookPro14,1": "MacBook Pro (2017)",
                "MacBookPro14,3": "MacBook Pro (2017)",
                "MacBookPro15,1": "MacBook Pro (2019)",
                "MacBookPro15,2": "MacBook Pro (2019)",
                "MacBookPro15,3": "MacBook Pro (2019)",
                "MacBookPro15,4": "MacBook Pro (2019)",
                "MacBookPro16,1": "MacBook Pro (2021)",
                "MacBookPro16,2": "MacBook Pro (2021)",
                "MacBookPro16,3": "MacBook Pro (2021)",
                "MacBookPro16,4": "MacBook Pro (2021)",
                "MacBookPro17,1": "MacBook Pro (2021)",
                "MacBookPro18,1": "MacBook Pro (2021)",
                "MacBookPro18,2": "MacBook Pro (M1, 2020)",
                "MacBookPro18,3": "MacBook Pro (2021)",
                "MacBookPro18,4": "MacBook Pro (2021)",
                "Mac14,5": "MacBook Pro (M2, 2022)",
                "Mac14,6": "MacBook Pro (M2, 2022)",
                "Mac14,8": "MacBook Air/Pro (M2, 2023)",
                "Mac14,9": "MacBook Pro (M2, 2023)",
                "Mac14,10": "MacBook Pro (M3, 2023)",
                "Mac14,11": "MacBook Pro (M3, 2023)",
                "Mac14,13": "MacBook Pro (M3, 2023)",
                "Mac14,14": "MacBook Pro (M3, 2023)",
                "Mac14,15": "MacBook Pro (M3, 2023)",
                "Mac15,2": "MacBook Pro (M4, 2024)",
                "Mac15,3": "MacBook Pro (M4, 2024)",
                "Mac15,4": "MacBook Pro (M4, 2024)",
                "Mac15,5": "MacBook Pro (M4, 2024)",
                "Mac15,6": "MacBook Pro (M4, 2024)",
                "Mac15,7": "MacBook Pro (M4, 2024)",
                "Mac16,1": "MacBook Pro (M4 Pro, 2024)",
                "Mac16,2": "MacBook Pro (M4 Pro, 2024)",
                "Mac16,3": "MacBook Pro (M4 Pro, 2024)",
                "Mac16,4": "MacBook Pro (M4 Pro, 2024)",
                "Mac16,5": "MacBook Pro (M4 Max, 2024)",
                "Mac16,6": "MacBook Pro (M4 Max, 2024)",
                "Mac16,7": "MacBook Pro (M4 Max, 2024)",
                "Mac16,8": "MacBook Pro (M4 Max, 2024)",

                // Mac Pro (2019 and later)
                "MacPro7,1": "Mac Pro (2019)",
                "Mac14,1": "Mac Pro (M2 Ultra, 2023)",

                // Mac Studio (2022 and later)
                "Mac13,1": "Mac Studio (M1 Max, 2022)",
                "Mac13,2": "Mac Studio (M1 Ultra, 2022)",
                "Mac14,3": "Mac Studio (M2 Max, 2023)",
                "Mac14,16": "Mac Studio (M2 Ultra, 2023)",
                "Mac15,8": "Mac Studio (M4, 2024)",
                "Mac15,9": "Mac Studio (M4, 2024)",
                "Mac15,10": "Mac Studio (M4, 2024)",
                "Mac15,11": "Mac Studio (M4, 2024)",

                // Mac mini (2018 and later)
                "Macmini8,1": "Mac mini (2018)",
                "Macmini9,1": "Mac mini (M1, 2020)",
                "Mac14,4": "Mac mini (M2, 2022)",
                "Mac14,12": "Mac mini (M2 Pro, 2023)",
            ]

            return deviceNames[modelIdentifier] ?? modelIdentifier
        #else
            return "Unknown Device"
        #endif
    }

    #if os(iOS)
        private func getModelIdentifier() -> String {
            var systemInfo = utsname()
            uname(&systemInfo)

            // Use Mirror to access the machine field and convert it to a String
            let machineMirror = Mirror(reflecting: systemInfo.machine)
            let identifier = machineMirror.children.reduce("") { identifier, element in
                guard let value = element.value as? Int8, value != 0 else { return identifier }
                return identifier + String(UnicodeScalar(UInt8(value)))
            }

            return identifier
        }

    #elseif os(macOS)
        private func getModelIdentifier() -> String {
            var size = 0
            sysctlbyname("hw.model", nil, &size, nil, 0)

            var model = [CChar](repeating: 0, count: size)
            sysctlbyname("hw.model", &model, &size, nil, 0)

            let data = Data(bytes: model, count: size)
            return String(data: data, encoding: .utf8) ?? "Unknown Model"
        }

    #endif
}

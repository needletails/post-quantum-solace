//
//  SessionCache.swift
//  needletail-crypto
//
//  Created by Cole M on 9/15/24.
//
import Foundation
import BSON
import NeedleTailHelpers
import NeedleTailCrypto
import DoubleRatchetKit

/// A protocol defining the requirements for a cache synchronizer.
protocol SessionCacheSynchronizer {
    func synchronizeLocalConfiguration(_ data: Data)
}

actor SessionCache: CryptoSessionStore {
    func fetchContacts() async throws -> [ContactModel] {
        []
    }
    
    func createContact(_ contact: ContactModel) async throws {
        
    }
    
    func updateContact(_ contact: ContactModel) async throws {
        
    }
    
    func removeContact(_ contact: ContactModel) async throws {
        
    }
    
    func fetchCommunicationTypes() async throws -> [CommunicationModel] {
        []
    }
    
    func createCommunicationType(_ type: CommunicationModel) async throws {
        
    }
    
    func updateCommunicationType(_ type: CommunicationModel) async throws {
        
    }
    
    func removeCommunicationType(_ type: CommunicationModel) async throws {
        
    }
    
    
    let crypto = NeedleTailCrypto()
    
    enum CacheErrors: Error {
        case localDeviceConfigurationIsNil
        case localDeviceSaltIsNil
    }
    
    let store: CryptoSessionStore
    private var sessionIdentities = [SessionIdentityModel]()
    private var messages = [MessageModel]()
    private var localDeviceConfiguration: Data? {
        didSet {
            if let localDeviceConfiguration = localDeviceConfiguration {
                synchronizer?.synchronizeLocalConfiguration(localDeviceConfiguration)
            }
        }
    }
    private var localDeviceSalt: String?
    var synchronizer: SessionCacheSynchronizer?
    
    init(store: CryptoSessionStore) {
        self.store = store
    }
    
    // Create a local device configuration and cache it
    func createLocalDeviceConfiguration(_ data: Data) async throws {
        try await store.createLocalDeviceConfiguration(data)
        localDeviceConfiguration = data // Cache the data directly
    }
    
    // Protocol method to find the local device configuration
    func findLocalDeviceConfiguration() async throws -> Data {
        if let cachedConfig = localDeviceConfiguration {
            return cachedConfig
        }
        localDeviceConfiguration = try await store.findLocalDeviceConfiguration()
        guard let config = localDeviceConfiguration else {
            throw CacheErrors.localDeviceConfigurationIsNil
        }
        return config
    }
    
    // Protocol method to find the local device salt
    func findLocalDeviceSalt() async throws -> String {
        if let cachedSalt = localDeviceSalt {
            return cachedSalt
        }
        localDeviceSalt = try await store.findLocalDeviceSalt()
        guard let salt = localDeviceSalt else {
            throw CacheErrors.localDeviceSaltIsNil
        }
        return salt
    }
    
    // Update the local device configuration and refresh the cache
    func updateLocalDeviceConfiguration(_ data: Data) async throws {
        try await store.updateLocalDeviceConfiguration(data)
        localDeviceConfiguration = data // Cache the updated data directly
    }
    
    // Delete the local device configuration and clear the cache
    func deleteLocalDeviceConfiguration() async throws {
        try await store.deleteLocalDeviceConfiguration()
        localDeviceConfiguration = nil
    }
    
    
    func createSessionIdentity(_ session: SessionIdentityModel) async throws {
        try await store.createSessionIdentity(session)
        sessionIdentities.append(session)
    }
    
    func fetchSessionIdentities() async throws -> [SessionIdentityModel] {
        let identities = try await store.fetchSessionIdentities()
        sessionIdentities.removeAll(keepingCapacity: true)
        sessionIdentities.append(contentsOf: identities)
        return sessionIdentities
    }
    
    func updateSessionIdentity(_ session: SessionIdentityModel) async throws {
        if let index = sessionIdentities.firstIndex(where: { $0.id == session.id }) {
            sessionIdentities[index] = session
            try await store.updateSessionIdentity(session)
            _ = try await fetchSessionIdentities()
        }
    }
    
    func removeSessionIdentity(_ session: SessionIdentityModel) async throws {
        sessionIdentities.removeAll(where: { $0.id == session.id })
        try await store.removeSessionIdentity(session)
        _ = try await fetchSessionIdentities()
    }
    
    
    func fetchMessage(byId messageId: UUID) async throws -> MessageModel {
        messages.first!
    }
    
    func fetchMessage(by sharedMessageId: String) async throws -> MessageModel {
        messages.first!
    }
    
    func createMessage(_ message: MessageModel) async throws {
        
    }
    
    func updateMessage(_ message: MessageModel) async throws {
        
    }
    
    func removeMessage(_ message: MessageModel) async throws {
        
    }
    
    func listMessages(
        in communication: UUID,
        senderId: Int,
        minimumOrder: Int?,
        maximumOrder: Int?,
        offsetBy: Int,
        limit: Int
    ) async throws -> [MessageModel] {
        messages
    }
    
    func readJobs() async throws -> [JobModel] {
        []
    }
    func createJob(_ job: JobModel) async throws {
        
    }
    func updateJob(_ job: JobModel) async throws {
        
    }
    func removeJob(_ job: JobModel) async throws {
        
    }
    
    // Refresh the entire cache
    func refreshCache() async throws {
        localDeviceConfiguration = try await findLocalDeviceConfiguration()
        localDeviceSalt = try await findLocalDeviceSalt()
    }
    
    // Clear the cache
    func dumpCache() {
        localDeviceConfiguration = nil
        localDeviceSalt = nil
    }
    
}

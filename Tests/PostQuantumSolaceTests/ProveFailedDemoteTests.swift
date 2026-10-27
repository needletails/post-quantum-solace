//
//  ProveFailedDemoteTests.swift
//  post-quantum-solace
//
//  A receiver never forks a lane. Demoting a prove-failed active must leave the
//  peer device at least one initialized lane for outbound; otherwise the next send
//  initiates on a blank, burns a one-time key, and the peer sees a second session
//  (dogfood 2026-10-27: 45FFCDA7 → blank D5E9A14E → stateLessPersonalOutboundRefresh).
//

import Foundation
import Testing
@testable import PQSSession

extension EndToEndTests {
    private struct ActiveLane {
        let identity: SessionIdentity
        let props: SessionIdentity.UnwrappedProps
    }

    private func setUpAliceBob() async throws -> (bob: String, bobDeviceId: UUID) {
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceDelegate = SessionDelegate(session: _senderSession)
        let bobDelegate = SessionDelegate(session: _recipientSession)

        try await createSenderSession(
            store: createSenderStore(),
            transport: aliceTransport,
            sessionDelegate: aliceDelegate)
        try await createRecipientSession(
            store: createRecipientStore(),
            transport: bobTransport,
            sessionDelegate: bobDelegate)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: aliceDelegate,
            bobSession: _recipientSession,
            rsd: bobDelegate)

        let bobDeviceId = try #require(
            await _recipientSession.sessionContext?.sessionUser.deviceId)
        return (rMockUserData.rsn, bobDeviceId)
    }

    private func aliceActiveLanes(toward secretName: String, deviceId: UUID) async throws -> [ActiveLane] {
        let symmetricKey = try await _senderSession.getDatabaseSymmetricKey()
        var lanes: [ActiveLane] = []
        for identity in try await _senderSession.cache?.fetchSessionIdentities() ?? [] {
            guard let props = await identity.props(symmetricKey: symmetricKey),
                  props.secretName == secretName,
                  props.deviceId == deviceId,
                  !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            else { continue }
            lanes.append(ActiveLane(identity: identity, props: props))
        }
        return lanes
    }

    @Test("a prove-failed demote keeps the device's last initialized lane")
    func proveFailedDemoteKeepsLastInitializedLane() async throws {
        defer { Task { await shutdownSessions() } }
        let (bob, bobDeviceId) = try await setUpAliceBob()

        let before = try await aliceActiveLanes(toward: bob, deviceId: bobDeviceId)
        let initialized = before.filter { $0.props.hasRatchetState }
        let lane = try #require(initialized.first)
        #expect(initialized.count == 1)

        let demoted = try await _senderSession.demoteProveFailedActive(
            sessionId: lane.identity.id,
            secretName: bob,
            deviceId: bobDeviceId)

        #expect(!demoted, "the only initialized lane must stay active for outbound")
        let after = try await aliceActiveLanes(toward: bob, deviceId: bobDeviceId)
        #expect(after.contains { $0.identity.id == lane.identity.id && $0.props.hasRatchetState })
    }

    @Test("a prove-failed demote proceeds when another initialized lane remains")
    func proveFailedDemoteProceedsWithAnotherInitializedLane() async throws {
        defer { Task { await shutdownSessions() } }
        let (bob, bobDeviceId) = try await setUpAliceBob()

        let before = try await aliceActiveLanes(toward: bob, deviceId: bobDeviceId)
        let initialized = before.filter { $0.props.hasRatchetState }
        let lane = try #require(initialized.first)
        // A second initialized active for the same device, as a crossing
        // initiation leaves behind.
        let symmetricKey = try await _senderSession.getDatabaseSymmetricKey()
        let twin = try SessionIdentity(id: UUID(), props: lane.props, symmetricKey: symmetricKey)
        try await _senderSession.cache?.createSessionIdentity(twin)

        let demoted = try await _senderSession.demoteProveFailedActive(
            sessionId: lane.identity.id,
            secretName: bob,
            deviceId: bobDeviceId)

        #expect(demoted)
        let after = try await aliceActiveLanes(toward: bob, deviceId: bobDeviceId)
        #expect(!after.contains { $0.identity.id == lane.identity.id })
        #expect(after.contains { $0.identity.id == twin.id && $0.props.hasRatchetState })
    }
}

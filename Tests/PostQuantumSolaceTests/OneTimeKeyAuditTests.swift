//
//  OneTimeKeyAuditTests.swift
//  post-quantum-solace
//
//  Every one-time-key batch outcome must reach the audit channel: the 2026-10-28
//  dogfood logs chose replaceOTKBatchThenPeerRefresh five times and no line showed
//  whether any of them finished.
//

import DoubleRatchetKit
import Foundation
import SessionModels
import Testing

@testable import PQSSession

extension TaskProcessorSequenceTests {
    private func startAuditedSession() async throws -> RecordingAuditSink {
        let sink = RecordingAuditSink()
        let identityStore = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        session = await PQSSession(configuration: SessionConfiguration(
            transport: transport,
            store: identityStore,
            observer: senderReceiver,
            auditSink: sink))
        try await createSenderSession(store: identityStore)
        return sink
    }

    private func publishedKeyIds(_ kind: KeyKind) async throws -> [UUID] {
        let context = try #require(await session.sessionContext)
        let deviceId = context.sessionUser.deviceId
        switch kind {
        case .x25519:
            return context.activeUserConfiguration.signedOneTimePublicKeys.filter { $0.deviceId == deviceId }.map(\.id)
        case .mlKEM:
            return context.activeUserConfiguration.signedMLKEMOneTimePublicKeys.filter { $0.deviceId == deviceId }.map(\.id)
        }
    }

    @Test("a committed recovery replacement audits one batchReplaced line per kind")
    func recoveryReplacementAuditsEachKind() async throws {
        let sink = try await startAuditedSession()

        #expect(await session.replacePublishedOneTimeKeyBatchesForRecovery())

        for kind in [KeyKind.x25519, .mlKEM] {
            let lines = sink.lines(containing: "pqs.otk.batchReplaced kind=\(kind) ")
            #expect(lines.count == 1)
            let ids = try await publishedKeyIds(kind)
            let line = try #require(lines.first)
            #expect(line.contains("policy=replacePublishedBatch"))
            #expect(line.contains("count=\(ids.count)"))
            #expect(line.contains("firstId=\(try #require(ids.first).uuidString)"))
            #expect(line.contains("lastId=\(try #require(ids.last).uuidString)"))
            #expect(line.contains("retainedPrivates="))
        }
        await session.shutdown()
    }

    @Test("a routine replenish audits its batch at the commit")
    func routineReplenishAuditsBatch() async throws {
        let sink = try await startAuditedSession()
        let context = try #require(await session.sessionContext)
        let deviceId = context.sessionUser.deviceId.uuidString
        for kind in [KeyKind.x25519, .mlKEM] {
            try await transport.batchDeleteOneTimeKeys(for: "alice", with: deviceId, type: kind)
        }

        #expect(await session.refreshOneTimeKeysTask())
        #expect(await session.refreshMLKEMOneTimeKeysTask())

        for kind in [KeyKind.x25519, .mlKEM] {
            let line = try #require(sink.lines(containing: "pqs.otk.batchReplaced kind=\(kind) ").first)
            #expect(line.contains("policy=automatic"))
            #expect(line.contains("lastId=\(try #require(try await publishedKeyIds(kind).last).uuidString)"))
        }
        await session.shutdown()
    }

    @Test("a failed upload audits its stage and the retry audits its batch")
    func failedUploadAuditsStage() async throws {
        let sink = try await startAuditedSession()
        await transport.setOTKUploadFailCount(1)

        #expect(await session.refreshOneTimeKeysTask(policy: .replacePublishedBatch))

        #expect(sink.lines(containing: "pqs.otk.batchReplaceFailed kind=x25519 stage=upload").count == 1)
        #expect(sink.lines(containing: "pqs.otk.batchReplaced kind=x25519 ").count == 1)
        await session.shutdown()
    }

    @Test("a failed upload's error field carries the code, never the request URL")
    func failedUploadErrorOmitsTheRequestURL() async throws {
        let sink = try await startAuditedSession()
        // The key routes carry the account's secret name, and URLSession puts the
        // whole URL in the error's userInfo.
        let url = "https://server.example/api/auth/one-time-keys/a/alice_secretname/\(UUID().uuidString)"
        await transport.setOTKUploadFailCount(1, error: URLError(.timedOut, userInfo: [
            NSURLErrorFailingURLStringErrorKey: url,
            NSURLErrorFailingURLErrorKey: try #require(URL(string: url)),
        ]))

        _ = await session.refreshOneTimeKeysTask(policy: .replacePublishedBatch)

        let line = try #require(sink.lines(containing: "pqs.otk.batchReplaceFailed kind=x25519 stage=upload").first)
        #expect(!line.contains("alice_secretname"))
        #expect(!line.contains("https://"))
        #expect(line.contains("error=NSURLErrorDomain:-1001"))
        await session.shutdown()
    }

    @Test("an open circuit audits the skip for each kind")
    func openCircuitAuditsSkip() async throws {
        let sink = try await startAuditedSession()
        await session.setOTKBreakerForTesting(open: true)

        #expect(await session.replacePublishedOneTimeKeyBatchesForRecovery() == false)

        #expect(sink.contains("pqs.otk.batchReplaceSkipped kind=x25519 reason=circuitOpen remainingS="))
        #expect(sink.contains("pqs.otk.batchReplaceSkipped kind=mlKEM reason=circuitOpen remainingS="))
        await session.shutdown()
    }

    @Test("an incomplete recovery replacement reaches the audit channel")
    func incompleteRecoveryReplacementIsAudited() async throws {
        let sink = try await startAuditedSession()
        await session.messagePipeline.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.missingOneTimeKey))
        await transport.setOTKUploadFailCount(2, error: PQSError.sessionEncryptionError)

        try await session.messagePipeline.enqueue(
            EncryptableTask(task: .streamMessage(try makeTestInboundTaskMessage(
                senderSecretName: UUID().uuidString,
                senderDeviceId: UUID(),
                sharedMessageId: "incomplete_1"))),
            session: session)

        #expect(try await waitUntil(timeout: 10) {
            sink.contains("pqs.recovery.otkBatchReplacementIncomplete")
        })
        #expect(sink.contains("pqs.otk.batchReplaceFailed kind=x25519 stage=upload"))
        #expect(sink.contains("pqs.otk.batchReplaceFailed kind=mlKEM stage=upload"))
        await session.shutdown()
    }

    @Test("a recovery cancelled during replacement audits that no peerRefresh follows")
    func cancelledRecoveryReplacementIsAudited() async throws {
        let sink = try await startAuditedSession()
        await session.messagePipeline.setTaskDelegate(
            MockTaskDelegateWithStreamError(error: RatchetError.missingOneTimeKey))
        let uploadPause = OTKUploadPause()
        transport.beforeUpdateOneTimeKeys = { await uploadPause.beforeFirstUpload() }
        defer { transport.beforeUpdateOneTimeKeys = nil }

        try await session.messagePipeline.enqueue(
            EncryptableTask(task: .streamMessage(try makeTestInboundTaskMessage(
                senderSecretName: UUID().uuidString,
                senderDeviceId: UUID(),
                sharedMessageId: "cancelled_1"))),
            session: session)
        #expect(try await waitUntil(timeout: 15) { await uploadPause.isPaused() })

        // Shutdown cancels the session work tree while the replacement is in flight.
        let shuttingDown = session
        let shutdown = Task { await shuttingDown.shutdown() }
        #expect(try await waitUntil(timeout: 5) { await shuttingDown.lifecyclePhase == .shuttingDown })
        try await Task.sleep(for: .milliseconds(200))
        await uploadPause.release()
        await shutdown.value

        #expect(sink.contains("pqs.recovery.otkBatchReplacementCancelled"))
        #expect(sink.contains("proceeding=noPeerRefresh"))
    }
}

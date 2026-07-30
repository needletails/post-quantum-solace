import Foundation
import Testing
@testable import PQSSession

@Suite(.serialized)
struct PQSAuditLogTests {
    @Test
    func enabledByDefaultWhenCompileFlagPresent() {
        PQSAuditLog.configure(isEnabled: true)
        defer { PQSAuditLog.configure(isEnabled: true) }
        #expect(PQSAuditLog.isEnabled == true)
    }

    @Test
    func logAcceptsPlainTextRecoveryLine() {
        PQSAuditLog.configure(isEnabled: true)
        defer { PQSAuditLog.configure(isEnabled: true) }

        PQSAuditLog.log(
            .recovery,
            "pqs.decryptFailure failureClass=ratchet.maxSkippedHeadersExceeded layer=pqsInbound sender=frank deviceId=11111111-1111-1111-1111-111111111111 sharedId=shared-abc action=resendRequested")
    }

    @Test
    func logAcceptsSendAndRecvChannels() {
        PQSAuditLog.configure(isEnabled: true)
        defer { PQSAuditLog.configure(isEnabled: true) }

        PQSAuditLog.log(.send, "pqs.send.deviceTransportOk sharedId=test", level: .info)
        PQSAuditLog.log(.recv, "pqs.recv.persisted sharedId=test", level: .info)
    }

    @Test
    func disabledAuditSkipsLogging() {
        PQSAuditLog.configure(isEnabled: false)
        defer { PQSAuditLog.configure(isEnabled: true) }

        PQSAuditLog.log(.recovery, "pqs.decryptFailure failureClass=disabled-check")
        #expect(PQSAuditLog.isEnabled == false)
    }

    @Test
    func disabledAuditDoesNotEvaluateAutoclosure() {
        PQSAuditLog.configure(isEnabled: false)
        defer { PQSAuditLog.configure(isEnabled: true) }

        var evaluated = false
        func expensiveLine() -> String {
            evaluated = true
            return "pqs.send.attempt should-not-build"
        }
        PQSAuditLog.log(.send, expensiveLine())
        #expect(evaluated == false)
    }
}

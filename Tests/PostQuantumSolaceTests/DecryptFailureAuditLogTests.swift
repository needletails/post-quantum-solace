import Foundation
import Testing
@testable import PQSSession

@Suite(.serialized)
struct DecryptFailureAuditLogTests {
    @Test
    func logAcceptsPlainTextRecoveryLine() {
        DecryptFailureAuditLog.configure(isEnabled: true)
        defer { DecryptFailureAuditLog.configure(isEnabled: true) }

        DecryptFailureAuditLog.log(
            "pqs.decryptFailure failureClass=ratchet.maxSkippedHeadersExceeded layer=pqsInbound sender=frank deviceId=11111111-1111-1111-1111-111111111111 sharedId=shared-abc action=resendRequested")
    }

    @Test
    func disabledAuditSkipsLogging() {
        DecryptFailureAuditLog.configure(isEnabled: false)
        defer { DecryptFailureAuditLog.configure(isEnabled: true) }

        DecryptFailureAuditLog.log("pqs.decryptFailure failureClass=disabled-check")
        #expect(DecryptFailureAuditLog.isEnabled == false)
    }
}

import Testing
@testable import PQSSession

/// Represents an unchanged pre-hardening client conformance.
private final class LegacyNetworkDelegate: NetworkDelegate, @unchecked Sendable {
    var isViable = false
}

@Suite("NetworkDelegate minor-version compatibility")
struct NetworkDelegateCompatibilityTests {
    @Test("legacy conformers still require only synchronous get/set viability")
    func legacyConformerRemainsSourceCompatible() {
        var delegate: any NetworkDelegate = LegacyNetworkDelegate()
        #expect(!delegate.isViable)
        delegate.isViable = true
        #expect(delegate.isViable)
    }

    @Test("legacy PQSSession property assignment remains source compatible")
    func legacySessionAssignmentRemainsSourceCompatible() async {
        let session = PQSSession()
        session.isViable = true
        #expect(session.isViable)

        // The preferred async API and the legacy property share one ordered state.
        await session.setViability(false)
        #expect(!session.isViable)

        // A delayed Task from the older synchronous write cannot overwrite the newer update.
        await Task.yield()
        #expect(!session.isViable)
        await session.shutdown()
    }

    @Test("PQSSession provides an additive actor-isolated viability method")
    func pqsSessionProvidesAsyncViabilityMethod() async {
        let session = PQSSession()
        await session.setViability(true)
        #expect(session.isViable)
        await session.shutdown()
    }
}

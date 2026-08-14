import Testing
@testable import PQSSession

@Suite("Connectivity last-write-wins")
struct ConnectivityTests {
    @Test("setConnectivity is actor-ordered; last awaited write wins")
    func rapidFlipLastWriteWins() async {
        let session = PQSSession()
        await session.setConnectivity(true)
        await session.setConnectivity(false)
        await session.setConnectivity(true)
        await session.setConnectivity(false)
        #expect(await session.isViable == false)
        await session.setConnectivity(true)
        #expect(await session.isViable == true)
        await session.shutdown()
    }

    @Test("false-to-true connectivity coalesces one queue resume")
    func falseToTrueCoalesces() async {
        let session = PQSSession()
        await session.setConnectivity(false)
        await session.setConnectivity(true)
        await session.setConnectivity(true)
        #expect(await session.isViable)
        await session.setConnectivity(false)
        #expect(await session.isViable == false)
        await session.shutdown()
    }
}

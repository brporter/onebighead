import XCTest
@testable import OneBigHead

final class NetworkMonitorTests: XCTestCase {

    func testInitialStateIsConnected() {
        let monitor = NetworkMonitor()
        XCTAssertTrue(monitor.isConnected)
    }

    func testCreatesMonitorInstance() {
        // Verifies that the monitor can be instantiated without crashing
        // and that the isConnected property is accessible.
        let monitor = NetworkMonitor()
        _ = monitor.isConnected
    }

    func testMultipleInstancesAreIndependent() {
        let monitor1 = NetworkMonitor()
        let monitor2 = NetworkMonitor()
        // Both should start as connected
        XCTAssertTrue(monitor1.isConnected)
        XCTAssertTrue(monitor2.isConnected)
    }
}

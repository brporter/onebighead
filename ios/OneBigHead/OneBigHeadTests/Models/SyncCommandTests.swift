import XCTest
@testable import OneBigHead

final class SyncCommandTests: XCTestCase {

    func testInitWithDefaults() throws {
        let entityId = UUID()
        let payload = try JSONEncoder().encode(["name": "test"])

        let command = SyncCommand(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: entityId,
            payload: payload
        )

        XCTAssertNotNil(command.id)
        XCTAssertNotNil(command.createdAt)
        XCTAssertEqual(command.status, .pending)
        XCTAssertEqual(command.entityType, "Collection")
        XCTAssertEqual(command.operation, "Create")
        XCTAssertEqual(command.entityLocalId, entityId)
        XCTAssertEqual(command.payload, payload)
        XCTAssertNil(command.dependsOnCommandId)
        XCTAssertEqual(command.retryCount, 0)
        XCTAssertNil(command.lastError)
        XCTAssertNil(command.serverResponseId)
    }

    func testInitWithAllParameters() throws {
        let fixedId = UUID()
        let entityId = UUID()
        let dependsOnId = UUID()
        let fixedDate = Date(timeIntervalSince1970: 2000)
        let payload = Data("{}".utf8)

        let command = SyncCommand(
            id: fixedId,
            createdAt: fixedDate,
            status: .failed,
            entityType: "Item",
            operation: "Update",
            entityLocalId: entityId,
            payload: payload,
            dependsOnCommandId: dependsOnId,
            retryCount: 5,
            lastError: "Network timeout",
            serverResponseId: 123
        )

        XCTAssertEqual(command.id, fixedId)
        XCTAssertEqual(command.createdAt, fixedDate)
        XCTAssertEqual(command.status, .failed)
        XCTAssertEqual(command.entityType, "Item")
        XCTAssertEqual(command.operation, "Update")
        XCTAssertEqual(command.entityLocalId, entityId)
        XCTAssertEqual(command.payload, payload)
        XCTAssertEqual(command.dependsOnCommandId, dependsOnId)
        XCTAssertEqual(command.retryCount, 5)
        XCTAssertEqual(command.lastError, "Network timeout")
        XCTAssertEqual(command.serverResponseId, 123)
    }

    func testDefaultStatusIsPending() throws {
        let command = SyncCommand(
            entityType: "Category",
            operation: "Delete",
            entityLocalId: UUID(),
            payload: Data()
        )
        XCTAssertEqual(command.status, .pending)
    }

    func testDefaultRetryCountIsZero() throws {
        let command = SyncCommand(
            entityType: "Category",
            operation: "Create",
            entityLocalId: UUID(),
            payload: Data()
        )
        XCTAssertEqual(command.retryCount, 0)
    }

    func testUniqueIdPerInstance() {
        let cmd1 = SyncCommand(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: Data()
        )
        let cmd2 = SyncCommand(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: Data()
        )
        XCTAssertNotEqual(cmd1.id, cmd2.id)
    }

    func testMutableProperties() {
        let command = SyncCommand(
            entityType: "Item",
            operation: "Create",
            entityLocalId: UUID(),
            payload: Data()
        )

        command.status = .executing
        command.retryCount = 1
        command.lastError = "Server error"
        command.serverResponseId = 42

        XCTAssertEqual(command.status, .executing)
        XCTAssertEqual(command.retryCount, 1)
        XCTAssertEqual(command.lastError, "Server error")
        XCTAssertEqual(command.serverResponseId, 42)
    }

    func testPayloadContainsExpectedData() throws {
        let payloadDict = ["name": "Test Collection", "slug": "test"]
        let payload = try JSONEncoder().encode(payloadDict)

        let command = SyncCommand(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: payload
        )

        let decoded = try JSONDecoder().decode([String: String].self, from: command.payload)
        XCTAssertEqual(decoded["name"], "Test Collection")
        XCTAssertEqual(decoded["slug"], "test")
    }
}

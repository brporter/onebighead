import XCTest
import SwiftData
@testable import OneBigHead

final class CommandQueueTests: XCTestCase {

    private var container: ModelContainer!
    private var context: ModelContext!
    private var queue: CommandQueue!

    override func setUp() {
        super.setUp()
        let schema = Schema([
            SyncCommand.self,
            LocalCollection.self,
            LocalCategory.self,
            LocalItem.self,
            LocalPendingImage.self
        ])
        let config = ModelConfiguration(isStoredInMemoryOnly: true)
        container = try! ModelContainer(for: schema, configurations: [config])
        context = ModelContext(container)
        queue = CommandQueue(modelContext: context)
    }

    override func tearDown() {
        queue = nil
        context = nil
        container = nil
        super.tearDown()
    }

    // MARK: - Enqueue

    func testEnqueueCreatesCommandWithCorrectFields() throws {
        let entityId = UUID()
        let payload = ["name": "Test"]

        let command = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: entityId,
            payload: payload
        )

        XCTAssertEqual(command.entityType, "Collection")
        XCTAssertEqual(command.operation, "Create")
        XCTAssertEqual(command.entityLocalId, entityId)
        XCTAssertEqual(command.status, .pending)
        XCTAssertEqual(command.retryCount, 0)
        XCTAssertNil(command.lastError)
        XCTAssertNil(command.serverResponseId)
        XCTAssertNil(command.dependsOnCommandId)
    }

    func testEnqueueStoresPayloadData() throws {
        let payload = ["name": "Test Collection", "slug": "test"]

        let command = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: payload
        )

        let decoded = try JSONDecoder().decode([String: String].self, from: command.payload)
        XCTAssertEqual(decoded["name"], "Test Collection")
        XCTAssertEqual(decoded["slug"], "test")
    }

    func testEnqueueWithDependency() throws {
        let dependsOnId = UUID()

        let command = try queue.enqueue(
            entityType: "Item",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["key": "value"],
            dependsOn: dependsOnId
        )

        XCTAssertEqual(command.dependsOnCommandId, dependsOnId)
    }

    func testEnqueueInsertsIntoContext() throws {
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Test"]
        )

        let descriptor = FetchDescriptor<SyncCommand>()
        let commands = try context.fetch(descriptor)
        XCTAssertEqual(commands.count, 1)
    }

    func testEnqueueMultipleCommands() throws {
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "B"]
        )

        let descriptor = FetchDescriptor<SyncCommand>()
        let commands = try context.fetch(descriptor)
        XCTAssertEqual(commands.count, 2)
    }

    // MARK: - Pending Commands

    func testPendingCommandsReturnsOnlyPending() throws {
        let cmd1 = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Update",
            entityLocalId: UUID(),
            payload: ["name": "B"]
        )

        // Mark cmd1 as executing
        queue.markExecuting(cmd1)

        let pending = try queue.pendingCommands()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].operation, "Update")
    }

    func testPendingCommandsOrderedByCreatedAt() throws {
        let oldDate = Date(timeIntervalSince1970: 1000)
        let newDate = Date(timeIntervalSince1970: 2000)

        let payload = try JSONEncoder().encode(["key": "value"])

        let cmd2 = SyncCommand(
            createdAt: newDate,
            entityType: "Collection",
            operation: "Update",
            entityLocalId: UUID(),
            payload: payload
        )
        context.insert(cmd2)

        let cmd1 = SyncCommand(
            createdAt: oldDate,
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: payload
        )
        context.insert(cmd1)

        let pending = try queue.pendingCommands()
        XCTAssertEqual(pending.count, 2)
        XCTAssertEqual(pending[0].operation, "Create")
        XCTAssertEqual(pending[1].operation, "Update")
    }

    func testPendingCommandsExcludesCompleted() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        queue.markCompleted(cmd, serverResponseId: 1)

        let pending = try queue.pendingCommands()
        XCTAssertTrue(pending.isEmpty)
    }

    func testPendingCommandsExcludesFailed() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        queue.markFailed(cmd, error: "Network error")

        let pending = try queue.pendingCommands()
        XCTAssertTrue(pending.isEmpty)
    }

    func testPendingCommandsExcludesCancelled() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        cmd.status = .cancelled

        let pending = try queue.pendingCommands()
        XCTAssertTrue(pending.isEmpty)
    }

    // MARK: - Executing Commands

    func testExecutingCommandsReturnsOnlyExecuting() throws {
        let cmd1 = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Update",
            entityLocalId: UUID(),
            payload: ["name": "B"]
        )

        queue.markExecuting(cmd1)

        let executing = try queue.executingCommands()
        XCTAssertEqual(executing.count, 1)
        XCTAssertEqual(executing[0].operation, "Create")
    }

    func testExecutingCommandsReturnsEmptyWhenNone() throws {
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        let executing = try queue.executingCommands()
        XCTAssertTrue(executing.isEmpty)
    }

    // MARK: - Failed Commands

    func testFailedCommandsReturnsOnlyFailed() throws {
        let cmd1 = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Update",
            entityLocalId: UUID(),
            payload: ["name": "B"]
        )

        queue.markFailed(cmd1, error: "Server down")

        let failed = try queue.failedCommands()
        XCTAssertEqual(failed.count, 1)
        XCTAssertEqual(failed[0].operation, "Create")
    }

    func testFailedCommandsReturnsEmptyWhenNone() throws {
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        let failed = try queue.failedCommands()
        XCTAssertTrue(failed.isEmpty)
    }

    // MARK: - Mark Executing

    func testMarkExecutingSetsStatus() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        XCTAssertEqual(cmd.status, .pending)
        queue.markExecuting(cmd)
        XCTAssertEqual(cmd.status, .executing)
    }

    // MARK: - Mark Completed

    func testMarkCompletedSetsStatusAndServerId() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        queue.markCompleted(cmd, serverResponseId: 42)
        XCTAssertEqual(cmd.status, .completed)
        XCTAssertEqual(cmd.serverResponseId, 42)
    }

    func testMarkCompletedWithNilServerId() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Delete",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        queue.markCompleted(cmd, serverResponseId: nil)
        XCTAssertEqual(cmd.status, .completed)
        XCTAssertNil(cmd.serverResponseId)
    }

    // MARK: - Mark Failed

    func testMarkFailedSetsStatusAndIncrementsRetryCount() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        XCTAssertEqual(cmd.retryCount, 0)
        queue.markFailed(cmd, error: "Timeout")
        XCTAssertEqual(cmd.status, .failed)
        XCTAssertEqual(cmd.retryCount, 1)
        XCTAssertEqual(cmd.lastError, "Timeout")
    }

    func testMarkFailedIncrementsRetryCountMultipleTimes() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        queue.markFailed(cmd, error: "Error 1")
        queue.markFailed(cmd, error: "Error 2")
        queue.markFailed(cmd, error: "Error 3")
        XCTAssertEqual(cmd.retryCount, 3)
        XCTAssertEqual(cmd.lastError, "Error 3")
    }

    // MARK: - Cancel Dependents

    func testCancelDependentsCancelsDependentCommands() throws {
        let parentCmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Parent"]
        )

        let childCmd = try queue.enqueue(
            entityType: "Item",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Child"],
            dependsOn: parentCmd.id
        )

        try queue.cancelDependents(of: parentCmd.id)
        XCTAssertEqual(childCmd.status, .cancelled)
    }

    func testCancelDependentsDoesNotAffectUnrelated() throws {
        let parentCmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Parent"]
        )

        let unrelatedCmd = try queue.enqueue(
            entityType: "Category",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Unrelated"]
        )

        let _ = try queue.enqueue(
            entityType: "Item",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Child"],
            dependsOn: parentCmd.id
        )

        try queue.cancelDependents(of: parentCmd.id)
        XCTAssertEqual(unrelatedCmd.status, .pending)
    }

    func testCancelDependentsCancelsMultipleDependents() throws {
        let parentCmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Parent"]
        )

        let child1 = try queue.enqueue(
            entityType: "Item",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Child1"],
            dependsOn: parentCmd.id
        )

        let child2 = try queue.enqueue(
            entityType: "Item",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Child2"],
            dependsOn: parentCmd.id
        )

        try queue.cancelDependents(of: parentCmd.id)
        XCTAssertEqual(child1.status, .cancelled)
        XCTAssertEqual(child2.status, .cancelled)
    }

    func testCancelDependentsWithNoMatchesDoesNothing() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        try queue.cancelDependents(of: UUID())
        XCTAssertEqual(cmd.status, .pending)
    }

    // MARK: - Retry Failed

    func testRetryFailedResetsStatusToPending() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        queue.markFailed(cmd, error: "Timeout")
        XCTAssertEqual(cmd.status, .failed)

        queue.retryFailed(cmd)
        XCTAssertEqual(cmd.status, .pending)
    }

    func testRetryFailedPreservesRetryCount() throws {
        let cmd = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        queue.markFailed(cmd, error: "Error")
        queue.markFailed(cmd, error: "Error again")
        XCTAssertEqual(cmd.retryCount, 2)

        queue.retryFailed(cmd)
        XCTAssertEqual(cmd.retryCount, 2)
        XCTAssertEqual(cmd.status, .pending)
    }

    // MARK: - Clear Completed

    func testClearCompletedRemovesCompletedCommands() throws {
        let cmd1 = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Update",
            entityLocalId: UUID(),
            payload: ["name": "B"]
        )

        queue.markCompleted(cmd1, serverResponseId: 1)
        try queue.clearCompleted()

        let descriptor = FetchDescriptor<SyncCommand>()
        let remaining = try context.fetch(descriptor)
        XCTAssertEqual(remaining.count, 1)
        XCTAssertEqual(remaining[0].operation, "Update")
    }

    func testClearCompletedDoesNothingWhenNoCompleted() throws {
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        try queue.clearCompleted()

        let descriptor = FetchDescriptor<SyncCommand>()
        let remaining = try context.fetch(descriptor)
        XCTAssertEqual(remaining.count, 1)
    }

    func testClearCompletedRemovesAllCompleted() throws {
        let cmd1 = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        let cmd2 = try queue.enqueue(
            entityType: "Collection",
            operation: "Update",
            entityLocalId: UUID(),
            payload: ["name": "B"]
        )

        queue.markCompleted(cmd1, serverResponseId: 1)
        queue.markCompleted(cmd2, serverResponseId: 2)
        try queue.clearCompleted()

        let descriptor = FetchDescriptor<SyncCommand>()
        let remaining = try context.fetch(descriptor)
        XCTAssertTrue(remaining.isEmpty)
    }

    // MARK: - Pending Command Count

    func testPendingCommandCountReturnsCorrectCount() throws {
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        let _ = try queue.enqueue(
            entityType: "Collection",
            operation: "Update",
            entityLocalId: UUID(),
            payload: ["name": "B"]
        )
        let cmd3 = try queue.enqueue(
            entityType: "Collection",
            operation: "Delete",
            entityLocalId: UUID(),
            payload: ["name": "C"]
        )
        queue.markExecuting(cmd3)

        let count = try queue.pendingCommandCount()
        XCTAssertEqual(count, 2)
    }

    func testPendingCommandCountReturnsZeroWhenEmpty() throws {
        let count = try queue.pendingCommandCount()
        XCTAssertEqual(count, 0)
    }

    // MARK: - AnyEncodable

    func testAnyEncodableEncodesStringPayload() throws {
        let payload = ["name": "Test"]
        let wrapped = AnyEncodable(payload)
        let data = try JSONEncoder().encode(wrapped)
        let decoded = try JSONDecoder().decode([String: String].self, from: data)
        XCTAssertEqual(decoded["name"], "Test")
    }

    func testAnyEncodableEncodesNestedPayload() throws {
        struct Nested: Encodable {
            let name: String
            let count: Int
        }
        let payload = Nested(name: "Test", count: 42)
        let wrapped = AnyEncodable(payload)
        let data = try JSONEncoder().encode(wrapped)
        let decoded = try JSONDecoder().decode([String: AnyCodableValue].self, from: data)
        XCTAssertEqual(decoded["name"]?.stringValue, "Test")
        XCTAssertEqual(decoded["count"]?.intValue, 42)
    }
}

// MARK: - AnyCodableValue Helper

/// Simple helper for decoding mixed-type JSON values in tests.
private enum AnyCodableValue: Decodable {
    case string(String)
    case int(Int)

    var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    var intValue: Int? {
        if case .int(let value) = self { return value }
        return nil
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode(Int.self) {
            self = .int(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported type")
        }
    }
}

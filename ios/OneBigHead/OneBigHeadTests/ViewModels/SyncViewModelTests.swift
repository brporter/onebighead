import XCTest
import SwiftData
@testable import OneBigHead

final class SyncViewModelTests: XCTestCase {

    private var container: ModelContainer!
    private var context: ModelContext!
    private var commandQueue: CommandQueue!
    private var mockAPIClient: MockSyncAPIClient!
    private var syncEngine: SyncEngine!
    private var viewModel: SyncViewModel!

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
        commandQueue = CommandQueue(modelContext: context)
        mockAPIClient = MockSyncAPIClient()
        syncEngine = SyncEngine(
            apiClient: mockAPIClient,
            commandQueue: commandQueue,
            modelContext: context
        )
        viewModel = SyncViewModel(syncEngine: syncEngine, commandQueue: commandQueue)
    }

    override func tearDown() {
        viewModel = nil
        syncEngine = nil
        mockAPIClient = nil
        commandQueue = nil
        context = nil
        container = nil
        super.tearDown()
    }

    // MARK: - Initial State

    func testInitialStateNotSyncing() {
        XCTAssertFalse(viewModel.isSyncing)
    }

    func testInitialLastSyncDateIsNil() {
        XCTAssertNil(viewModel.lastSyncDate)
    }

    func testInitialSyncErrorIsNil() {
        XCTAssertNil(viewModel.syncError)
    }

    func testInitialPendingCountIsZero() {
        XCTAssertEqual(viewModel.pendingCount, 0)
    }

    func testInitialFailedCountIsZero() {
        XCTAssertEqual(viewModel.failedCount, 0)
    }

    func testInitialProgressIsEmpty() {
        XCTAssertEqual(viewModel.progress.phase, "")
        XCTAssertEqual(viewModel.progress.current, 0)
        XCTAssertEqual(viewModel.progress.total, 0)
    }

    // MARK: - Pending Count

    func testPendingCountReflectsQueueState() throws {
        try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Test"]
        )

        XCTAssertEqual(viewModel.pendingCount, 1)
    }

    func testPendingCountReflectsMultipleCommands() throws {
        try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "B"]
        )

        XCTAssertEqual(viewModel.pendingCount, 2)
    }

    func testPendingCountExcludesNonPending() throws {
        let cmd = try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        commandQueue.markFailed(cmd, error: "Error")

        XCTAssertEqual(viewModel.pendingCount, 0)
    }

    // MARK: - Failed Count

    func testFailedCountReflectsQueueState() throws {
        let cmd = try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        commandQueue.markFailed(cmd, error: "Network error")

        XCTAssertEqual(viewModel.failedCount, 1)
    }

    func testFailedCountZeroWhenNoFailed() throws {
        try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )

        XCTAssertEqual(viewModel.failedCount, 0)
    }

    // MARK: - Sync Delegates to Engine

    func testSyncDelegatesToEngine() async {
        mockAPIClient.getCollectionsResult = .success([])

        await viewModel.sync()

        XCTAssertNotNil(viewModel.lastSyncDate)
        XCTAssertEqual(mockAPIClient.getCollectionsCallCount, 1)
    }

    // MARK: - Retry Failed

    func testRetryFailedResetsFailedCommandsToPending() async throws {
        let cmd = try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        commandQueue.markFailed(cmd, error: "Error")

        XCTAssertEqual(viewModel.failedCount, 1)

        mockAPIClient.getCollectionsResult = .success([])
        // The command will be retried during sync - make it succeed this time
        mockAPIClient.createCollectionResult = .success(CollectionDTO(
            id: 1, name: "A", description: nil, heroImageUrl: nil, slug: "a", isPublic: false, effectiveIsPublic: false
        ))

        // Need a local entity for the command
        let collection = LocalCollection(
            localId: cmd.entityLocalId,
            workspaceId: 1,
            name: "A",
            slug: "a",
            syncStatus: .pendingCreate
        )
        context.insert(collection)

        await viewModel.retryFailed()

        // After retry + sync, the command should have been processed
        XCTAssertEqual(cmd.status, .completed)
    }

    // MARK: - Discard Failed

    func testDiscardFailedCancelsAllFailedCommands() throws {
        let cmd1 = try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "A"]
        )
        let cmd2 = try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Update",
            entityLocalId: UUID(),
            payload: ["name": "B"]
        )
        commandQueue.markFailed(cmd1, error: "Error 1")
        commandQueue.markFailed(cmd2, error: "Error 2")

        XCTAssertEqual(viewModel.failedCount, 2)

        viewModel.discardFailed()

        XCTAssertEqual(cmd1.status, .cancelled)
        XCTAssertEqual(cmd2.status, .cancelled)
        XCTAssertEqual(viewModel.failedCount, 0)
    }

    func testDiscardFailedDoesNotAffectPendingCommands() throws {
        let pending = try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Create",
            entityLocalId: UUID(),
            payload: ["name": "Pending"]
        )
        let failed = try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Update",
            entityLocalId: UUID(),
            payload: ["name": "Failed"]
        )
        commandQueue.markFailed(failed, error: "Error")

        viewModel.discardFailed()

        XCTAssertEqual(pending.status, .pending)
        XCTAssertEqual(failed.status, .cancelled)
    }

    // MARK: - Sync Error Propagation

    func testSyncErrorPropagatedFromEngine() async throws {
        let localId = UUID()
        let collection = LocalCollection(
            localId: localId,
            serverId: 1,
            workspaceId: 1,
            name: "Test",
            slug: "test",
            syncStatus: .pendingUpdate
        )
        context.insert(collection)

        try commandQueue.enqueue(
            entityType: "Collection",
            operation: "Update",
            entityLocalId: localId,
            payload: CreateCollectionRequest(name: "Test", description: nil, heroImageUrl: nil)
        )

        mockAPIClient.updateCollectionResult = .failure(APIError.unauthorized)

        await viewModel.sync()

        XCTAssertEqual(viewModel.syncError, "Authentication required")
    }

    // MARK: - IsSyncing Delegates

    func testIsSyncingDelegatesToEngine() {
        // Engine is not syncing initially
        XCTAssertFalse(viewModel.isSyncing)
        XCTAssertEqual(viewModel.isSyncing, syncEngine.isSyncing)
    }

    // MARK: - LastSyncDate Delegates

    func testLastSyncDateDelegatesToEngine() async {
        XCTAssertNil(viewModel.lastSyncDate)

        mockAPIClient.getCollectionsResult = .success([])
        await viewModel.sync()

        XCTAssertEqual(viewModel.lastSyncDate, syncEngine.lastSyncDate)
        XCTAssertNotNil(viewModel.lastSyncDate)
    }
}

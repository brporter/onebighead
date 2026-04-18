import XCTest
import SwiftData
@testable import OneBigHead

final class CollectionListViewModelTests: XCTestCase {

    private var container: ModelContainer!
    private var context: ModelContext!
    private var commandQueue: CommandQueue!
    private var apiClient: APIClient!
    private var viewModel: CollectionListViewModel!

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
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [MockURLProtocol.self]
        apiClient = APIClient(session: URLSession(configuration: sessionConfig))
        viewModel = CollectionListViewModel(
            modelContext: context,
            commandQueue: commandQueue,
            apiClient: apiClient,
            workspaceId: 1
        )
    }

    override func tearDown() {
        viewModel = nil
        apiClient = nil
        commandQueue = nil
        context = nil
        container = nil
        super.tearDown()
    }

    // MARK: - Initial State

    func testInitialState() {
        XCTAssertTrue(viewModel.collections.isEmpty)
        XCTAssertFalse(viewModel.isLoading)
        XCTAssertNil(viewModel.errorMessage)
        XCTAssertEqual(viewModel.workspaceId, 1)
    }

    // MARK: - Load Collections

    func testLoadCollectionsFetchesFromSwiftData() {
        let collection = LocalCollection(
            workspaceId: 1,
            name: "Test Collection",
            slug: "test-collection"
        )
        context.insert(collection)

        viewModel.loadCollections()

        XCTAssertEqual(viewModel.collections.count, 1)
        XCTAssertEqual(viewModel.collections[0].name, "Test Collection")
        XCTAssertFalse(viewModel.isLoading)
    }

    func testLoadCollectionsFiltersbyWorkspace() {
        let c1 = LocalCollection(workspaceId: 1, name: "WS1", slug: "ws1")
        let c2 = LocalCollection(workspaceId: 2, name: "WS2", slug: "ws2")
        context.insert(c1)
        context.insert(c2)

        viewModel.loadCollections()

        XCTAssertEqual(viewModel.collections.count, 1)
        XCTAssertEqual(viewModel.collections[0].name, "WS1")
    }

    func testLoadCollectionsExcludesPendingDelete() {
        let c1 = LocalCollection(workspaceId: 1, name: "Visible", slug: "visible")
        let c2 = LocalCollection(workspaceId: 1, name: "Deleted", slug: "deleted", syncStatus: .pendingDelete)
        context.insert(c1)
        context.insert(c2)

        viewModel.loadCollections()

        XCTAssertEqual(viewModel.collections.count, 1)
        XCTAssertEqual(viewModel.collections[0].name, "Visible")
    }

    func testLoadCollectionsSortsByName() {
        let c1 = LocalCollection(workspaceId: 1, name: "Zebra", slug: "zebra")
        let c2 = LocalCollection(workspaceId: 1, name: "Apple", slug: "apple")
        context.insert(c1)
        context.insert(c2)

        viewModel.loadCollections()

        XCTAssertEqual(viewModel.collections.count, 2)
        XCTAssertEqual(viewModel.collections[0].name, "Apple")
        XCTAssertEqual(viewModel.collections[1].name, "Zebra")
    }

    func testLoadCollectionsReturnsEmptyWhenNone() {
        viewModel.loadCollections()

        XCTAssertTrue(viewModel.collections.isEmpty)
        XCTAssertFalse(viewModel.isLoading)
        XCTAssertNil(viewModel.errorMessage)
    }

    func testLoadCollectionsClearsErrorMessage() {
        viewModel.errorMessage = "Previous error"
        let c = LocalCollection(workspaceId: 1, name: "Test", slug: "test")
        context.insert(c)

        viewModel.loadCollections()

        XCTAssertNil(viewModel.errorMessage)
    }

    func testLoadCollectionsIncludesPendingCreate() {
        let c = LocalCollection(workspaceId: 1, name: "New", slug: "new", syncStatus: .pendingCreate)
        context.insert(c)

        viewModel.loadCollections()

        XCTAssertEqual(viewModel.collections.count, 1)
    }

    func testLoadCollectionsIncludesPendingUpdate() {
        let c = LocalCollection(workspaceId: 1, name: "Updated", slug: "updated", syncStatus: .pendingUpdate)
        context.insert(c)

        viewModel.loadCollections()

        XCTAssertEqual(viewModel.collections.count, 1)
    }

    // MARK: - Create Collection

    func testCreateCollectionCreatesEntityInSwiftData() {
        viewModel.createCollection(name: "New Collection", description: "Desc", slug: "new-collection")

        XCTAssertEqual(viewModel.collections.count, 1)
        XCTAssertEqual(viewModel.collections[0].name, "New Collection")
        XCTAssertEqual(viewModel.collections[0].descriptionText, "Desc")
        XCTAssertEqual(viewModel.collections[0].slug, "new-collection")
        XCTAssertEqual(viewModel.collections[0].workspaceId, 1)
    }

    func testCreateCollectionSetsSyncStatusPendingCreate() {
        viewModel.createCollection(name: "Test", description: "", slug: "test")

        XCTAssertEqual(viewModel.collections[0].syncStatus, .pendingCreate)
    }

    func testCreateCollectionEnqueuesCommand() throws {
        viewModel.createCollection(name: "Test", description: "Desc", slug: "test")

        let pending = try commandQueue.pendingCommands()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].entityType, "Collection")
        XCTAssertEqual(pending[0].operation, "Create")
    }

    func testCreateCollectionCommandHasCorrectEntityLocalId() throws {
        viewModel.createCollection(name: "Test", description: "", slug: "test")

        let pending = try commandQueue.pendingCommands()
        XCTAssertEqual(pending[0].entityLocalId, viewModel.collections[0].localId)
    }

    func testCreateCollectionCommandPayloadContainsName() throws {
        viewModel.createCollection(name: "My Collection", description: "A description", slug: "my-collection")

        let pending = try commandQueue.pendingCommands()
        let payload = try JSONDecoder().decode(CreateCollectionRequest.self, from: pending[0].payload)
        XCTAssertEqual(payload.name, "My Collection")
        XCTAssertEqual(payload.description, "A description")
    }

    func testCreateCollectionEmptyDescriptionEncodesAsNil() throws {
        viewModel.createCollection(name: "Test", description: "", slug: "test")

        let pending = try commandQueue.pendingCommands()
        let payload = try JSONDecoder().decode(CreateCollectionRequest.self, from: pending[0].payload)
        XCTAssertNil(payload.description)
    }

    // MARK: - Update Collection

    func testUpdateCollectionModifiesEntity() {
        let collection = LocalCollection(workspaceId: 1, name: "Old", slug: "old")
        context.insert(collection)
        viewModel.loadCollections()

        viewModel.updateCollection(collection, name: "New Name", description: "New Desc")

        XCTAssertEqual(collection.name, "New Name")
        XCTAssertEqual(collection.descriptionText, "New Desc")
    }

    func testUpdateCollectionSetsSyncStatusPendingUpdate() {
        let collection = LocalCollection(workspaceId: 1, name: "Test", slug: "test")
        context.insert(collection)
        viewModel.loadCollections()

        viewModel.updateCollection(collection, name: "Updated", description: "")

        XCTAssertEqual(collection.syncStatus, .pendingUpdate)
    }

    func testUpdateCollectionUpdatesLastModifiedLocally() {
        let oldDate = Date(timeIntervalSince1970: 1000)
        let collection = LocalCollection(
            workspaceId: 1,
            name: "Test",
            slug: "test",
            lastModifiedLocally: oldDate
        )
        context.insert(collection)

        viewModel.updateCollection(collection, name: "Updated", description: "")

        XCTAssertGreaterThan(collection.lastModifiedLocally, oldDate)
    }

    func testUpdateCollectionEnqueuesCommand() throws {
        let collection = LocalCollection(workspaceId: 1, name: "Test", slug: "test")
        context.insert(collection)

        viewModel.updateCollection(collection, name: "Updated", description: "Desc")

        let pending = try commandQueue.pendingCommands()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].entityType, "Collection")
        XCTAssertEqual(pending[0].operation, "Update")
        XCTAssertEqual(pending[0].entityLocalId, collection.localId)
    }

    func testUpdateCollectionCommandPayload() throws {
        let collection = LocalCollection(workspaceId: 1, name: "Test", slug: "test")
        context.insert(collection)

        viewModel.updateCollection(collection, name: "New Name", description: "New Desc")

        let pending = try commandQueue.pendingCommands()
        let payload = try JSONDecoder().decode(CreateCollectionRequest.self, from: pending[0].payload)
        XCTAssertEqual(payload.name, "New Name")
        XCTAssertEqual(payload.description, "New Desc")
    }

    // MARK: - Delete Collection

    func testDeleteCollectionSetsSyncStatusPendingDelete() {
        let collection = LocalCollection(workspaceId: 1, name: "Test", slug: "test")
        context.insert(collection)

        viewModel.deleteCollection(collection)

        XCTAssertEqual(collection.syncStatus, .pendingDelete)
    }

    func testDeleteCollectionUpdatesLastModifiedLocally() {
        let oldDate = Date(timeIntervalSince1970: 1000)
        let collection = LocalCollection(
            workspaceId: 1,
            name: "Test",
            slug: "test",
            lastModifiedLocally: oldDate
        )
        context.insert(collection)

        viewModel.deleteCollection(collection)

        XCTAssertGreaterThan(collection.lastModifiedLocally, oldDate)
    }

    func testDeleteCollectionEnqueuesCommand() throws {
        let collection = LocalCollection(workspaceId: 1, name: "Test", slug: "test")
        context.insert(collection)

        viewModel.deleteCollection(collection)

        let pending = try commandQueue.pendingCommands()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].entityType, "Collection")
        XCTAssertEqual(pending[0].operation, "Delete")
        XCTAssertEqual(pending[0].entityLocalId, collection.localId)
    }

    func testDeleteCollectionRemovedFromCollectionsList() {
        let collection = LocalCollection(workspaceId: 1, name: "Test", slug: "test")
        context.insert(collection)
        viewModel.loadCollections()
        XCTAssertEqual(viewModel.collections.count, 1)

        viewModel.deleteCollection(collection)

        XCTAssertTrue(viewModel.collections.isEmpty)
    }

    // MARK: - CollectionEditorView Slug Generation

    func testSlugGenerationBasicCase() {
        let slug = CollectionEditorView.generateSlug(from: "My Collection")
        XCTAssertEqual(slug, "my-collection")
    }

    func testSlugGenerationStripsNonAlphanumeric() {
        let slug = CollectionEditorView.generateSlug(from: "Hello! World?")
        XCTAssertEqual(slug, "hello-world")
    }

    func testSlugGenerationPreservesHyphens() {
        let slug = CollectionEditorView.generateSlug(from: "already-slugged")
        XCTAssertEqual(slug, "already-slugged")
    }

    func testSlugGenerationEmptyString() {
        let slug = CollectionEditorView.generateSlug(from: "")
        XCTAssertEqual(slug, "")
    }

    func testSlugGenerationAllSpecialCharacters() {
        let slug = CollectionEditorView.generateSlug(from: "!@#$%^&*()")
        XCTAssertEqual(slug, "")
    }

    func testSlugGenerationUppercase() {
        let slug = CollectionEditorView.generateSlug(from: "UPPERCASE")
        XCTAssertEqual(slug, "uppercase")
    }

    func testSlugGenerationMultipleSpaces() {
        let slug = CollectionEditorView.generateSlug(from: "multiple   spaces")
        XCTAssertEqual(slug, "multiple---spaces")
    }

    func testSlugGenerationNumbers() {
        let slug = CollectionEditorView.generateSlug(from: "Collection 2024")
        XCTAssertEqual(slug, "collection-2024")
    }

    // MARK: - EmptyPayload

    func testEmptyPayloadEncodes() throws {
        let payload = EmptyPayload()
        let data = try JSONEncoder().encode(payload)
        XCTAssertNotNil(data)
        let decoded = try JSONDecoder().decode([String: String].self, from: data)
        XCTAssertTrue(decoded.isEmpty)
    }
}

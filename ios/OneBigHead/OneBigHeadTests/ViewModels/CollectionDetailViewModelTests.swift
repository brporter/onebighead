import XCTest
import SwiftData
@testable import OneBigHead

final class CollectionDetailViewModelTests: XCTestCase {

    private var container: ModelContainer!
    private var context: ModelContext!
    private var commandQueue: CommandQueue!
    private var apiClient: APIClient!
    private var collection: LocalCollection!
    private var viewModel: CollectionDetailViewModel!

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

        collection = LocalCollection(workspaceId: 1, name: "Test Collection", slug: "test-collection", syncStatus: .synced)
        context.insert(collection)

        viewModel = CollectionDetailViewModel(
            modelContext: context,
            commandQueue: commandQueue,
            apiClient: apiClient,
            collectionLocalId: collection.localId
        )
    }

    override func tearDown() {
        viewModel = nil
        collection = nil
        apiClient = nil
        commandQueue = nil
        context = nil
        container = nil
        super.tearDown()
    }

    // MARK: - Initial State

    func testInitialState() {
        XCTAssertNil(viewModel.collection)
        XCTAssertTrue(viewModel.categories.isEmpty)
        XCTAssertFalse(viewModel.isLoading)
    }

    // MARK: - Load Data

    func testLoadDataFetchesCollection() {
        viewModel.loadData()

        XCTAssertNotNil(viewModel.collection)
        XCTAssertEqual(viewModel.collection?.name, "Test Collection")
        XCTAssertFalse(viewModel.isLoading)
    }

    func testLoadDataFetchesCategories() {
        let cat = LocalCategory(
            workspaceId: 1,
            collectionLocalId: collection.localId,
            name: "Category 1"
        )
        context.insert(cat)

        viewModel.loadData()

        XCTAssertEqual(viewModel.categories.count, 1)
        XCTAssertEqual(viewModel.categories[0].name, "Category 1")
    }

    func testLoadDataExcludesPendingDeleteCategories() {
        let cat1 = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "Visible")
        let cat2 = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "Deleted", syncStatus: .pendingDelete)
        context.insert(cat1)
        context.insert(cat2)

        viewModel.loadData()

        XCTAssertEqual(viewModel.categories.count, 1)
        XCTAssertEqual(viewModel.categories[0].name, "Visible")
    }

    func testLoadDataOnlyCategoriesForThisCollection() {
        let otherCollectionId = UUID()
        let cat1 = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "Mine")
        let cat2 = LocalCategory(workspaceId: 1, collectionLocalId: otherCollectionId, name: "Other")
        context.insert(cat1)
        context.insert(cat2)

        viewModel.loadData()

        XCTAssertEqual(viewModel.categories.count, 1)
        XCTAssertEqual(viewModel.categories[0].name, "Mine")
    }

    func testLoadDataSortsCategoriesBySortOrder() {
        let cat1 = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "B", sortOrder: 2)
        let cat2 = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "A", sortOrder: 1)
        context.insert(cat1)
        context.insert(cat2)

        viewModel.loadData()

        XCTAssertEqual(viewModel.categories.count, 2)
        XCTAssertEqual(viewModel.categories[0].name, "A")
        XCTAssertEqual(viewModel.categories[1].name, "B")
    }

    func testLoadDataCollectionNotFound() {
        let vm = CollectionDetailViewModel(
            modelContext: context,
            commandQueue: commandQueue,
            apiClient: apiClient,
            collectionLocalId: UUID()
        )

        vm.loadData()

        XCTAssertNil(vm.collection)
        XCTAssertTrue(vm.categories.isEmpty)
        XCTAssertFalse(vm.isLoading)
    }

    // MARK: - Create Category

    func testCreateCategoryCreatesEntity() {
        viewModel.loadData()

        viewModel.createCategory(name: "New Category", description: "A description", parentLocalId: nil)

        XCTAssertEqual(viewModel.categories.count, 1)
        XCTAssertEqual(viewModel.categories[0].name, "New Category")
        XCTAssertEqual(viewModel.categories[0].descriptionText, "A description")
    }

    func testCreateCategorySetsCorrectCollectionLocalId() {
        viewModel.loadData()

        viewModel.createCategory(name: "Test", description: "", parentLocalId: nil)

        XCTAssertEqual(viewModel.categories[0].collectionLocalId, collection.localId)
    }

    func testCreateCategorySetsSyncStatusPendingCreate() {
        viewModel.loadData()

        viewModel.createCategory(name: "Test", description: "", parentLocalId: nil)

        XCTAssertEqual(viewModel.categories[0].syncStatus, .pendingCreate)
    }

    func testCreateCategorySetsWorkspaceId() {
        viewModel.loadData()

        viewModel.createCategory(name: "Test", description: "", parentLocalId: nil)

        XCTAssertEqual(viewModel.categories[0].workspaceId, 1)
    }

    func testCreateCategoryEnqueuesCommand() throws {
        viewModel.loadData()

        viewModel.createCategory(name: "Test", description: "Desc", parentLocalId: nil)

        let pending = try commandQueue.pendingCommands()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].entityType, "Category")
        XCTAssertEqual(pending[0].operation, "Create")
    }

    func testCreateCategoryWithParent() {
        viewModel.loadData()
        let parentId = UUID()

        viewModel.createCategory(name: "Child", description: "", parentLocalId: parentId)

        XCTAssertEqual(viewModel.categories[0].parentLocalId, parentId)
    }

    func testCreateCategoryDoesNothingIfCollectionNotLoaded() throws {
        // Don't call loadData, so collection is nil
        viewModel.createCategory(name: "Test", description: "", parentLocalId: nil)

        XCTAssertTrue(viewModel.categories.isEmpty)
        let pending = try commandQueue.pendingCommands()
        XCTAssertTrue(pending.isEmpty)
    }

    // MARK: - Update Category

    func testUpdateCategoryModifiesEntity() {
        let cat = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "Old")
        context.insert(cat)
        viewModel.loadData()

        viewModel.updateCategory(cat, name: "New Name", description: "New Desc")

        XCTAssertEqual(cat.name, "New Name")
        XCTAssertEqual(cat.descriptionText, "New Desc")
    }

    func testUpdateCategorySetsSyncStatusPendingUpdate() {
        let cat = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "Test")
        context.insert(cat)

        viewModel.updateCategory(cat, name: "Updated", description: "")

        XCTAssertEqual(cat.syncStatus, .pendingUpdate)
    }

    func testUpdateCategoryEnqueuesCommand() throws {
        let cat = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "Test")
        context.insert(cat)

        viewModel.updateCategory(cat, name: "Updated", description: "Desc")

        let pending = try commandQueue.pendingCommands()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].entityType, "Category")
        XCTAssertEqual(pending[0].operation, "Update")
        XCTAssertEqual(pending[0].entityLocalId, cat.localId)
    }

    func testUpdateCategoryCommandPayload() throws {
        let cat = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "Test")
        context.insert(cat)

        viewModel.updateCategory(cat, name: "New", description: "New Desc")

        let pending = try commandQueue.pendingCommands()
        let payload = try JSONDecoder().decode(UpdateCategoryRequest.self, from: pending[0].payload)
        XCTAssertEqual(payload.name, "New")
        XCTAssertEqual(payload.description, "New Desc")
    }

    // MARK: - Delete Category

    func testDeleteCategorySetsSyncStatusPendingDelete() {
        let cat = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "Test")
        context.insert(cat)

        viewModel.deleteCategory(cat)

        XCTAssertEqual(cat.syncStatus, .pendingDelete)
    }

    func testDeleteCategoryEnqueuesCommand() throws {
        let cat = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "Test")
        context.insert(cat)

        viewModel.deleteCategory(cat)

        let pending = try commandQueue.pendingCommands()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].entityType, "Category")
        XCTAssertEqual(pending[0].operation, "Delete")
        XCTAssertEqual(pending[0].entityLocalId, cat.localId)
    }

    func testDeleteCategoryRemovedFromCategoriesList() {
        let cat = LocalCategory(workspaceId: 1, collectionLocalId: collection.localId, name: "Test")
        context.insert(cat)
        viewModel.loadData()
        XCTAssertEqual(viewModel.categories.count, 1)

        viewModel.deleteCategory(cat)

        XCTAssertTrue(viewModel.categories.isEmpty)
    }
}

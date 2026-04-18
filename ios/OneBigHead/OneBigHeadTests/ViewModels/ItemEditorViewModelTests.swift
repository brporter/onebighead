import XCTest
import SwiftData
@testable import OneBigHead

final class ItemEditorViewModelTests: XCTestCase {

    private var container: ModelContainer!
    private var context: ModelContext!
    private var commandQueue: CommandQueue!
    private let workspaceId = 1
    private var collectionLocalId: UUID!
    private var collection: LocalCollection!

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

        collection = LocalCollection(workspaceId: workspaceId, name: "Test Collection", slug: "test")
        context.insert(collection)
        collectionLocalId = collection.localId
    }

    override func tearDown() {
        collection = nil
        collectionLocalId = nil
        commandQueue = nil
        context = nil
        container = nil
        super.tearDown()
    }

    // MARK: - Helper

    private func makeViewModel(existingItem: LocalItem? = nil) -> ItemEditorViewModel {
        ItemEditorViewModel(
            modelContext: context,
            commandQueue: commandQueue,
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            existingItem: existingItem
        )
    }

    // MARK: - Initial State (New Item)

    func testInitialStateForNewItem() {
        let vm = makeViewModel()

        XCTAssertEqual(vm.name, "")
        XCTAssertEqual(vm.summary, "")
        XCTAssertEqual(vm.descriptionText, "")
        XCTAssertNil(vm.categoryLocalId)
        XCTAssertEqual(vm.userFlag, .have)
        XCTAssertTrue(vm.properties.isEmpty)
        XCTAssertTrue(vm.images.isEmpty)
        XCTAssertFalse(vm.isEditing)
        XCTAssertFalse(vm.isSaving)
        XCTAssertNil(vm.errorMessage)
    }

    // MARK: - Initial State (Existing Item)

    func testInitialStateForExistingItem() {
        let categoryId = UUID()
        let props = [ItemProperty(key: "Color", value: "Red")]
        let imgs = [ItemImage(key: UUID(), url: "https://example.com/img.jpg", sortOrder: 0, isPrimary: true)]
        let item = LocalItem(
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            categoryLocalId: categoryId,
            name: "Existing Item",
            summary: "A summary",
            descriptionText: "A description",
            properties: props,
            images: imgs,
            userFlag: .want
        )
        context.insert(item)

        let vm = makeViewModel(existingItem: item)

        XCTAssertEqual(vm.name, "Existing Item")
        XCTAssertEqual(vm.summary, "A summary")
        XCTAssertEqual(vm.descriptionText, "A description")
        XCTAssertEqual(vm.categoryLocalId, categoryId)
        XCTAssertEqual(vm.userFlag, .want)
        XCTAssertEqual(vm.properties.count, 1)
        XCTAssertEqual(vm.properties[0].key, "Color")
        XCTAssertEqual(vm.properties[0].value, "Red")
        XCTAssertEqual(vm.images.count, 1)
        XCTAssertTrue(vm.isEditing)
        XCTAssertFalse(vm.isSaving)
        XCTAssertNil(vm.errorMessage)
    }

    // MARK: - Save Creates New Item

    func testSaveCreatesNewLocalItem() {
        let vm = makeViewModel()
        vm.name = "New Item"
        vm.summary = "Summary"
        vm.descriptionText = "Description"
        vm.userFlag = .want

        vm.save()

        let descriptor = FetchDescriptor<LocalItem>()
        let items = try! context.fetch(descriptor)
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items[0].name, "New Item")
        XCTAssertEqual(items[0].summary, "Summary")
        XCTAssertEqual(items[0].descriptionText, "Description")
        XCTAssertEqual(items[0].userFlag, .want)
        XCTAssertEqual(items[0].workspaceId, workspaceId)
        XCTAssertEqual(items[0].collectionLocalId, collectionLocalId)
    }

    func testSaveNewItemSetsSyncStatusPendingCreate() {
        let vm = makeViewModel()
        vm.name = "New Item"

        vm.save()

        let items = try! context.fetch(FetchDescriptor<LocalItem>())
        XCTAssertEqual(items[0].syncStatus, .pendingCreate)
    }

    func testSaveNewItemSetsCategoryLocalId() {
        let categoryId = UUID()
        let vm = makeViewModel()
        vm.name = "New Item"
        vm.categoryLocalId = categoryId

        vm.save()

        let items = try! context.fetch(FetchDescriptor<LocalItem>())
        XCTAssertEqual(items[0].categoryLocalId, categoryId)
    }

    func testSaveNewItemSetsProperties() {
        let vm = makeViewModel()
        vm.name = "New Item"
        vm.properties = [
            ItemProperty(key: "Color", value: "Blue"),
            ItemProperty(key: "Size", value: "Large")
        ]

        vm.save()

        let items = try! context.fetch(FetchDescriptor<LocalItem>())
        XCTAssertEqual(items[0].properties.count, 2)
        XCTAssertEqual(items[0].properties[0].key, "Color")
        XCTAssertEqual(items[0].properties[1].key, "Size")
    }

    func testSaveNewItemSetsImages() {
        let imgKey = UUID()
        let vm = makeViewModel()
        vm.name = "New Item"
        vm.images = [ItemImage(key: imgKey, url: "https://example.com/img.jpg", sortOrder: 0, isPrimary: true)]

        vm.save()

        let items = try! context.fetch(FetchDescriptor<LocalItem>())
        XCTAssertEqual(items[0].images.count, 1)
        XCTAssertEqual(items[0].images[0].key, imgKey)
    }

    // MARK: - Save Enqueues Command (Create)

    func testSaveNewItemEnqueuesCreateCommand() throws {
        let vm = makeViewModel()
        vm.name = "New Item"
        vm.summary = "Summary"

        vm.save()

        let pending = try commandQueue.pendingCommands()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].entityType, "Item")
        XCTAssertEqual(pending[0].operation, "Create")
    }

    func testSaveNewItemCommandPayload() throws {
        let vm = makeViewModel()
        vm.name = "New Item"
        vm.summary = "Summary"
        vm.descriptionText = "Desc"
        vm.userFlag = .tradeOrSell

        vm.save()

        let pending = try commandQueue.pendingCommands()
        let payload = try JSONDecoder().decode(CreateItemRequest.self, from: pending[0].payload)
        XCTAssertEqual(payload.name, "New Item")
        XCTAssertEqual(payload.summary, "Summary")
        XCTAssertEqual(payload.description, "Desc")
        XCTAssertEqual(payload.userFlag, "TradeOrSell")
    }

    // MARK: - Save Updates Existing Item

    func testSaveUpdatesExistingItem() {
        let item = LocalItem(
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            name: "Original",
            summary: "Old summary"
        )
        context.insert(item)

        let vm = makeViewModel(existingItem: item)
        vm.name = "Updated"
        vm.summary = "New summary"
        vm.descriptionText = "New description"
        vm.userFlag = .tradeOrSell

        vm.save()

        XCTAssertEqual(item.name, "Updated")
        XCTAssertEqual(item.summary, "New summary")
        XCTAssertEqual(item.descriptionText, "New description")
        XCTAssertEqual(item.userFlag, .tradeOrSell)
    }

    func testSaveExistingItemSetsSyncStatusPendingUpdate() {
        let item = LocalItem(
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            name: "Original"
        )
        context.insert(item)

        let vm = makeViewModel(existingItem: item)
        vm.name = "Updated"

        vm.save()

        XCTAssertEqual(item.syncStatus, .pendingUpdate)
    }

    func testSaveExistingItemUpdatesProperties() {
        let item = LocalItem(
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            name: "Original",
            properties: [ItemProperty(key: "Old", value: "Value")]
        )
        context.insert(item)

        let vm = makeViewModel(existingItem: item)
        vm.properties = [ItemProperty(key: "New", value: "NewValue")]

        vm.save()

        XCTAssertEqual(item.properties.count, 1)
        XCTAssertEqual(item.properties[0].key, "New")
        XCTAssertEqual(item.properties[0].value, "NewValue")
    }

    func testSaveExistingItemUpdatesCategoryLocalId() {
        let item = LocalItem(
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            name: "Original"
        )
        context.insert(item)

        let newCategoryId = UUID()
        let vm = makeViewModel(existingItem: item)
        vm.categoryLocalId = newCategoryId

        vm.save()

        XCTAssertEqual(item.categoryLocalId, newCategoryId)
    }

    // MARK: - Save Enqueues Command (Update)

    func testSaveExistingItemEnqueuesUpdateCommand() throws {
        let item = LocalItem(
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            name: "Original"
        )
        context.insert(item)

        let vm = makeViewModel(existingItem: item)
        vm.name = "Updated"

        vm.save()

        let pending = try commandQueue.pendingCommands()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].entityType, "Item")
        XCTAssertEqual(pending[0].operation, "Update")
        XCTAssertEqual(pending[0].entityLocalId, item.localId)
    }

    func testSaveExistingItemCommandPayload() throws {
        let item = LocalItem(
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            name: "Original"
        )
        context.insert(item)

        let vm = makeViewModel(existingItem: item)
        vm.name = "Updated"
        vm.summary = "New Summary"
        vm.userFlag = .want

        vm.save()

        let pending = try commandQueue.pendingCommands()
        let payload = try JSONDecoder().decode(UpdateItemRequest.self, from: pending[0].payload)
        XCTAssertEqual(payload.name, "Updated")
        XCTAssertEqual(payload.summary, "New Summary")
        XCTAssertEqual(payload.userFlag, "Want")
    }

    // MARK: - Delete Item

    func testDeleteItemMarksSyncStatusPendingDelete() {
        let item = LocalItem(
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            name: "To Delete"
        )
        context.insert(item)

        let vm = makeViewModel(existingItem: item)

        vm.deleteItem()

        XCTAssertEqual(item.syncStatus, .pendingDelete)
    }

    func testDeleteItemEnqueuesDeleteCommand() throws {
        let item = LocalItem(
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            name: "To Delete"
        )
        context.insert(item)

        let vm = makeViewModel(existingItem: item)

        vm.deleteItem()

        let pending = try commandQueue.pendingCommands()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].entityType, "Item")
        XCTAssertEqual(pending[0].operation, "Delete")
        XCTAssertEqual(pending[0].entityLocalId, item.localId)
    }

    func testDeleteItemDoesNothingIfNoExistingItem() throws {
        let vm = makeViewModel()

        vm.deleteItem()

        let pending = try commandQueue.pendingCommands()
        XCTAssertTrue(pending.isEmpty)
    }

    // MARK: - isSaving State

    func testIsSavingIsFalseAfterSave() {
        let vm = makeViewModel()
        vm.name = "Test"

        vm.save()

        XCTAssertFalse(vm.isSaving)
    }

    // MARK: - Save Sets ExistingItem After Create

    func testSaveNewItemSetsExistingItem() {
        let vm = makeViewModel()
        XCTAssertNil(vm.existingItem)

        vm.name = "New Item"
        vm.save()

        XCTAssertNotNil(vm.existingItem)
        XCTAssertTrue(vm.isEditing)
    }

    // MARK: - WorkspaceId and CollectionLocalId

    func testNewItemHasCorrectWorkspaceId() {
        let vm = makeViewModel()
        vm.name = "Test"

        vm.save()

        let items = try! context.fetch(FetchDescriptor<LocalItem>())
        XCTAssertEqual(items[0].workspaceId, workspaceId)
    }

    func testNewItemHasCorrectCollectionLocalId() {
        let vm = makeViewModel()
        vm.name = "Test"

        vm.save()

        let items = try! context.fetch(FetchDescriptor<LocalItem>())
        XCTAssertEqual(items[0].collectionLocalId, collectionLocalId)
    }

    // MARK: - Save Existing Item Updates Images

    func testSaveExistingItemUpdatesImages() {
        let item = LocalItem(
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId,
            name: "Original"
        )
        context.insert(item)

        let imgKey = UUID()
        let vm = makeViewModel(existingItem: item)
        vm.images = [ItemImage(key: imgKey, url: "https://example.com/new.jpg", sortOrder: 0, isPrimary: true)]

        vm.save()

        XCTAssertEqual(item.images.count, 1)
        XCTAssertEqual(item.images[0].key, imgKey)
    }
}

import Foundation
import SwiftData

/// ViewModel for viewing a single collection with its categories.
@Observable
final class CollectionDetailViewModel {

    // MARK: - Properties

    var collection: LocalCollection?
    var categories: [LocalCategory] = []
    var isLoading: Bool = false

    // MARK: - Dependencies

    private let modelContext: ModelContext
    private let commandQueue: CommandQueue
    private let apiClient: APIClient
    let collectionLocalId: UUID

    // MARK: - Init

    init(
        modelContext: ModelContext,
        commandQueue: CommandQueue,
        apiClient: APIClient,
        collectionLocalId: UUID
    ) {
        self.modelContext = modelContext
        self.commandQueue = commandQueue
        self.apiClient = apiClient
        self.collectionLocalId = collectionLocalId
    }

    // MARK: - Methods

    /// Fetches collection and its categories from SwiftData.
    func loadData() {
        isLoading = true

        do {
            let cid = collectionLocalId
            let collectionDescriptor = FetchDescriptor<LocalCollection>(
                predicate: #Predicate { $0.localId == cid }
            )
            collection = try modelContext.fetch(collectionDescriptor).first

            let categoryDescriptor = FetchDescriptor<LocalCategory>(
                predicate: #Predicate { $0.collectionLocalId == cid },
                sortBy: [SortDescriptor(\.sortOrder, order: .forward), SortDescriptor(\.name, order: .forward)]
            )
            categories = try modelContext.fetch(categoryDescriptor).filter { $0.syncStatus != .pendingDelete }
        } catch {
            collection = nil
            categories = []
        }

        isLoading = false
    }

    /// Updates a collection's name and description, enqueues command.
    func updateCollection(_ collection: LocalCollection, name: String, description: String) {
        collection.name = name
        collection.descriptionText = description
        collection.syncStatus = .pendingUpdate
        collection.lastModifiedLocally = Date()

        do {
            try commandQueue.enqueue(
                entityType: "Collection",
                operation: "Update",
                entityLocalId: collection.localId,
                payload: CreateCollectionRequest(
                    name: name,
                    description: description.isEmpty ? nil : description,
                    heroImageUrl: collection.heroImageUrl
                )
            )
        } catch {
            // Error is silently handled; the command will be retried on next sync
        }

        loadData()
    }

    /// Creates a LocalCategory, enqueues command.
    func createCategory(name: String, description: String, parentLocalId: UUID?) {
        guard let collection else { return }

        let category = LocalCategory(
            workspaceId: collection.workspaceId,
            collectionLocalId: collectionLocalId,
            name: name,
            descriptionText: description,
            parentLocalId: parentLocalId,
            syncStatus: .pendingCreate
        )
        modelContext.insert(category)

        do {
            try commandQueue.enqueue(
                entityType: "Category",
                operation: "Create",
                entityLocalId: category.localId,
                payload: CreateCategoryRequest(
                    collectionId: collection.serverId ?? 0,
                    name: name,
                    description: description.isEmpty ? nil : description,
                    parentCategoryId: nil,
                    itemTemplateIds: nil
                )
            )
        } catch {
            // Error is silently handled; the command will be retried on next sync
        }

        loadData()
    }

    /// Updates a category, enqueues command.
    func updateCategory(_ category: LocalCategory, name: String, description: String) {
        category.name = name
        category.descriptionText = description
        category.syncStatus = .pendingUpdate

        do {
            try commandQueue.enqueue(
                entityType: "Category",
                operation: "Update",
                entityLocalId: category.localId,
                payload: UpdateCategoryRequest(
                    name: name,
                    description: description.isEmpty ? nil : description,
                    parentCategoryId: nil,
                    itemTemplateIds: nil
                )
            )
        } catch {
            // Error is silently handled
        }

        loadData()
    }

    /// Marks a category for delete, enqueues command.
    func deleteCategory(_ category: LocalCategory) {
        category.syncStatus = .pendingDelete

        do {
            try commandQueue.enqueue(
                entityType: "Category",
                operation: "Delete",
                entityLocalId: category.localId,
                payload: EmptyPayload()
            )
        } catch {
            // Error is silently handled
        }

        loadData()
    }
}

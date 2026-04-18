import Foundation
import SwiftData

/// ViewModel for the collections list screen.
@Observable
final class CollectionListViewModel {

    // MARK: - Properties

    var collections: [LocalCollection] = []
    var isLoading: Bool = false
    var errorMessage: String?

    // MARK: - Dependencies

    private let modelContext: ModelContext
    private let commandQueue: CommandQueue
    private let apiClient: APIClient
    let workspaceId: Int

    // MARK: - Init

    init(
        modelContext: ModelContext,
        commandQueue: CommandQueue,
        apiClient: APIClient,
        workspaceId: Int
    ) {
        self.modelContext = modelContext
        self.commandQueue = commandQueue
        self.apiClient = apiClient
        self.workspaceId = workspaceId
    }

    // MARK: - Methods

    /// Queries SwiftData for all LocalCollections in this workspace.
    func loadCollections() {
        isLoading = true
        errorMessage = nil

        do {
            let wid = workspaceId
            let descriptor = FetchDescriptor<LocalCollection>(
                predicate: #Predicate { $0.workspaceId == wid },
                sortBy: [SortDescriptor(\.name, order: .forward)]
            )
            collections = try modelContext.fetch(descriptor).filter { $0.syncStatus != .pendingDelete }
        } catch {
            errorMessage = error.localizedDescription
        }

        isLoading = false
    }

    /// Creates a LocalCollection in SwiftData with syncStatus .pendingCreate, enqueues a create command.
    func createCollection(name: String, description: String, slug: String) {
        let collection = LocalCollection(
            workspaceId: workspaceId,
            name: name,
            descriptionText: description,
            slug: slug,
            syncStatus: .pendingCreate,
            lastModifiedLocally: Date()
        )
        modelContext.insert(collection)

        do {
            try commandQueue.enqueue(
                entityType: "Collection",
                operation: "Create",
                entityLocalId: collection.localId,
                payload: CreateCollectionRequest(
                    name: name,
                    description: description.isEmpty ? nil : description,
                    heroImageUrl: nil
                )
            )
        } catch {
            errorMessage = error.localizedDescription
        }

        loadCollections()
    }

    /// Updates a collection in SwiftData, sets syncStatus to .pendingUpdate, enqueues update command.
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
            errorMessage = error.localizedDescription
        }

        loadCollections()
    }

    /// Sets syncStatus to .pendingDelete, enqueues delete command.
    func deleteCollection(_ collection: LocalCollection) {
        collection.syncStatus = .pendingDelete
        collection.lastModifiedLocally = Date()

        do {
            try commandQueue.enqueue(
                entityType: "Collection",
                operation: "Delete",
                entityLocalId: collection.localId,
                payload: EmptyPayload()
            )
        } catch {
            errorMessage = error.localizedDescription
        }

        loadCollections()
    }
}

/// Empty payload for delete operations.
struct EmptyPayload: Encodable {}

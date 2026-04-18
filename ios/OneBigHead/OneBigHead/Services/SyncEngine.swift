import Foundation
import SwiftData

// MARK: - SyncProgress

/// Tracks the current phase and progress of a sync operation.
struct SyncProgress {
    var phase: String
    var current: Int
    var total: Int
}

// MARK: - ImageManaging Protocol

/// Protocol for image management operations needed by sync.
/// ImageManager can conform to this when available.
protocol ImageManaging {
    func loadImageData(for pendingImage: LocalPendingImage) -> Data?
}

// MARK: - SyncAPIClient Protocol

/// Protocol for API operations needed by SyncEngine. Allows mocking in tests.
protocol SyncAPIClient {
    func getCollections() async throws -> [CollectionDTO]
    func createCollection(_ request: CreateCollectionRequest) async throws -> CollectionDTO
    func updateCollection(id: Int, _ request: CreateCollectionRequest) async throws -> CollectionDTO
    func deleteCollection(id: Int) async throws
    func getCategories(collectionId: Int) async throws -> [CategoryDTO]
    func createCategory(_ request: CreateCategoryRequest) async throws -> CategoryDTO
    func updateCategory(id: Int, _ request: UpdateCategoryRequest) async throws -> CategoryDTO
    func deleteCategory(id: Int) async throws
    func getItems(categoryId: Int) async throws -> [ItemDTO]
    func createItem(_ request: CreateItemRequest) async throws -> ItemDTO
    func updateItem(id: Int, _ request: UpdateItemRequest) async throws -> ItemDTO
    func deleteItem(id: Int) async throws
    func uploadImage(data: Data, filename: String) async throws -> ImageUploadResponse
}

/// APIClient conforms to SyncAPIClient.
extension APIClient: SyncAPIClient {}

// MARK: - SyncEngine

/// Orchestrates syncing local changes with the server.
@Observable
final class SyncEngine {

    // MARK: - Properties

    private(set) var isSyncing: Bool = false
    private(set) var lastSyncDate: Date?
    private(set) var syncError: String?
    private(set) var progress: SyncProgress = SyncProgress(phase: "", current: 0, total: 0)

    // MARK: - Dependencies

    private let apiClient: SyncAPIClient
    private let commandQueue: CommandQueue
    private let modelContext: ModelContext
    private var imageManager: ImageManaging?

    // MARK: - ID Resolution

    /// Maps local UUIDs to server-assigned IDs. Populated as create commands succeed.
    private(set) var idResolutionMap: [UUID: Int] = [:]

    /// Maximum number of retries for a command before marking it as failed.
    static let maxRetries = 3

    // MARK: - Init

    init(
        apiClient: SyncAPIClient,
        commandQueue: CommandQueue,
        modelContext: ModelContext,
        imageManager: ImageManaging? = nil
    ) {
        self.apiClient = apiClient
        self.commandQueue = commandQueue
        self.modelContext = modelContext
        self.imageManager = imageManager
    }

    // MARK: - Main Sync

    /// Executes a full sync cycle: upload images, execute commands, pull fresh data.
    func sync() async {
        guard !isSyncing else { return }

        isSyncing = true
        syncError = nil

        // Phase 1: Upload pending images
        await uploadPendingImages()

        // Phase 2: Execute commands in order
        let aborted = await executeCommands()

        // Phase 3: Pull fresh data (skip if aborted due to auth error)
        if !aborted {
            await pullFreshData()
        }

        isSyncing = false
        if syncError == nil {
            lastSyncDate = Date()
        }
    }

    // MARK: - Phase 1: Upload Images

    private func uploadPendingImages() async {
        progress = SyncProgress(phase: "Uploading images", current: 0, total: 0)

        let pendingImages: [LocalPendingImage]
        do {
            let descriptor = FetchDescriptor<LocalPendingImage>()
            pendingImages = try modelContext.fetch(descriptor).filter { $0.uploadStatus == .pending }
        } catch {
            return
        }

        progress.total = pendingImages.count

        for (index, pendingImage) in pendingImages.enumerated() {
            progress.current = index + 1

            guard let imageData = imageManager?.loadImageData(for: pendingImage) else {
                pendingImage.uploadStatus = .failed
                continue
            }

            do {
                let filename = "\(pendingImage.localId.uuidString).jpg"
                let response = try await apiClient.uploadImage(data: imageData, filename: filename)
                pendingImage.serverKey = response.key.uuidString
                pendingImage.serverUrl = response.url
                pendingImage.uploadStatus = .uploaded
            } catch {
                pendingImage.uploadStatus = .failed
                pendingImage.retryCount += 1
            }
        }
    }

    // MARK: - Phase 2: Execute Commands

    /// Executes pending commands. Returns true if sync was aborted (e.g. auth error).
    private func executeCommands() async -> Bool {
        progress = SyncProgress(phase: "Syncing changes", current: 0, total: 0)

        let commands: [SyncCommand]
        do {
            commands = try commandQueue.pendingCommands()
        } catch {
            syncError = "Failed to load pending commands: \(error.localizedDescription)"
            return false
        }

        progress.total = commands.count

        for (index, command) in commands.enumerated() {
            progress.current = index + 1

            // Skip commands that were cancelled by a previous iteration (e.g. dependents of a 404)
            guard command.status == .pending else { continue }

            commandQueue.markExecuting(command)

            var lastError: Error?
            var succeeded = false

            for attempt in 0..<SyncEngine.maxRetries {
                do {
                    let serverId = try await executeCommand(command)
                    commandQueue.markCompleted(command, serverResponseId: serverId)

                    // Update ID resolution map for creates
                    if command.operation.lowercased() == "create", let serverId {
                        idResolutionMap[command.entityLocalId] = serverId
                        // Also update the local entity's serverId
                        updateLocalEntityServerId(
                            entityType: command.entityType,
                            localId: command.entityLocalId,
                            serverId: serverId
                        )
                    }

                    succeeded = true
                    break
                } catch let error as APIError {
                    lastError = error

                    switch error {
                    case .unauthorized:
                        commandQueue.markFailed(command, error: "Authentication required")
                        syncError = "Authentication required"
                        return true

                    case .notFound:
                        commandQueue.markFailed(command, error: "Entity not found on server")
                        deleteLocalEntity(entityType: command.entityType, localId: command.entityLocalId)
                        do {
                            try commandQueue.cancelDependents(of: command.id)
                        } catch {
                            // Best effort
                        }
                        succeeded = true // Move on, don't retry
                        break

                    case .conflict:
                        commandQueue.markFailed(command, error: "Conflict - server wins")
                        // Server wins - will be resolved in pull phase
                        succeeded = true
                        break

                    case .serverError, .networkError:
                        if attempt < SyncEngine.maxRetries - 1 {
                            // Backoff before retry
                            try? await Task.sleep(nanoseconds: UInt64((attempt + 1)) * 100_000_000)
                            continue
                        }

                    default:
                        if attempt < SyncEngine.maxRetries - 1 {
                            continue
                        }
                    }
                } catch {
                    lastError = error
                    if attempt < SyncEngine.maxRetries - 1 {
                        try? await Task.sleep(nanoseconds: UInt64((attempt + 1)) * 100_000_000)
                        continue
                    }
                }
            }

            if !succeeded {
                commandQueue.markFailed(command, error: lastError?.localizedDescription ?? "Unknown error")
            }
        }

        return false
    }

    // MARK: - Command Execution

    /// Executes a single command against the API. Returns the server ID if applicable.
    private func executeCommand(_ command: SyncCommand) async throws -> Int? {
        let entityType = command.entityType.lowercased()
        let operation = command.operation.lowercased()

        switch (entityType, operation) {
        case ("collection", "create"):
            let request = try JSONDecoder().decode(CreateCollectionRequest.self, from: command.payload)
            let response = try await apiClient.createCollection(request)
            return response.id

        case ("collection", "update"):
            let request = try JSONDecoder().decode(CreateCollectionRequest.self, from: command.payload)
            guard let serverId = resolveServerId(for: command.entityLocalId, entityType: entityType) else {
                throw APIError.notFound
            }
            let response = try await apiClient.updateCollection(id: serverId, request)
            return response.id

        case ("collection", "delete"):
            guard let serverId = resolveServerId(for: command.entityLocalId, entityType: entityType) else {
                return nil // Already deleted
            }
            try await apiClient.deleteCollection(id: serverId)
            return nil

        case ("category", "create"):
            let payload = try JSONDecoder().decode(CreateCategoryPayload.self, from: command.payload)
            let collectionServerId = resolveId(for: payload.collectionLocalId) ?? payload.collectionId
            let request = CreateCategoryRequest(
                collectionId: collectionServerId,
                name: payload.name,
                description: payload.description,
                parentCategoryId: payload.parentCategoryId,
                itemTemplateIds: payload.itemTemplateIds
            )
            let response = try await apiClient.createCategory(request)
            return response.id

        case ("category", "update"):
            let request = try JSONDecoder().decode(UpdateCategoryRequest.self, from: command.payload)
            guard let serverId = resolveServerId(for: command.entityLocalId, entityType: entityType) else {
                throw APIError.notFound
            }
            let response = try await apiClient.updateCategory(id: serverId, request)
            return response.id

        case ("category", "delete"):
            guard let serverId = resolveServerId(for: command.entityLocalId, entityType: entityType) else {
                return nil
            }
            try await apiClient.deleteCategory(id: serverId)
            return nil

        case ("item", "create"):
            let request = try JSONDecoder().decode(CreateItemRequest.self, from: command.payload)
            let response = try await apiClient.createItem(request)
            return response.id

        case ("item", "update"):
            let request = try JSONDecoder().decode(UpdateItemRequest.self, from: command.payload)
            guard let serverId = resolveServerId(for: command.entityLocalId, entityType: entityType) else {
                throw APIError.notFound
            }
            let response = try await apiClient.updateItem(id: serverId, request)
            return response.id

        case ("item", "delete"):
            guard let serverId = resolveServerId(for: command.entityLocalId, entityType: entityType) else {
                return nil
            }
            try await apiClient.deleteItem(id: serverId)
            return nil

        default:
            throw APIError.invalidResponse
        }
    }

    // MARK: - ID Resolution

    /// Resolves a local UUID to a server ID, checking the resolution map first, then local entities.
    func resolveServerId(for localId: UUID, entityType: String) -> Int? {
        // Check resolution map first
        if let serverId = idResolutionMap[localId] {
            return serverId
        }

        // Look up the local entity
        switch entityType.lowercased() {
        case "collection":
            let descriptor = FetchDescriptor<LocalCollection>()
            if let collections = try? modelContext.fetch(descriptor),
               let collection = collections.first(where: { $0.localId == localId }) {
                return collection.serverId
            }
        case "category":
            let descriptor = FetchDescriptor<LocalCategory>()
            if let categories = try? modelContext.fetch(descriptor),
               let category = categories.first(where: { $0.localId == localId }) {
                return category.serverId
            }
        case "item":
            let descriptor = FetchDescriptor<LocalItem>()
            if let items = try? modelContext.fetch(descriptor),
               let item = items.first(where: { $0.localId == localId }) {
                return item.serverId
            }
        default:
            break
        }

        return nil
    }

    /// Resolves a local UUID to a server ID using only the ID resolution map.
    private func resolveId(for localId: UUID) -> Int? {
        return idResolutionMap[localId]
    }

    // MARK: - Local Entity Updates

    private func updateLocalEntityServerId(entityType: String, localId: UUID, serverId: Int) {
        switch entityType.lowercased() {
        case "collection":
            let descriptor = FetchDescriptor<LocalCollection>()
            if let collections = try? modelContext.fetch(descriptor),
               let collection = collections.first(where: { $0.localId == localId }) {
                collection.serverId = serverId
                collection.syncStatus = .synced
            }
        case "category":
            let descriptor = FetchDescriptor<LocalCategory>()
            if let categories = try? modelContext.fetch(descriptor),
               let category = categories.first(where: { $0.localId == localId }) {
                category.serverId = serverId
                category.syncStatus = .synced
            }
        case "item":
            let descriptor = FetchDescriptor<LocalItem>()
            if let items = try? modelContext.fetch(descriptor),
               let item = items.first(where: { $0.localId == localId }) {
                item.serverId = serverId
                item.syncStatus = .synced
            }
        default:
            break
        }
    }

    private func deleteLocalEntity(entityType: String, localId: UUID) {
        switch entityType.lowercased() {
        case "collection":
            let descriptor = FetchDescriptor<LocalCollection>()
            if let collections = try? modelContext.fetch(descriptor),
               let collection = collections.first(where: { $0.localId == localId }) {
                modelContext.delete(collection)
            }
        case "category":
            let descriptor = FetchDescriptor<LocalCategory>()
            if let categories = try? modelContext.fetch(descriptor),
               let category = categories.first(where: { $0.localId == localId }) {
                modelContext.delete(category)
            }
        case "item":
            let descriptor = FetchDescriptor<LocalItem>()
            if let items = try? modelContext.fetch(descriptor),
               let item = items.first(where: { $0.localId == localId }) {
                modelContext.delete(item)
            }
        default:
            break
        }
    }

    // MARK: - Phase 3: Pull Fresh Data

    private func pullFreshData() async {
        progress = SyncProgress(phase: "Pulling updates", current: 0, total: 0)

        do {
            // Pull collections
            let serverCollections = try await apiClient.getCollections()
            try syncCollections(serverCollections)

            // Pull categories and items for each collection
            let descriptor = FetchDescriptor<LocalCollection>()
            let localCollections = try modelContext.fetch(descriptor)
            let collectionsWithServerId = localCollections.filter { $0.serverId != nil }

            progress.total = collectionsWithServerId.count

            for (index, collection) in collectionsWithServerId.enumerated() {
                progress.current = index + 1

                guard let serverId = collection.serverId else { continue }

                let serverCategories = try await apiClient.getCategories(collectionId: serverId)
                try syncCategories(serverCategories, collectionLocalId: collection.localId)

                // Pull items for each category
                for serverCategory in serverCategories {
                    let serverItems = try await apiClient.getItems(categoryId: serverCategory.id)
                    let categoryLocalId = findCategoryLocalId(serverId: serverCategory.id)
                    try syncItems(serverItems, collectionLocalId: collection.localId, categoryLocalId: categoryLocalId)
                }
            }
        } catch {
            syncError = "Pull failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Sync Collections

    private func syncCollections(_ serverCollections: [CollectionDTO]) throws {
        let descriptor = FetchDescriptor<LocalCollection>()
        let localCollections = try modelContext.fetch(descriptor)

        // Update or create
        for serverCollection in serverCollections {
            if let local = localCollections.first(where: { $0.serverId == serverCollection.id }) {
                // Only update if synced (don't overwrite local changes)
                if local.syncStatus == .synced {
                    local.name = serverCollection.name
                    local.descriptionText = serverCollection.description ?? ""
                    local.heroImageUrl = serverCollection.heroImageUrl
                    local.slug = serverCollection.slug
                    local.visibility = serverCollection.effectiveIsPublic ? .publicVisibility : .privateVisibility
                }
            } else {
                // New from server
                let newCollection = LocalCollection(
                    serverId: serverCollection.id,
                    workspaceId: 0, // Will be set by workspace context
                    name: serverCollection.name,
                    descriptionText: serverCollection.description ?? "",
                    heroImageUrl: serverCollection.heroImageUrl,
                    slug: serverCollection.slug,
                    visibility: serverCollection.effectiveIsPublic ? .publicVisibility : .privateVisibility,
                    syncStatus: .synced
                )
                modelContext.insert(newCollection)
            }
        }

        // Delete local entities that no longer exist on server (only if synced)
        let serverIds = Set(serverCollections.map { $0.id })
        for local in localCollections {
            if let serverId = local.serverId,
               !serverIds.contains(serverId),
               local.syncStatus == .synced {
                modelContext.delete(local)
            }
        }
    }

    // MARK: - Sync Categories

    private func syncCategories(_ serverCategories: [CategoryDTO], collectionLocalId: UUID) throws {
        let descriptor = FetchDescriptor<LocalCategory>()
        let allLocal = try modelContext.fetch(descriptor)
        let localCategories = allLocal.filter { $0.collectionLocalId == collectionLocalId }

        for serverCategory in serverCategories {
            if let local = localCategories.first(where: { $0.serverId == serverCategory.id }) {
                if local.syncStatus == .synced {
                    local.name = serverCategory.name
                    local.descriptionText = serverCategory.description ?? ""
                    local.sortOrder = serverCategory.sortOrder
                    local.isSystem = serverCategory.isSystem
                    local.visibility = serverCategory.effectiveIsPublic ? .publicVisibility : .privateVisibility
                }
            } else {
                let newCategory = LocalCategory(
                    serverId: serverCategory.id,
                    workspaceId: 0,
                    collectionLocalId: collectionLocalId,
                    name: serverCategory.name,
                    descriptionText: serverCategory.description ?? "",
                    sortOrder: serverCategory.sortOrder,
                    isSystem: serverCategory.isSystem,
                    visibility: serverCategory.effectiveIsPublic ? .publicVisibility : .privateVisibility,
                    syncStatus: .synced
                )
                modelContext.insert(newCategory)
            }
        }

        let serverIds = Set(serverCategories.map { $0.id })
        for local in localCategories {
            if let serverId = local.serverId,
               !serverIds.contains(serverId),
               local.syncStatus == .synced {
                modelContext.delete(local)
            }
        }
    }

    // MARK: - Sync Items

    private func syncItems(_ serverItems: [ItemDTO], collectionLocalId: UUID, categoryLocalId: UUID?) throws {
        let descriptor = FetchDescriptor<LocalItem>()
        let allLocal = try modelContext.fetch(descriptor)
        let localItems = allLocal.filter { $0.collectionLocalId == collectionLocalId }

        for serverItem in serverItems {
            if let local = localItems.first(where: { $0.serverId == serverItem.id }) {
                if local.syncStatus == .synced {
                    local.name = serverItem.name
                    local.summary = serverItem.summary ?? ""
                    local.descriptionText = serverItem.description ?? ""
                    local.templateKey = serverItem.templateKey
                    local.properties = serverItem.properties.map {
                        ItemProperty(key: $0.key, value: $0.value, templatePropertyId: $0.templatePropertyId)
                    }
                    local.images = serverItem.images.map {
                        ItemImage(key: $0.key, url: $0.url, sortOrder: $0.sortOrder, isPrimary: $0.isPrimary)
                    }
                    local.visibility = serverItem.effectiveIsPublic ? .publicVisibility : .privateVisibility
                    if let flag = UserFlag(rawValue: serverItem.userFlag ?? "") {
                        local.userFlag = flag
                    }
                }
            } else {
                let newItem = LocalItem(
                    serverId: serverItem.id,
                    workspaceId: 0,
                    collectionLocalId: collectionLocalId,
                    categoryLocalId: categoryLocalId,
                    templateKey: serverItem.templateKey,
                    name: serverItem.name,
                    summary: serverItem.summary ?? "",
                    descriptionText: serverItem.description ?? "",
                    properties: serverItem.properties.map {
                        ItemProperty(key: $0.key, value: $0.value, templatePropertyId: $0.templatePropertyId)
                    },
                    images: serverItem.images.map {
                        ItemImage(key: $0.key, url: $0.url, sortOrder: $0.sortOrder, isPrimary: $0.isPrimary)
                    },
                    visibility: serverItem.effectiveIsPublic ? .publicVisibility : .privateVisibility,
                    userFlag: UserFlag(rawValue: serverItem.userFlag ?? "") ?? .have,
                    syncStatus: .synced
                )
                modelContext.insert(newItem)
            }
        }

        let serverIds = Set(serverItems.map { $0.id })
        for local in localItems {
            if let serverId = local.serverId,
               !serverIds.contains(serverId),
               local.syncStatus == .synced,
               local.categoryLocalId == categoryLocalId {
                modelContext.delete(local)
            }
        }
    }

    // MARK: - Helpers

    private func findCategoryLocalId(serverId: Int) -> UUID? {
        let descriptor = FetchDescriptor<LocalCategory>()
        if let categories = try? modelContext.fetch(descriptor),
           let category = categories.first(where: { $0.serverId == serverId }) {
            return category.localId
        }
        return nil
    }
}

// MARK: - CreateCategoryPayload

/// Intermediate payload for category creation that includes the collection local ID for resolution.
struct CreateCategoryPayload: Codable {
    let collectionLocalId: UUID
    let collectionId: Int
    let name: String
    let description: String?
    let parentCategoryId: Int?
    let itemTemplateIds: [Int]?
}

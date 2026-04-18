import Foundation
import SwiftData

/// ViewModel for creating or editing an item.
@Observable
final class ItemEditorViewModel {

    // MARK: - Properties

    var name: String = ""
    var summary: String = ""
    var descriptionText: String = ""
    var categoryLocalId: UUID?
    var userFlag: UserFlag = .have
    var properties: [ItemProperty] = []
    var images: [ItemImage] = []
    var isSaving: Bool = false
    var errorMessage: String?

    /// Whether we are editing an existing item (vs. creating a new one).
    var isEditing: Bool { existingItem != nil }

    // MARK: - Dependencies

    private let modelContext: ModelContext
    private let commandQueue: CommandQueue
    let workspaceId: Int
    let collectionLocalId: UUID
    private(set) var existingItem: LocalItem?

    // MARK: - Init

    init(
        modelContext: ModelContext,
        commandQueue: CommandQueue,
        workspaceId: Int,
        collectionLocalId: UUID,
        existingItem: LocalItem? = nil
    ) {
        self.modelContext = modelContext
        self.commandQueue = commandQueue
        self.workspaceId = workspaceId
        self.collectionLocalId = collectionLocalId
        self.existingItem = existingItem

        if let item = existingItem {
            self.name = item.name
            self.summary = item.summary
            self.descriptionText = item.descriptionText
            self.categoryLocalId = item.categoryLocalId
            self.userFlag = item.userFlag
            self.properties = item.properties
            self.images = item.images
        }
    }

    // MARK: - Methods

    /// Creates or updates a LocalItem in SwiftData and enqueues a sync command.
    func save() {
        isSaving = true
        errorMessage = nil

        if let item = existingItem {
            // Update existing
            item.name = name
            item.summary = summary
            item.descriptionText = descriptionText
            item.categoryLocalId = categoryLocalId
            item.userFlag = userFlag
            item.properties = properties
            item.images = images
            item.syncStatus = .pendingUpdate

            do {
                try commandQueue.enqueue(
                    entityType: "Item",
                    operation: "Update",
                    entityLocalId: item.localId,
                    payload: UpdateItemRequest(
                        name: name,
                        summary: summary,
                        description: descriptionText,
                        categoryId: nil,
                        templateKey: item.templateKey,
                        properties: properties.map { ItemPropertyDTO(key: $0.key, value: $0.value, templatePropertyId: $0.templatePropertyId) },
                        images: images.map { ItemImageDTO(key: $0.key, url: $0.url, sortOrder: $0.sortOrder, isPrimary: $0.isPrimary) },
                        userFlag: userFlag.rawValue
                    )
                )
            } catch {
                errorMessage = error.localizedDescription
            }
        } else {
            // Create new
            let item = LocalItem(
                workspaceId: workspaceId,
                collectionLocalId: collectionLocalId,
                categoryLocalId: categoryLocalId,
                name: name,
                summary: summary,
                descriptionText: descriptionText,
                properties: properties,
                images: images,
                userFlag: userFlag,
                syncStatus: .pendingCreate
            )
            modelContext.insert(item)
            existingItem = item

            do {
                try commandQueue.enqueue(
                    entityType: "Item",
                    operation: "Create",
                    entityLocalId: item.localId,
                    payload: CreateItemRequest(
                        name: name,
                        summary: summary,
                        description: descriptionText,
                        collectionId: 0,
                        categoryId: nil,
                        templateKey: nil,
                        properties: properties.map { ItemPropertyDTO(key: $0.key, value: $0.value, templatePropertyId: $0.templatePropertyId) },
                        images: images.map { ItemImageDTO(key: $0.key, url: $0.url, sortOrder: $0.sortOrder, isPrimary: $0.isPrimary) },
                        userFlag: userFlag.rawValue
                    )
                )
            } catch {
                errorMessage = error.localizedDescription
            }
        }

        isSaving = false
    }

    /// Marks the item for deletion and enqueues a delete command.
    func deleteItem() {
        guard let item = existingItem else { return }

        item.syncStatus = .pendingDelete

        do {
            try commandQueue.enqueue(
                entityType: "Item",
                operation: "Delete",
                entityLocalId: item.localId,
                payload: EmptyPayload()
            )
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

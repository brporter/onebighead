import Foundation
import SwiftData

/// A single property key-value pair associated with an item.
struct ItemProperty: Codable, Equatable {
    var key: String
    var value: String
    var templatePropertyId: UUID?
}

/// An image associated with an item.
struct ItemImage: Codable, Equatable {
    var key: UUID
    var url: String
    var sortOrder: Int
    var isPrimary: Bool
}

@Model
final class LocalItem {
    @Attribute(.unique) var localId: UUID
    var serverId: Int?
    var workspaceId: Int
    var collectionLocalId: UUID
    var categoryLocalId: UUID?
    var templateKey: UUID?
    var name: String
    var summary: String
    var descriptionText: String
    var properties: [ItemProperty]
    var images: [ItemImage]
    var visibility: Visibility
    var userFlag: UserFlag
    var syncStatus: SyncStatus

    init(
        localId: UUID = UUID(),
        serverId: Int? = nil,
        workspaceId: Int,
        collectionLocalId: UUID,
        categoryLocalId: UUID? = nil,
        templateKey: UUID? = nil,
        name: String,
        summary: String = "",
        descriptionText: String = "",
        properties: [ItemProperty] = [],
        images: [ItemImage] = [],
        visibility: Visibility = .privateVisibility,
        userFlag: UserFlag = .have,
        syncStatus: SyncStatus = .synced
    ) {
        self.localId = localId
        self.serverId = serverId
        self.workspaceId = workspaceId
        self.collectionLocalId = collectionLocalId
        self.categoryLocalId = categoryLocalId
        self.templateKey = templateKey
        self.name = name
        self.summary = summary
        self.descriptionText = descriptionText
        self.properties = properties
        self.images = images
        self.visibility = visibility
        self.userFlag = userFlag
        self.syncStatus = syncStatus
    }
}

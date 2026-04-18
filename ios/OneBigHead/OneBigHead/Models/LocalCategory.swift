import Foundation
import SwiftData

@Model
final class LocalCategory {
    @Attribute(.unique) var localId: UUID
    var serverId: Int?
    var workspaceId: Int
    var collectionLocalId: UUID
    var name: String
    var descriptionText: String
    var parentLocalId: UUID?
    var sortOrder: Int
    var isSystem: Bool
    var visibility: Visibility
    var syncStatus: SyncStatus

    init(
        localId: UUID = UUID(),
        serverId: Int? = nil,
        workspaceId: Int,
        collectionLocalId: UUID,
        name: String,
        descriptionText: String = "",
        parentLocalId: UUID? = nil,
        sortOrder: Int = 0,
        isSystem: Bool = false,
        visibility: Visibility = .privateVisibility,
        syncStatus: SyncStatus = .synced
    ) {
        self.localId = localId
        self.serverId = serverId
        self.workspaceId = workspaceId
        self.collectionLocalId = collectionLocalId
        self.name = name
        self.descriptionText = descriptionText
        self.parentLocalId = parentLocalId
        self.sortOrder = sortOrder
        self.isSystem = isSystem
        self.visibility = visibility
        self.syncStatus = syncStatus
    }
}

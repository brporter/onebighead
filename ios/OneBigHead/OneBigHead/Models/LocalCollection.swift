import Foundation
import SwiftData

@Model
final class LocalCollection {
    @Attribute(.unique) var localId: UUID
    var serverId: Int?
    var workspaceId: Int
    var name: String
    var descriptionText: String
    var heroImageUrl: String?
    var slug: String
    var visibility: Visibility
    var syncStatus: SyncStatus
    var lastModifiedLocally: Date

    init(
        localId: UUID = UUID(),
        serverId: Int? = nil,
        workspaceId: Int,
        name: String,
        descriptionText: String = "",
        heroImageUrl: String? = nil,
        slug: String,
        visibility: Visibility = .privateVisibility,
        syncStatus: SyncStatus = .synced,
        lastModifiedLocally: Date = Date()
    ) {
        self.localId = localId
        self.serverId = serverId
        self.workspaceId = workspaceId
        self.name = name
        self.descriptionText = descriptionText
        self.heroImageUrl = heroImageUrl
        self.slug = slug
        self.visibility = visibility
        self.syncStatus = syncStatus
        self.lastModifiedLocally = lastModifiedLocally
    }
}

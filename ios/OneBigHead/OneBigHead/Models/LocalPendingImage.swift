import Foundation
import SwiftData

@Model
final class LocalPendingImage {
    @Attribute(.unique) var localId: UUID
    var localFilePath: String
    var uploadStatus: UploadStatus
    var serverKey: String?
    var serverUrl: String?
    var retryCount: Int
    var itemLocalId: UUID

    init(
        localId: UUID = UUID(),
        localFilePath: String,
        uploadStatus: UploadStatus = .pending,
        serverKey: String? = nil,
        serverUrl: String? = nil,
        retryCount: Int = 0,
        itemLocalId: UUID
    ) {
        self.localId = localId
        self.localFilePath = localFilePath
        self.uploadStatus = uploadStatus
        self.serverKey = serverKey
        self.serverUrl = serverUrl
        self.retryCount = retryCount
        self.itemLocalId = itemLocalId
    }
}

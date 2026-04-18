import Foundation
import SwiftData

@Model
final class SyncCommand {
    @Attribute(.unique) var id: UUID
    var createdAt: Date
    var status: CommandStatus
    var entityType: String
    var operation: String
    var entityLocalId: UUID
    var payload: Data
    var dependsOnCommandId: UUID?
    var retryCount: Int
    var lastError: String?
    var serverResponseId: Int?

    init(
        id: UUID = UUID(),
        createdAt: Date = Date(),
        status: CommandStatus = .pending,
        entityType: String,
        operation: String,
        entityLocalId: UUID,
        payload: Data,
        dependsOnCommandId: UUID? = nil,
        retryCount: Int = 0,
        lastError: String? = nil,
        serverResponseId: Int? = nil
    ) {
        self.id = id
        self.createdAt = createdAt
        self.status = status
        self.entityType = entityType
        self.operation = operation
        self.entityLocalId = entityLocalId
        self.payload = payload
        self.dependsOnCommandId = dependsOnCommandId
        self.retryCount = retryCount
        self.lastError = lastError
        self.serverResponseId = serverResponseId
    }
}

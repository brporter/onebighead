import Foundation

/// Tracks the synchronization state of a local entity relative to the server.
enum SyncStatus: String, Codable {
    case synced
    case pendingCreate
    case pendingUpdate
    case pendingDelete
}

/// Tracks the execution state of a sync command in the command queue.
enum CommandStatus: String, Codable {
    case pending
    case executing
    case completed
    case failed
    case cancelled
}

/// Tracks the upload state of a pending image.
enum UploadStatus: String, Codable {
    case pending
    case uploading
    case uploaded
    case failed
}

/// The authentication provider used to sign in.
enum AuthProvider: String, Codable {
    case apple
    case google
    case microsoft
}

/// User-assigned flag indicating their relationship to an item.
enum UserFlag: String, Codable {
    case have = "Have"
    case want = "Want"
    case tradeOrSell = "TradeOrSell"
}

/// Controls the visibility of an entity (collection, category, or item).
enum Visibility: String, Codable {
    case privateVisibility = "Private"
    case publicVisibility = "Public"
}

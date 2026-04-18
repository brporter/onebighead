import Foundation
import SwiftData

/// ViewModel wrapping SyncEngine for UI consumption.
@Observable
final class SyncViewModel {

    // MARK: - Dependencies

    private let syncEngine: SyncEngine
    private let commandQueue: CommandQueue

    // MARK: - Properties

    /// Whether a sync is currently in progress. Delegates to syncEngine.
    var isSyncing: Bool {
        syncEngine.isSyncing
    }

    /// The date of the last successful sync. Delegates to syncEngine.
    var lastSyncDate: Date? {
        syncEngine.lastSyncDate
    }

    /// The current sync error, if any.
    var syncError: String? {
        syncEngine.syncError
    }

    /// Count of pending commands in the queue.
    var pendingCount: Int {
        (try? commandQueue.pendingCommandCount()) ?? 0
    }

    /// Count of failed commands in the queue.
    var failedCount: Int {
        (try? commandQueue.failedCommands().count) ?? 0
    }

    /// Current sync progress.
    var progress: SyncProgress {
        syncEngine.progress
    }

    // MARK: - Init

    init(syncEngine: SyncEngine, commandQueue: CommandQueue) {
        self.syncEngine = syncEngine
        self.commandQueue = commandQueue
    }

    // MARK: - Methods

    /// Triggers a full sync cycle.
    func sync() async {
        await syncEngine.sync()
    }

    /// Retries all failed commands, then triggers a sync.
    func retryFailed() async {
        do {
            let failed = try commandQueue.failedCommands()
            for command in failed {
                commandQueue.retryFailed(command)
            }
        } catch {
            // Best effort
        }
        await syncEngine.sync()
    }

    /// Cancels (discards) all failed commands.
    func discardFailed() {
        do {
            let failed = try commandQueue.failedCommands()
            for command in failed {
                command.status = .cancelled
            }
        } catch {
            // Best effort
        }
    }
}

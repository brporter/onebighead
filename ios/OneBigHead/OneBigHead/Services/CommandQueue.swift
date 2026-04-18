import Foundation
import SwiftData

/// Manages SyncCommand records in SwiftData for offline-first sync.
final class CommandQueue {

    // MARK: - Dependencies

    private let modelContext: ModelContext

    // MARK: - Init

    init(modelContext: ModelContext) {
        self.modelContext = modelContext
    }

    // MARK: - Enqueue

    /// Creates and inserts a SyncCommand into the model context.
    @discardableResult
    func enqueue(
        entityType: String,
        operation: String,
        entityLocalId: UUID,
        payload: any Encodable,
        dependsOn: UUID? = nil
    ) throws -> SyncCommand {
        let encoder = JSONEncoder()
        let payloadData = try encoder.encode(AnyEncodable(payload))
        let command = SyncCommand(
            entityType: entityType,
            operation: operation,
            entityLocalId: entityLocalId,
            payload: payloadData,
            dependsOnCommandId: dependsOn
        )
        modelContext.insert(command)
        return command
    }

    // MARK: - Queries

    /// Returns all commands with status .pending, ordered by createdAt ascending.
    func pendingCommands() throws -> [SyncCommand] {
        let descriptor = FetchDescriptor<SyncCommand>(
            sortBy: [SortDescriptor(\.createdAt, order: .forward)]
        )
        return try modelContext.fetch(descriptor).filter { $0.status == .pending }
    }

    /// Returns all commands with status .executing.
    func executingCommands() throws -> [SyncCommand] {
        let descriptor = FetchDescriptor<SyncCommand>()
        return try modelContext.fetch(descriptor).filter { $0.status == .executing }
    }

    /// Returns all commands with status .failed.
    func failedCommands() throws -> [SyncCommand] {
        let descriptor = FetchDescriptor<SyncCommand>()
        return try modelContext.fetch(descriptor).filter { $0.status == .failed }
    }

    /// Count of pending commands.
    func pendingCommandCount() throws -> Int {
        let descriptor = FetchDescriptor<SyncCommand>()
        return try modelContext.fetch(descriptor).filter { $0.status == .pending }.count
    }

    // MARK: - State Transitions

    /// Sets status to .executing.
    func markExecuting(_ command: SyncCommand) {
        command.status = .executing
    }

    /// Sets status to .completed, stores serverResponseId.
    func markCompleted(_ command: SyncCommand, serverResponseId: Int?) {
        command.status = .completed
        command.serverResponseId = serverResponseId
    }

    /// Sets status to .failed, increments retryCount, stores lastError.
    func markFailed(_ command: SyncCommand, error: String) {
        command.status = .failed
        command.retryCount += 1
        command.lastError = error
    }

    /// Resets status to .pending.
    func retryFailed(_ command: SyncCommand) {
        command.status = .pending
    }

    // MARK: - Dependents

    /// Finds all commands that depend on this command and sets their status to .cancelled.
    func cancelDependents(of commandId: UUID) throws {
        let descriptor = FetchDescriptor<SyncCommand>()
        let dependents = try modelContext.fetch(descriptor).filter { $0.dependsOnCommandId == commandId }
        for dependent in dependents {
            dependent.status = .cancelled
        }
    }

    // MARK: - Cleanup

    /// Deletes all completed commands.
    func clearCompleted() throws {
        let descriptor = FetchDescriptor<SyncCommand>()
        let completed = try modelContext.fetch(descriptor).filter { $0.status == .completed }
        for command in completed {
            modelContext.delete(command)
        }
    }
}

// MARK: - AnyEncodable

/// Type-erased wrapper for encoding arbitrary Encodable values.
struct AnyEncodable: Encodable {
    private let _encode: (Encoder) throws -> Void

    init(_ wrapped: any Encodable) {
        _encode = { encoder in
            try wrapped.encode(to: encoder)
        }
    }

    func encode(to encoder: Encoder) throws {
        try _encode(encoder)
    }
}

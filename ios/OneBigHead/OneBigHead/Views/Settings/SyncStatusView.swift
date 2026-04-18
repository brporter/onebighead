import SwiftUI

/// A full settings page showing sync details and controls.
struct SyncStatusView: View {
    let syncViewModel: SyncViewModel
    let networkMonitor: NetworkMonitor

    var body: some View {
        List {
            statusSection
            pendingSection
            failedSection
            actionsSection
        }
        .navigationTitle("Sync Status")
    }

    // MARK: - Sections

    @ViewBuilder
    private var statusSection: some View {
        Section("Status") {
            HStack {
                Text("Connection")
                Spacer()
                Text(networkMonitor.isConnected ? "Online" : "Offline")
                    .foregroundStyle(networkMonitor.isConnected ? .green : .red)
            }

            HStack {
                Text("Sync State")
                Spacer()
                if syncViewModel.isSyncing {
                    HStack(spacing: 4) {
                        ProgressView()
                            .controlSize(.small)
                        Text(syncViewModel.progress.phase)
                    }
                } else {
                    Text("Idle")
                }
            }

            if let lastSync = syncViewModel.lastSyncDate {
                HStack {
                    Text("Last Sync")
                    Spacer()
                    Text(lastSync, style: .relative)
                        .foregroundStyle(.secondary)
                }
            }

            if let error = syncViewModel.syncError {
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    Text(error)
                        .foregroundStyle(.red)
                }
            }
        }
    }

    @ViewBuilder
    private var pendingSection: some View {
        Section("Pending Changes") {
            HStack {
                Text("Pending Commands")
                Spacer()
                Text("\(syncViewModel.pendingCount)")
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var failedSection: some View {
        if syncViewModel.failedCount > 0 {
            Section("Failed Commands") {
                HStack {
                    Text("Failed Commands")
                    Spacer()
                    Text("\(syncViewModel.failedCount)")
                        .foregroundStyle(.red)
                }

                Button("Retry All Failed") {
                    Task {
                        await syncViewModel.retryFailed()
                    }
                }

                Button("Discard All Failed", role: .destructive) {
                    syncViewModel.discardFailed()
                }
            }
        }
    }

    @ViewBuilder
    private var actionsSection: some View {
        Section("Actions") {
            Button("Sync Now") {
                Task {
                    await syncViewModel.sync()
                }
            }
            .disabled(!networkMonitor.isConnected || syncViewModel.isSyncing)
        }
    }
}

import SwiftUI

/// A toolbar button component showing sync state.
struct SyncButton: View {
    let syncViewModel: SyncViewModel
    let networkMonitor: NetworkMonitor
    var onTap: () -> Void = {}

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 4) {
                iconView
                textView
            }
        }
        .disabled(!networkMonitor.isConnected || syncViewModel.isSyncing)
    }

    @ViewBuilder
    private var iconView: some View {
        if syncViewModel.isSyncing {
            ProgressView()
                .controlSize(.small)
        } else if syncViewModel.failedCount > 0 {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.red)
        } else if syncViewModel.pendingCount > 0 {
            ZStack(alignment: .topTrailing) {
                Image(systemName: "cloud.arrow.up")
                Text("\(syncViewModel.pendingCount)")
                    .font(.caption2)
                    .padding(2)
                    .background(Color.blue)
                    .clipShape(Circle())
                    .foregroundStyle(.white)
                    .offset(x: 6, y: -6)
            }
        } else {
            Image(systemName: "checkmark.circle")
                .foregroundStyle(.green)
        }
    }

    @ViewBuilder
    private var textView: some View {
        if syncViewModel.isSyncing {
            Text("Syncing...")
                .font(.caption)
        } else if syncViewModel.failedCount > 0 {
            Text("Errors")
                .font(.caption)
        } else if syncViewModel.pendingCount > 0 {
            Text("Pending")
                .font(.caption)
        } else if let lastSync = syncViewModel.lastSyncDate {
            Text("Synced \(lastSync, style: .relative) ago")
                .font(.caption)
        } else {
            Text("Synced")
                .font(.caption)
        }
    }
}

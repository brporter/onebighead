import SwiftUI

/// The main settings screen with navigation to account, workspace, and sync settings.
struct SettingsView: View {
    let authService: AuthService
    let apiClient: APIClient
    let syncViewModel: SyncViewModel
    let networkMonitor: NetworkMonitor

    var body: some View {
        NavigationStack {
            List {
                accountSection
                syncSection
                aboutSection
            }
            .navigationTitle("Settings")
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private var accountSection: some View {
        Section {
            NavigationLink {
                AccountView(authService: authService)
            } label: {
                Label("Account", systemImage: "person.circle")
            }

            NavigationLink {
                WorkspaceSwitcherView(
                    apiClient: apiClient,
                    authService: authService,
                    currentWorkspaceId: authService.currentUser?.workspaceId ?? 0
                )
            } label: {
                Label("Workspace", systemImage: "building.2")
            }
        }
    }

    @ViewBuilder
    private var syncSection: some View {
        Section {
            NavigationLink {
                SyncStatusView(syncViewModel: syncViewModel, networkMonitor: networkMonitor)
            } label: {
                Label("Sync Status", systemImage: "arrow.triangle.2.circlepath")
            }
        }
    }

    @ViewBuilder
    private var aboutSection: some View {
        Section {
            HStack {
                Text("Version")
                Spacer()
                Text(appVersion)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Helpers

    private var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "\(version) (\(build))"
    }
}

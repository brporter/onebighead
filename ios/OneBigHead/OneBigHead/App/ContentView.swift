import SwiftUI
import SwiftData

/// The root content view that manages authentication flow and the main tab interface.
struct ContentView: View {
    let apiClient: APIClient
    let authService: AuthService
    let networkMonitor: NetworkMonitor

    @Environment(\.modelContext) private var modelContext

    @State private var hasCheckedAuth = false

    var body: some View {
        Group {
            if !hasCheckedAuth {
                ProgressView("Loading...")
            } else if !authService.isAuthenticated {
                SignInView(viewModel: AuthViewModel(authService: authService))
            } else if let user = authService.currentUser, !user.hasAcceptedTerms {
                AcceptTermsView(authService: authService)
            } else if let user = authService.currentUser, !user.hasCompletedWelcome {
                WelcomeView(authService: authService)
            } else {
                mainTabView
            }
        }
        .task {
            await authService.checkAuthStatus()
            hasCheckedAuth = true
        }
    }

    // MARK: - Main Tab View

    @ViewBuilder
    private var mainTabView: some View {
        TabView {
            CollectionListView(
                workspaceId: authService.currentUser?.workspaceId ?? 0,
                apiClient: apiClient
            )
            .tabItem {
                Label("Collections", systemImage: "folder")
            }

            SettingsView(
                authService: authService,
                apiClient: apiClient,
                syncViewModel: makeSyncViewModel(),
                networkMonitor: networkMonitor
            )
            .tabItem {
                Label("Settings", systemImage: "gear")
            }
        }
    }

    // MARK: - Helpers

    private func makeSyncViewModel() -> SyncViewModel {
        let queue = CommandQueue(modelContext: modelContext)
        let engine = SyncEngine(
            apiClient: apiClient,
            commandQueue: queue,
            modelContext: modelContext
        )
        return SyncViewModel(syncEngine: engine, commandQueue: queue)
    }
}

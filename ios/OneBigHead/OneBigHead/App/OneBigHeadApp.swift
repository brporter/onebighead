import SwiftUI
import SwiftData
import MSAL

@main
struct OneBigHeadApp: App {
    @State private var apiClient = APIClient()
    @State private var networkMonitor = NetworkMonitor()
    @State private var authService: AuthService

    init() {
        let client = APIClient()
        _apiClient = State(initialValue: client)
        _authService = State(initialValue: AuthService(apiClient: client))
    }

    var body: some Scene {
        WindowGroup {
            ZStack(alignment: .top) {
                ContentView(
                    apiClient: apiClient,
                    authService: authService,
                    networkMonitor: networkMonitor
                )

                if !networkMonitor.isConnected {
                    offlineBanner
                }
            }
            .onOpenURL { url in
                MSALPublicClientApplication.handleMSALResponse(
                    url,
                    sourceApplication: nil
                )
            }
        }
        .modelContainer(for: [
            LocalCollection.self,
            LocalCategory.self,
            LocalItem.self,
            LocalPendingImage.self,
            SyncCommand.self
        ])
    }

    // MARK: - Offline Banner

    @ViewBuilder
    private var offlineBanner: some View {
        HStack(spacing: 6) {
            Image(systemName: "wifi.slash")
                .font(.caption)
            Text("No Internet Connection")
                .font(.caption)
                .fontWeight(.medium)
        }
        .foregroundStyle(.white)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity)
        .background(Color.red)
        .transition(.move(edge: .top))
        .animation(.easeInOut, value: networkMonitor.isConnected)
    }
}

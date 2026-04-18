import Foundation

// MARK: - APIClientWorkspaceProtocol

/// Protocol abstracting workspace API calls for testability.
protocol APIClientWorkspaceProtocol {
    func getWorkspaces() async throws -> [WorkspaceMembershipDTO]
    func switchWorkspace(id: Int) async throws -> SwitchWorkspaceResponse
}

extension APIClient: APIClientWorkspaceProtocol {}

// MARK: - WorkspaceSwitcherViewModel

/// ViewModel for the workspace switcher view.
@Observable
final class WorkspaceSwitcherViewModel {
    // MARK: - Properties

    /// The list of workspace memberships available to the user.
    private(set) var workspaces: [WorkspaceMembershipDTO] = []

    /// Whether workspace data is currently loading.
    private(set) var isLoading: Bool = false

    /// The last error message, if any.
    private(set) var error: String?

    /// Whether a workspace switch is in progress.
    private(set) var isSwitching: Bool = false

    /// The ID of the current workspace.
    var currentWorkspaceId: Int

    // MARK: - Private

    private let apiClient: APIClientWorkspaceProtocol
    private let authService: AuthServiceProtocol

    // MARK: - Init

    init(apiClient: APIClientWorkspaceProtocol, authService: AuthServiceProtocol, currentWorkspaceId: Int) {
        self.apiClient = apiClient
        self.authService = authService
        self.currentWorkspaceId = currentWorkspaceId
    }

    // MARK: - Methods

    /// Loads the list of workspaces from the API.
    func loadWorkspaces() async {
        isLoading = true
        error = nil
        defer { isLoading = false }

        do {
            workspaces = try await apiClient.getWorkspaces()
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Switches to the workspace with the given ID.
    func switchWorkspace(id: Int) async {
        isSwitching = true
        error = nil
        defer { isSwitching = false }

        do {
            let response = try await apiClient.switchWorkspace(id: id)
            currentWorkspaceId = response.workspaceId
            await authService.checkAuthStatus()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

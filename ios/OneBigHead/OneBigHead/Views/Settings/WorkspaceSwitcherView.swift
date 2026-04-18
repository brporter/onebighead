import SwiftUI

/// Displays available workspaces and allows switching between them.
struct WorkspaceSwitcherView: View {
    @State private var viewModel: WorkspaceSwitcherViewModel

    init(apiClient: APIClientWorkspaceProtocol, authService: AuthServiceProtocol, currentWorkspaceId: Int) {
        _viewModel = State(initialValue: WorkspaceSwitcherViewModel(
            apiClient: apiClient,
            authService: authService,
            currentWorkspaceId: currentWorkspaceId
        ))
    }

    var body: some View {
        Group {
            if viewModel.isLoading {
                ProgressView("Loading workspaces...")
            } else if let error = viewModel.error {
                ContentUnavailableView {
                    Label("Error", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(error)
                } actions: {
                    Button("Retry") {
                        Task {
                            await viewModel.loadWorkspaces()
                        }
                    }
                }
            } else if viewModel.workspaces.isEmpty {
                ContentUnavailableView(
                    "No Workspaces",
                    systemImage: "building.2",
                    description: Text("No workspaces available.")
                )
            } else {
                List(viewModel.workspaces) { workspace in
                    Button {
                        Task {
                            await viewModel.switchWorkspace(id: workspace.workspaceId)
                        }
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(workspace.workspaceName)
                                    .font(.body)
                                    .foregroundStyle(.primary)
                                Text(workspace.role.capitalized)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            if workspace.workspaceId == viewModel.currentWorkspaceId {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.blue)
                            }
                        }
                    }
                    .disabled(viewModel.isSwitching)
                }
            }
        }
        .navigationTitle("Workspace")
        .task {
            await viewModel.loadWorkspaces()
        }
        .overlay {
            if viewModel.isSwitching {
                ZStack {
                    Color.black.opacity(0.3)
                        .ignoresSafeArea()
                    ProgressView("Switching...")
                        .padding()
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
            }
        }
    }
}

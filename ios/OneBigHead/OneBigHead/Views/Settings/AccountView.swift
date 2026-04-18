import SwiftUI

/// Displays current user account information and provides a logout option.
struct AccountView: View {
    let authService: AuthService

    @State private var showingLogoutConfirmation = false

    var body: some View {
        List {
            userInfoSection
            logoutSection
        }
        .navigationTitle("Account")
        .confirmationDialog(
            "Are you sure you want to log out?",
            isPresented: $showingLogoutConfirmation,
            titleVisibility: .visible
        ) {
            Button("Log Out", role: .destructive) {
                Task {
                    await authService.logout()
                }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private var userInfoSection: some View {
        Section("User Info") {
            if let user = authService.currentUser {
                if let displayName = user.displayName {
                    HStack {
                        Text("Name")
                        Spacer()
                        Text(displayName)
                            .foregroundStyle(.secondary)
                    }
                }

                HStack {
                    Text("Email")
                    Spacer()
                    Text(user.email)
                        .foregroundStyle(.secondary)
                }

                HStack {
                    Text("Workspace")
                    Spacer()
                    Text(user.workspaceName)
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("Not signed in")
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var logoutSection: some View {
        Section {
            Button("Log Out", role: .destructive) {
                showingLogoutConfirmation = true
            }
        }

        if let error = authService.error {
            Section {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.footnote)
            }
        }
    }
}

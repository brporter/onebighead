import SwiftUI

// MARK: - WelcomeView

/// Shown after the user accepts terms but before completing the welcome flow.
struct WelcomeView: View {
    let authService: AuthService

    @State private var workspaceName: String = ""
    @State private var isCompleting = false

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            VStack(spacing: 16) {
                Image(systemName: "hand.wave.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.blue)

                Text("Welcome to OneBigHead!")
                    .font(.title)
                    .fontWeight(.bold)

                Text("Let's get you set up. You can name your workspace or use the default.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            .padding(.bottom, 32)

            VStack(alignment: .leading, spacing: 8) {
                Text("Workspace Name")
                    .font(.subheadline)
                    .fontWeight(.medium)

                TextField("My Workspace", text: $workspaceName)
                    .textFieldStyle(.roundedBorder)
            }
            .padding(.horizontal, 32)

            Button {
                isCompleting = true
                Task {
                    let name = workspaceName.trimmingCharacters(in: .whitespacesAndNewlines)
                    await authService.completeWelcome(workspaceName: name.isEmpty ? nil : name)
                    isCompleting = false
                }
            } label: {
                if isCompleting {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                        .frame(height: 50)
                } else {
                    Text("Get Started")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .frame(height: 50)
                }
            }
            .buttonStyle(.borderedProminent)
            .padding(.horizontal, 32)
            .padding(.top, 24)
            .disabled(isCompleting)

            if let error = authService.error {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                    .padding(.top, 12)
            }

            Spacer()
            Spacer()
        }
    }
}

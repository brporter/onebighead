import SwiftUI
import AuthenticationServices

// MARK: - SignInView

/// The sign-in screen offering Apple, Google, and Microsoft authentication options.
struct SignInView: View {
    let viewModel: AuthViewModel

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            // App logo and title
            VStack(spacing: 12) {
                Image(systemName: "cube.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(.blue)

                Text("OneBigHead")
                    .font(.largeTitle)
                    .fontWeight(.bold)

                Text("Organize your collections")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding(.bottom, 48)

            // Sign-in buttons
            VStack(spacing: 16) {
                // Apple
                SignInWithAppleButton(.signIn) { request in
                    request.requestedScopes = [.email, .fullName]
                } onCompletion: { _ in
                    // The actual sign-in is handled via the view model
                }
                .signInWithAppleButtonStyle(.black)
                .frame(height: 50)
                .cornerRadius(8)
                .overlay {
                    // Invisible tap target that uses the view model
                    Color.clear
                        .contentShape(Rectangle())
                        .onTapGesture {
                            Task {
                                await viewModel.signInWithApple()
                            }
                        }
                }

                // Google
                Button {
                    Task {
                        if let window = UIApplication.shared.connectedScenes
                            .compactMap({ $0 as? UIWindowScene })
                            .flatMap({ $0.windows })
                            .first(where: { $0.isKeyWindow }) {
                            await viewModel.signInWithGoogle(from: window)
                        }
                    }
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: "g.circle.fill")
                            .font(.title2)
                        Text("Sign in with Google")
                            .fontWeight(.medium)
                    }
                    .frame(maxWidth: .infinity)
                    .frame(height: 50)
                    .background(Color(.systemBackground))
                    .foregroundStyle(.primary)
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color(.systemGray3), lineWidth: 1)
                    )
                }

                // Microsoft
                Button {
                    Task {
                        if let viewController = UIApplication.shared.connectedScenes
                            .compactMap({ $0 as? UIWindowScene })
                            .flatMap({ $0.windows })
                            .first(where: { $0.isKeyWindow })?
                            .rootViewController {
                            await viewModel.signInWithMicrosoft(from: viewController)
                        }
                    }
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: "building.2.fill")
                            .font(.title2)
                        Text("Sign in with Microsoft")
                            .fontWeight(.medium)
                    }
                    .frame(maxWidth: .infinity)
                    .frame(height: 50)
                    .background(Color(.systemBackground))
                    .foregroundStyle(.primary)
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color(.systemGray3), lineWidth: 1)
                    )
                }
            }
            .padding(.horizontal, 32)
            .disabled(viewModel.isSigningIn)

            // Loading indicator
            if viewModel.isSigningIn {
                ProgressView()
                    .padding(.top, 20)
            }

            // Error message
            if let errorMessage = viewModel.errorMessage {
                Text(errorMessage)
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

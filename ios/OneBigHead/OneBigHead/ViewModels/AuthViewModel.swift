import Foundation
import UIKit

// MARK: - AuthViewModel

/// View model for the sign-in screen, delegating auth operations to AuthService.
@Observable
final class AuthViewModel {
    // MARK: - Properties

    /// The auth service used for sign-in operations.
    let authService: AuthService

    /// Whether a sign-in operation is currently in progress.
    var isSigningIn: Bool {
        authService.isLoading
    }

    /// The last error message from a sign-in attempt, if any.
    var errorMessage: String? {
        authService.error
    }

    // MARK: - Init

    init(authService: AuthService) {
        self.authService = authService
    }

    // MARK: - Actions

    /// Initiates Apple sign-in.
    func signInWithApple() async {
        await authService.signInWithApple()
    }

    /// Initiates Google sign-in from the given window.
    func signInWithGoogle(from window: UIWindow) async {
        await authService.signInWithGoogle(presentingWindow: window)
    }

    /// Initiates Microsoft sign-in from the given view controller.
    func signInWithMicrosoft(from viewController: UIViewController) async {
        await authService.signInWithMicrosoft(presentingViewController: viewController)
    }
}

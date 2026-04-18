import Foundation
import AuthenticationServices
import GoogleSignIn
import MSAL

// MARK: - AuthServiceProtocol

/// Protocol for AuthService to enable testing with mocks.
protocol AuthServiceProtocol {
    var currentUser: MeResponse? { get }
    var isAuthenticated: Bool { get }
    var isLoading: Bool { get }
    var error: String? { get }

    func signInWithApple() async
    func signInWithGoogle(presentingWindow: UIWindow) async
    func signInWithMicrosoft(presentingViewController: UIViewController) async
    func checkAuthStatus() async
    func logout() async
    func acceptTerms() async
    func completeWelcome(workspaceName: String?) async
}

// MARK: - APIClientProtocol

/// Protocol abstracting the API calls needed by AuthService, enabling mock injection for tests.
protocol APIClientAuthProtocol {
    func authCallback(token: String, provider: String) async throws -> AuthCallbackResponse
    func getMe() async throws -> MeResponse
    func logout() async throws
    func acceptTerms() async throws -> AcceptTermsResponse
    func completeWelcome(workspaceName: String?) async throws -> CompleteWelcomeResponse
}

extension APIClient: APIClientAuthProtocol {}

// MARK: - AppleSignInDelegate

/// Handles the Apple Sign In authorization flow via ASAuthorizationController.
final class AppleSignInDelegate: NSObject, ASAuthorizationControllerDelegate, @unchecked Sendable {
    private var continuation: CheckedContinuation<String, Error>?

    func performSignIn() async throws -> String {
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let provider = ASAuthorizationAppleIDProvider()
            let request = provider.createRequest()
            request.requestedScopes = [.email, .fullName]
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.performRequests()
        }
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        if let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
           let tokenData = credential.identityToken,
           let token = String(data: tokenData, encoding: .utf8) {
            continuation?.resume(returning: token)
        } else {
            continuation?.resume(throwing: AuthServiceError.missingToken)
        }
        continuation = nil
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

// MARK: - AuthServiceError

enum AuthServiceError: LocalizedError {
    case missingToken
    case signInCancelled
    case configurationError(String)

    var errorDescription: String? {
        switch self {
        case .missingToken:
            return "Failed to obtain authentication token."
        case .signInCancelled:
            return "Sign in was cancelled."
        case .configurationError(let message):
            return "Configuration error: \(message)"
        }
    }
}

// MARK: - AuthService

/// Manages authentication state and coordinates with auth providers (Apple, Google, Microsoft).
@Observable
final class AuthService: AuthServiceProtocol {
    // MARK: - Properties

    /// The current authenticated user, or nil if not signed in.
    private(set) var currentUser: MeResponse?

    /// Whether the user is currently authenticated.
    var isAuthenticated: Bool {
        currentUser != nil
    }

    /// Whether an auth operation is in progress.
    private(set) var isLoading: Bool = false

    /// The last error message, if any.
    private(set) var error: String?

    // MARK: - Private

    private let apiClient: APIClientAuthProtocol

    // MARK: - Init

    init(apiClient: APIClientAuthProtocol) {
        self.apiClient = apiClient
    }

    // MARK: - Sign In

    /// Initiates Sign in with Apple and authenticates with the backend.
    func signInWithApple() async {
        isLoading = true
        error = nil
        defer { isLoading = false }

        do {
            let delegate = AppleSignInDelegate()
            let token = try await delegate.performSignIn()
            _ = try await apiClient.authCallback(token: token, provider: "apple")
            await checkAuthStatus()
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Initiates Sign in with Google and authenticates with the backend.
    func signInWithGoogle(presentingWindow: UIWindow) async {
        isLoading = true
        error = nil
        defer { isLoading = false }

        do {
            let result = try await GIDSignIn.sharedInstance.signIn(withPresenting: presentingWindow.rootViewController!)
            guard let idToken = result.user.idToken?.tokenString else {
                throw AuthServiceError.missingToken
            }
            _ = try await apiClient.authCallback(token: idToken, provider: "google")
            await checkAuthStatus()
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Initiates Sign in with Microsoft and authenticates with the backend.
    func signInWithMicrosoft(presentingViewController: UIViewController) async {
        isLoading = true
        error = nil
        defer { isLoading = false }

        do {
            guard let configPath = Bundle.main.path(forResource: "MSAL", ofType: "json"),
                  let configData = FileManager.default.contents(atPath: configPath) else {
                throw AuthServiceError.configurationError("MSAL configuration file not found.")
            }

            let config = try JSONSerialization.jsonObject(with: configData) as? [String: Any]
            guard let clientId = config?["client_id"] as? String else {
                throw AuthServiceError.configurationError("Missing client_id in MSAL config.")
            }

            let msalConfig = MSALPublicClientApplicationConfig(clientId: clientId)

            // Disable keychain sharing by scoping the MSAL token cache to this app's
            // own bundle identifier. MSAL's default group (`com.microsoft.adalcache`)
            // requires the `keychain-access-groups` entitlement, and writes fail with
            // MSALErrorInternal (-50000) when that entitlement isn't present. We don't
            // need SSO with other Microsoft apps, so the app-scoped group is sufficient.
            if let bundleIdentifier = Bundle.main.bundleIdentifier {
                msalConfig.cacheConfig.keychainSharingGroup = bundleIdentifier
            }

            let application = try MSALPublicClientApplication(configuration: msalConfig)

            let webViewParameters = MSALWebviewParameters(authPresentationViewController: presentingViewController)
            // Do not pass `openid`, `profile`, or `offline_access` — MSAL treats those
            // as reserved and adds them automatically. We only need the ID token for
            // the backend, so we request the non-reserved `User.Read` scope as a valid
            // placeholder. The ID token MSAL returns still contains the standard
            // profile/email claims.
            let parameters = MSALInteractiveTokenParameters(scopes: ["User.Read"],
                                                            webviewParameters: webViewParameters)

            let result = try await application.acquireToken(with: parameters)
            guard let idToken = result.idToken else {
                throw AuthServiceError.missingToken
            }

            let callbackResponse = try await apiClient.authCallback(token: idToken, provider: "microsoft")
            print("[Microsoft Sign-In] authCallback succeeded: email=\(callbackResponse.email) workspaceId=\(callbackResponse.workspaceId)")
            logAuthCookies()

            await checkAuthStatus()
            if currentUser == nil {
                print("[Microsoft Sign-In] checkAuthStatus returned no user. error=\(error ?? "nil")")
            } else {
                print("[Microsoft Sign-In] checkAuthStatus loaded user: \(currentUser?.email ?? "?")")
            }
        } catch {
            self.error = Self.describeAuthError(error)
            print("[Microsoft Sign-In] \(Self.describeAuthError(error))")
        }
    }

    /// Logs the cookies currently stored for the API host, for debugging auth flow issues.
    private func logAuthCookies() {
        guard let baseURLString = (apiClient as? APIClient)?.baseURL,
              let url = URL(string: baseURLString) else {
            return
        }
        let cookies = HTTPCookieStorage.shared.cookies(for: url) ?? []
        if cookies.isEmpty {
            print("[Microsoft Sign-In] No cookies stored for \(baseURLString) after authCallback.")
        } else {
            for cookie in cookies {
                print("[Microsoft Sign-In] Cookie: name=\(cookie.name) domain=\(cookie.domain) path=\(cookie.path) secure=\(cookie.isSecure) httpOnly=\(cookie.isHTTPOnly)")
            }
        }
    }

    /// Builds a detailed diagnostic string from an NSError, expanding MSAL-specific
    /// userInfo keys so callers can see the real underlying cause of `MSALErrorInternal`.
    static func describeAuthError(_ error: Error) -> String {
        let nsError = error as NSError
        var parts: [String] = []
        parts.append("domain=\(nsError.domain) code=\(nsError.code)")

        if let description = nsError.userInfo["MSALErrorDescriptionKey"] as? String {
            parts.append("description=\(description)")
        } else if !nsError.localizedDescription.isEmpty {
            parts.append("localizedDescription=\(nsError.localizedDescription)")
        }

        if let internalCode = nsError.userInfo["MSALInternalErrorCodeKey"] as? Int {
            parts.append("internalCode=\(internalCode)")
        }
        if let oauthError = nsError.userInfo["MSALOAuthErrorKey"] as? String {
            parts.append("oauthError=\(oauthError)")
        }
        if let oauthSubError = nsError.userInfo["MSALOAuthSubErrorKey"] as? String {
            parts.append("oauthSubError=\(oauthSubError)")
        }
        if let correlationId = nsError.userInfo["MSALCorrelationIDKey"] as? String {
            parts.append("correlationId=\(correlationId)")
        }
        if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? NSError {
            parts.append("underlying=(domain=\(underlying.domain) code=\(underlying.code) \(underlying.localizedDescription))")
        }

        return parts.joined(separator: " | ")
    }

    // MARK: - Auth Status

    /// Checks current authentication status by calling the /me endpoint.
    func checkAuthStatus() async {
        do {
            currentUser = try await apiClient.getMe()
            error = nil
        } catch {
            currentUser = nil
            self.error = Self.describeAuthError(error)
            print("[checkAuthStatus] getMe failed: \(Self.describeAuthError(error))")
        }
    }

    // MARK: - Logout

    /// Signs the user out and clears local state.
    func logout() async {
        isLoading = true
        error = nil
        defer { isLoading = false }

        do {
            try await apiClient.logout()
        } catch {
            self.error = error.localizedDescription
        }
        currentUser = nil
    }

    // MARK: - Onboarding

    /// Accepts the terms of service and refreshes the user.
    func acceptTerms() async {
        isLoading = true
        error = nil
        defer { isLoading = false }

        do {
            _ = try await apiClient.acceptTerms()
            await checkAuthStatus()
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Completes the welcome flow with an optional workspace name and refreshes the user.
    func completeWelcome(workspaceName: String?) async {
        isLoading = true
        error = nil
        defer { isLoading = false }

        do {
            _ = try await apiClient.completeWelcome(workspaceName: workspaceName)
            await checkAuthStatus()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

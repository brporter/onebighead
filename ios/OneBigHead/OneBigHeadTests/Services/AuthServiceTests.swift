import XCTest
@testable import OneBigHead

// MARK: - MockAPIClientAuth

/// A mock implementation of APIClientAuthProtocol for testing AuthService.
final class MockAPIClientAuth: APIClientAuthProtocol {
    // MARK: - Call Tracking

    var authCallbackCallCount = 0
    var authCallbackLastToken: String?
    var authCallbackLastProvider: String?
    var getMeCallCount = 0
    var logoutCallCount = 0
    var acceptTermsCallCount = 0
    var completeWelcomeCallCount = 0
    var completeWelcomeLastWorkspaceName: String?

    // MARK: - Stubs

    var authCallbackResult: Result<AuthCallbackResponse, Error> = .success(
        AuthCallbackResponse(success: true, email: "test@example.com", workspaceId: 1, workspaceName: "Test WS")
    )
    var getMeResult: Result<MeResponse, Error> = .success(
        MeResponse(userId: 1, email: "test@example.com", displayName: "Test User",
                   workspaceId: 1, workspaceName: "Test WS",
                   hasAcceptedTerms: true, hasCompletedWelcome: true)
    )
    var logoutResult: Result<Void, Error> = .success(())
    var acceptTermsResult: Result<AcceptTermsResponse, Error> = .success(
        AcceptTermsResponse(hasAcceptedTerms: true, acceptedTermsAt: "2026-01-01T00:00:00Z")
    )
    var completeWelcomeResult: Result<CompleteWelcomeResponse, Error> = .success(
        CompleteWelcomeResponse(workspaceId: 1, workspaceName: "Test WS", hasCompletedWelcome: true)
    )

    // MARK: - APIClientAuthProtocol

    func authCallback(token: String, provider: String) async throws -> AuthCallbackResponse {
        authCallbackCallCount += 1
        authCallbackLastToken = token
        authCallbackLastProvider = provider
        return try authCallbackResult.get()
    }

    func getMe() async throws -> MeResponse {
        getMeCallCount += 1
        return try getMeResult.get()
    }

    func logout() async throws {
        logoutCallCount += 1
        try logoutResult.get()
    }

    func acceptTerms() async throws -> AcceptTermsResponse {
        acceptTermsCallCount += 1
        return try acceptTermsResult.get()
    }

    func completeWelcome(workspaceName: String?) async throws -> CompleteWelcomeResponse {
        completeWelcomeCallCount += 1
        completeWelcomeLastWorkspaceName = workspaceName
        return try completeWelcomeResult.get()
    }
}

// MARK: - AuthServiceTests

final class AuthServiceTests: XCTestCase {
    private var mockClient: MockAPIClientAuth!
    private var authService: AuthService!

    override func setUp() {
        super.setUp()
        mockClient = MockAPIClientAuth()
        authService = AuthService(apiClient: mockClient)
    }

    override func tearDown() {
        authService = nil
        mockClient = nil
        super.tearDown()
    }

    // MARK: - Initial State

    func testInitialStateHasNoUser() {
        XCTAssertNil(authService.currentUser)
    }

    func testInitialStateIsNotAuthenticated() {
        XCTAssertFalse(authService.isAuthenticated)
    }

    func testInitialStateIsNotLoading() {
        XCTAssertFalse(authService.isLoading)
    }

    func testInitialStateHasNoError() {
        XCTAssertNil(authService.error)
    }

    // MARK: - checkAuthStatus

    func testCheckAuthStatusSetsCurrentUserOnSuccess() async {
        let expectedUser = MeResponse(
            userId: 42, email: "user@test.com", displayName: "Test",
            workspaceId: 2, workspaceName: "WS",
            hasAcceptedTerms: true, hasCompletedWelcome: true
        )
        mockClient.getMeResult = .success(expectedUser)

        await authService.checkAuthStatus()

        XCTAssertNotNil(authService.currentUser)
        XCTAssertEqual(authService.currentUser?.userId, 42)
        XCTAssertEqual(authService.currentUser?.email, "user@test.com")
        XCTAssertTrue(authService.isAuthenticated)
        XCTAssertEqual(mockClient.getMeCallCount, 1)
    }

    func testCheckAuthStatusClearsCurrentUserOnFailure() async {
        // First, set up a user
        mockClient.getMeResult = .success(
            MeResponse(userId: 1, email: "a@b.com", displayName: nil,
                       workspaceId: 1, workspaceName: "WS",
                       hasAcceptedTerms: true, hasCompletedWelcome: true)
        )
        await authService.checkAuthStatus()
        XCTAssertNotNil(authService.currentUser)

        // Now simulate failure
        mockClient.getMeResult = .failure(APIError.unauthorized)
        await authService.checkAuthStatus()

        XCTAssertNil(authService.currentUser)
        XCTAssertFalse(authService.isAuthenticated)
    }

    func testCheckAuthStatusClearsErrorOnSuccess() async {
        // Set error via a failed logout
        mockClient.logoutResult = .failure(APIError.networkError(NSError(domain: "", code: -1)))
        await authService.logout()
        XCTAssertNotNil(authService.error)

        // Now checkAuthStatus should clear error on success
        mockClient.getMeResult = .success(
            MeResponse(userId: 1, email: "a@b.com", displayName: nil,
                       workspaceId: 1, workspaceName: "WS",
                       hasAcceptedTerms: true, hasCompletedWelcome: true)
        )
        await authService.checkAuthStatus()
        XCTAssertNil(authService.error)
    }

    // MARK: - logout

    func testLogoutClearsCurrentUser() async {
        // Set up authenticated state
        mockClient.getMeResult = .success(
            MeResponse(userId: 1, email: "a@b.com", displayName: nil,
                       workspaceId: 1, workspaceName: "WS",
                       hasAcceptedTerms: true, hasCompletedWelcome: true)
        )
        await authService.checkAuthStatus()
        XCTAssertTrue(authService.isAuthenticated)

        await authService.logout()

        XCTAssertNil(authService.currentUser)
        XCTAssertFalse(authService.isAuthenticated)
        XCTAssertEqual(mockClient.logoutCallCount, 1)
    }

    func testLogoutClearsUserEvenOnApiFailure() async {
        // Set up authenticated state
        mockClient.getMeResult = .success(
            MeResponse(userId: 1, email: "a@b.com", displayName: nil,
                       workspaceId: 1, workspaceName: "WS",
                       hasAcceptedTerms: true, hasCompletedWelcome: true)
        )
        await authService.checkAuthStatus()
        XCTAssertTrue(authService.isAuthenticated)

        mockClient.logoutResult = .failure(APIError.networkError(NSError(domain: "", code: -1)))
        await authService.logout()

        XCTAssertNil(authService.currentUser)
        XCTAssertFalse(authService.isAuthenticated)
        XCTAssertNotNil(authService.error)
    }

    func testLogoutSetsLoadingFalseAfterCompletion() async {
        await authService.logout()
        XCTAssertFalse(authService.isLoading)
    }

    // MARK: - acceptTerms

    func testAcceptTermsCallsApiAndRefreshesUser() async {
        mockClient.acceptTermsResult = .success(
            AcceptTermsResponse(hasAcceptedTerms: true, acceptedTermsAt: "2026-01-01")
        )
        mockClient.getMeResult = .success(
            MeResponse(userId: 1, email: "a@b.com", displayName: nil,
                       workspaceId: 1, workspaceName: "WS",
                       hasAcceptedTerms: true, hasCompletedWelcome: false)
        )

        await authService.acceptTerms()

        XCTAssertEqual(mockClient.acceptTermsCallCount, 1)
        XCTAssertEqual(mockClient.getMeCallCount, 1)
        XCTAssertNotNil(authService.currentUser)
        XCTAssertTrue(authService.currentUser?.hasAcceptedTerms ?? false)
    }

    func testAcceptTermsSetsErrorOnFailure() async {
        mockClient.acceptTermsResult = .failure(APIError.serverError(statusCode: 500, message: "fail"))

        await authService.acceptTerms()

        XCTAssertNotNil(authService.error)
        XCTAssertEqual(mockClient.acceptTermsCallCount, 1)
        XCTAssertEqual(mockClient.getMeCallCount, 0)
    }

    func testAcceptTermsSetsLoadingFalseAfterCompletion() async {
        await authService.acceptTerms()
        XCTAssertFalse(authService.isLoading)
    }

    // MARK: - completeWelcome

    func testCompleteWelcomeCallsApiWithWorkspaceName() async {
        mockClient.completeWelcomeResult = .success(
            CompleteWelcomeResponse(workspaceId: 1, workspaceName: "My WS", hasCompletedWelcome: true)
        )
        mockClient.getMeResult = .success(
            MeResponse(userId: 1, email: "a@b.com", displayName: nil,
                       workspaceId: 1, workspaceName: "My WS",
                       hasAcceptedTerms: true, hasCompletedWelcome: true)
        )

        await authService.completeWelcome(workspaceName: "My WS")

        XCTAssertEqual(mockClient.completeWelcomeCallCount, 1)
        XCTAssertEqual(mockClient.completeWelcomeLastWorkspaceName, "My WS")
        XCTAssertEqual(mockClient.getMeCallCount, 1)
        XCTAssertNotNil(authService.currentUser)
    }

    func testCompleteWelcomeCallsApiWithNilWorkspaceName() async {
        await authService.completeWelcome(workspaceName: nil)

        XCTAssertEqual(mockClient.completeWelcomeCallCount, 1)
        XCTAssertNil(mockClient.completeWelcomeLastWorkspaceName)
    }

    func testCompleteWelcomeSetsErrorOnFailure() async {
        mockClient.completeWelcomeResult = .failure(APIError.serverError(statusCode: 500, message: "fail"))

        await authService.completeWelcome(workspaceName: "Test")

        XCTAssertNotNil(authService.error)
        XCTAssertEqual(mockClient.completeWelcomeCallCount, 1)
        XCTAssertEqual(mockClient.getMeCallCount, 0)
    }

    func testCompleteWelcomeSetsLoadingFalseAfterCompletion() async {
        await authService.completeWelcome(workspaceName: nil)
        XCTAssertFalse(authService.isLoading)
    }

    // MARK: - isAuthenticated computed property

    func testIsAuthenticatedIsTrueWhenUserExists() async {
        mockClient.getMeResult = .success(
            MeResponse(userId: 1, email: "a@b.com", displayName: nil,
                       workspaceId: 1, workspaceName: "WS",
                       hasAcceptedTerms: true, hasCompletedWelcome: true)
        )
        await authService.checkAuthStatus()
        XCTAssertTrue(authService.isAuthenticated)
    }

    func testIsAuthenticatedIsFalseWhenUserIsNil() {
        XCTAssertFalse(authService.isAuthenticated)
    }

    // MARK: - AuthServiceError

    func testAuthServiceErrorMissingTokenDescription() {
        let error = AuthServiceError.missingToken
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("token"))
    }

    func testAuthServiceErrorSignInCancelledDescription() {
        let error = AuthServiceError.signInCancelled
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("cancelled"))
    }

    func testAuthServiceErrorConfigurationErrorDescription() {
        let error = AuthServiceError.configurationError("test reason")
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("test reason"))
    }
}

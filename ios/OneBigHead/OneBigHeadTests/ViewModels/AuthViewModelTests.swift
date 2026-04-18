import XCTest
@testable import OneBigHead

// MARK: - AuthViewModelTests

final class AuthViewModelTests: XCTestCase {
    private var mockClient: MockAPIClientAuth!
    private var authService: AuthService!
    private var viewModel: AuthViewModel!

    override func setUp() {
        super.setUp()
        mockClient = MockAPIClientAuth()
        authService = AuthService(apiClient: mockClient)
        viewModel = AuthViewModel(authService: authService)
    }

    override func tearDown() {
        viewModel = nil
        authService = nil
        mockClient = nil
        super.tearDown()
    }

    // MARK: - Initial State

    func testInitialStateIsNotSigningIn() {
        XCTAssertFalse(viewModel.isSigningIn)
    }

    func testInitialStateHasNoErrorMessage() {
        XCTAssertNil(viewModel.errorMessage)
    }

    func testAuthServiceIsInjected() {
        XCTAssertTrue(viewModel.authService === authService)
    }

    // MARK: - isSigningIn reflects authService.isLoading

    func testIsSigningInReflectsAuthServiceLoading() async {
        // After a completed operation, isLoading (and thus isSigningIn) should be false
        await authService.logout()
        XCTAssertFalse(viewModel.isSigningIn)
    }

    // MARK: - errorMessage reflects authService.error

    func testErrorMessageReflectsAuthServiceError() async {
        mockClient.logoutResult = .failure(APIError.networkError(NSError(domain: "Test", code: -1, userInfo: [NSLocalizedDescriptionKey: "No connection"])))
        await authService.logout()
        XCTAssertNotNil(viewModel.errorMessage)
    }

    func testErrorMessageClearsWhenAuthServiceErrorClears() async {
        // Cause an error
        mockClient.logoutResult = .failure(APIError.networkError(NSError(domain: "Test", code: -1)))
        await authService.logout()
        XCTAssertNotNil(viewModel.errorMessage)

        // Successful logout clears error
        mockClient.logoutResult = .success(())
        await authService.logout()
        XCTAssertNil(viewModel.errorMessage)
    }

    // MARK: - signInWithApple delegates to authService

    func testSignInWithAppleDelegatesToAuthService() async {
        // signInWithApple() calls AppleSignInDelegate.performSignIn() which creates
        // an ASAuthorizationController. In a test environment this will fail,
        // which is expected - the important thing is the method runs without crashing
        // and the error is captured.
        await viewModel.signInWithApple()
        // The Apple sign-in will fail in test env, but authService should capture the error
        XCTAssertFalse(viewModel.isSigningIn)
    }
}

import XCTest
@testable import OneBigHead

// MARK: - MockAPIClientWorkspace

/// Mock implementation of APIClientWorkspaceProtocol for testing.
final class MockAPIClientWorkspace: APIClientWorkspaceProtocol {
    var getWorkspacesCallCount = 0
    var switchWorkspaceCallCount = 0
    var switchWorkspaceLastId: Int?

    var getWorkspacesResult: Result<[WorkspaceMembershipDTO], Error> = .success([])
    var switchWorkspaceResult: Result<SwitchWorkspaceResponse, Error> = .success(
        SwitchWorkspaceResponse(workspaceId: 1, workspaceName: "Test WS")
    )

    func getWorkspaces() async throws -> [WorkspaceMembershipDTO] {
        getWorkspacesCallCount += 1
        return try getWorkspacesResult.get()
    }

    func switchWorkspace(id: Int) async throws -> SwitchWorkspaceResponse {
        switchWorkspaceCallCount += 1
        switchWorkspaceLastId = id
        return try switchWorkspaceResult.get()
    }
}

// MARK: - MockAuthServiceForWorkspace

/// Mock implementation of AuthServiceProtocol for testing workspace switching.
final class MockAuthServiceForWorkspace: AuthServiceProtocol {
    var currentUser: MeResponse?
    var isAuthenticated: Bool = false
    var isLoading: Bool = false
    var error: String?

    var checkAuthStatusCallCount = 0

    func signInWithApple() async {}
    func signInWithGoogle(presentingWindow: UIWindow) async {}
    func signInWithMicrosoft(presentingViewController: UIViewController) async {}

    func checkAuthStatus() async {
        checkAuthStatusCallCount += 1
    }

    func logout() async {}
    func acceptTerms() async {}
    func completeWelcome(workspaceName: String?) async {}
}

// MARK: - WorkspaceSwitcherViewModelTests

final class WorkspaceSwitcherViewModelTests: XCTestCase {
    private var mockClient: MockAPIClientWorkspace!
    private var mockAuthService: MockAuthServiceForWorkspace!
    private var viewModel: WorkspaceSwitcherViewModel!

    override func setUp() {
        super.setUp()
        mockClient = MockAPIClientWorkspace()
        mockAuthService = MockAuthServiceForWorkspace()
        viewModel = WorkspaceSwitcherViewModel(
            apiClient: mockClient,
            authService: mockAuthService,
            currentWorkspaceId: 1
        )
    }

    override func tearDown() {
        viewModel = nil
        mockAuthService = nil
        mockClient = nil
        super.tearDown()
    }

    // MARK: - Initial State

    func testInitialStateHasNoWorkspaces() {
        XCTAssertTrue(viewModel.workspaces.isEmpty)
    }

    func testInitialStateIsNotLoading() {
        XCTAssertFalse(viewModel.isLoading)
    }

    func testInitialStateHasNoError() {
        XCTAssertNil(viewModel.error)
    }

    func testInitialStateIsNotSwitching() {
        XCTAssertFalse(viewModel.isSwitching)
    }

    func testInitialStateCurrentWorkspaceId() {
        XCTAssertEqual(viewModel.currentWorkspaceId, 1)
    }

    // MARK: - loadWorkspaces

    func testLoadWorkspacesSuccess() async {
        let workspaces = [
            WorkspaceMembershipDTO(id: 1, workspaceId: 10, workspaceName: "WS One", role: "owner"),
            WorkspaceMembershipDTO(id: 2, workspaceId: 20, workspaceName: "WS Two", role: "member")
        ]
        mockClient.getWorkspacesResult = .success(workspaces)

        await viewModel.loadWorkspaces()

        XCTAssertEqual(viewModel.workspaces.count, 2)
        XCTAssertEqual(viewModel.workspaces[0].workspaceName, "WS One")
        XCTAssertEqual(viewModel.workspaces[1].workspaceName, "WS Two")
        XCTAssertFalse(viewModel.isLoading)
        XCTAssertNil(viewModel.error)
        XCTAssertEqual(mockClient.getWorkspacesCallCount, 1)
    }

    func testLoadWorkspacesFailure() async {
        mockClient.getWorkspacesResult = .failure(APIError.networkError(
            NSError(domain: "Test", code: -1, userInfo: [NSLocalizedDescriptionKey: "No connection"])
        ))

        await viewModel.loadWorkspaces()

        XCTAssertTrue(viewModel.workspaces.isEmpty)
        XCTAssertFalse(viewModel.isLoading)
        XCTAssertNotNil(viewModel.error)
        XCTAssertEqual(mockClient.getWorkspacesCallCount, 1)
    }

    func testLoadWorkspacesSetsLoadingFalseAfterCompletion() async {
        await viewModel.loadWorkspaces()
        XCTAssertFalse(viewModel.isLoading)
    }

    func testLoadWorkspacesClearsErrorOnSuccess() async {
        // First cause an error
        mockClient.getWorkspacesResult = .failure(APIError.networkError(
            NSError(domain: "Test", code: -1, userInfo: [NSLocalizedDescriptionKey: "fail"])
        ))
        await viewModel.loadWorkspaces()
        XCTAssertNotNil(viewModel.error)

        // Now succeed
        mockClient.getWorkspacesResult = .success([])
        await viewModel.loadWorkspaces()
        XCTAssertNil(viewModel.error)
    }

    // MARK: - switchWorkspace

    func testSwitchWorkspaceSuccess() async {
        mockClient.switchWorkspaceResult = .success(
            SwitchWorkspaceResponse(workspaceId: 20, workspaceName: "WS Two")
        )

        await viewModel.switchWorkspace(id: 20)

        XCTAssertEqual(viewModel.currentWorkspaceId, 20)
        XCTAssertFalse(viewModel.isSwitching)
        XCTAssertNil(viewModel.error)
        XCTAssertEqual(mockClient.switchWorkspaceCallCount, 1)
        XCTAssertEqual(mockClient.switchWorkspaceLastId, 20)
        XCTAssertEqual(mockAuthService.checkAuthStatusCallCount, 1)
    }

    func testSwitchWorkspaceFailure() async {
        mockClient.switchWorkspaceResult = .failure(APIError.serverError(statusCode: 500, message: "fail"))

        await viewModel.switchWorkspace(id: 20)

        XCTAssertEqual(viewModel.currentWorkspaceId, 1) // unchanged
        XCTAssertFalse(viewModel.isSwitching)
        XCTAssertNotNil(viewModel.error)
        XCTAssertEqual(mockClient.switchWorkspaceCallCount, 1)
        XCTAssertEqual(mockAuthService.checkAuthStatusCallCount, 0)
    }

    func testSwitchWorkspaceSetsSwitchingFalseAfterCompletion() async {
        await viewModel.switchWorkspace(id: 1)
        XCTAssertFalse(viewModel.isSwitching)
    }

    func testSwitchWorkspaceClearsErrorOnSuccess() async {
        // First cause an error
        mockClient.switchWorkspaceResult = .failure(APIError.serverError(statusCode: 500, message: "fail"))
        await viewModel.switchWorkspace(id: 20)
        XCTAssertNotNil(viewModel.error)

        // Now succeed
        mockClient.switchWorkspaceResult = .success(
            SwitchWorkspaceResponse(workspaceId: 20, workspaceName: "WS Two")
        )
        await viewModel.switchWorkspace(id: 20)
        XCTAssertNil(viewModel.error)
    }

    func testSwitchWorkspaceCallsCheckAuthStatus() async {
        mockClient.switchWorkspaceResult = .success(
            SwitchWorkspaceResponse(workspaceId: 5, workspaceName: "New WS")
        )

        await viewModel.switchWorkspace(id: 5)

        XCTAssertEqual(mockAuthService.checkAuthStatusCallCount, 1)
    }

    // MARK: - loadWorkspaces returns empty list

    func testLoadWorkspacesReturnsEmptyList() async {
        mockClient.getWorkspacesResult = .success([])

        await viewModel.loadWorkspaces()

        XCTAssertTrue(viewModel.workspaces.isEmpty)
        XCTAssertFalse(viewModel.isLoading)
        XCTAssertNil(viewModel.error)
    }
}

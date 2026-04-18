import Foundation

// MARK: - APIError

/// Errors that can occur when making API requests.
enum APIError: LocalizedError {
    case invalidURL
    case invalidResponse
    case unauthorized
    case notFound
    case conflict
    case serverError(statusCode: Int, message: String?)
    case networkError(Error)
    case decodingError(Error)

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "The URL is invalid."
        case .invalidResponse:
            return "The server returned an invalid response."
        case .unauthorized:
            return "You are not authorized. Please sign in again."
        case .notFound:
            return "The requested resource was not found."
        case .conflict:
            return "A conflict occurred with the current state of the resource."
        case .serverError(let statusCode, let message):
            if let message {
                return "Server error (\(statusCode)): \(message)"
            }
            return "Server error (\(statusCode))."
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .decodingError(let error):
            return "Failed to decode response: \(error.localizedDescription)"
        }
    }
}

// MARK: - APIClient

/// A URLSession-based HTTP client with cookie-based authentication.
@Observable
final class APIClient {
    // MARK: - Properties

    /// The production base URL for all API requests.
    static let productionBaseURL = "https://onebighead.com"

    /// The base URL for all API requests. Fixed at initialization time.
    let baseURL: String

    /// Whether the user is currently authenticated, based on the presence of auth cookies.
    var isAuthenticated: Bool {
        guard let url = URL(string: baseURL),
              let host = url.host else {
            return false
        }
        let cookies = HTTPCookieStorage.shared.cookies(for: url) ?? []
        return cookies.contains { $0.domain.hasSuffix(host) }
    }

    // MARK: - Private

    private let session: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    // MARK: - Init

    init(session: URLSession = .shared, baseURL: String = APIClient.productionBaseURL) {
        self.session = session
        self.baseURL = baseURL
        self.decoder = JSONDecoder()
        self.encoder = JSONEncoder()
    }

    // MARK: - Core Request Methods

    /// Performs an HTTP request and decodes the JSON response.
    private func request<T: Decodable>(
        _ method: String,
        path: String,
        body: (any Encodable)? = nil
    ) async throws -> T {
        let urlRequest = try buildRequest(method, path: path, body: body)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: urlRequest)
        } catch {
            throw APIError.networkError(error)
        }

        try validateResponse(response)

        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw APIError.decodingError(error)
        }
    }

    /// Performs an HTTP request that returns no content (204).
    private func requestNoContent(
        _ method: String,
        path: String,
        body: (any Encodable)? = nil
    ) async throws {
        let urlRequest = try buildRequest(method, path: path, body: body)

        let response: URLResponse
        do {
            (_, response) = try await session.data(for: urlRequest)
        } catch {
            throw APIError.networkError(error)
        }

        try validateResponse(response)
    }

    /// Builds a URLRequest with the given method, path, and optional JSON body.
    private func buildRequest(
        _ method: String,
        path: String,
        body: (any Encodable)? = nil
    ) throws -> URLRequest {
        guard !baseURL.isEmpty,
              let url = URL(string: baseURL + path),
              url.scheme != nil,
              url.host != nil else {
            throw APIError.invalidURL
        }

        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = method
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if let body {
            urlRequest.httpBody = try encoder.encode(body)
        }

        return urlRequest
    }

    /// Validates the HTTP response and maps status codes to APIError.
    private func validateResponse(_ response: URLResponse) throws {
        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }

        switch httpResponse.statusCode {
        case 200...299:
            return
        case 401:
            throw APIError.unauthorized
        case 404:
            throw APIError.notFound
        case 409:
            throw APIError.conflict
        default:
            throw APIError.serverError(statusCode: httpResponse.statusCode, message: nil)
        }
    }

    // MARK: - Auth

    func authCallback(token: String, provider: String) async throws -> AuthCallbackResponse {
        struct Body: Encodable {
            let token: String
            let provider: String
        }
        return try await request("POST", path: "/api/auth/callback", body: Body(token: token, provider: provider))
    }

    func getMe() async throws -> MeResponse {
        return try await request("GET", path: "/api/auth/me")
    }

    func logout() async throws {
        try await requestNoContent("POST", path: "/api/auth/logout")
    }

    func acceptTerms() async throws -> AcceptTermsResponse {
        return try await request("POST", path: "/api/auth/accept-terms")
    }

    func completeWelcome(workspaceName: String?) async throws -> CompleteWelcomeResponse {
        struct Body: Encodable {
            let workspaceName: String?
        }
        return try await request("POST", path: "/api/auth/complete-welcome", body: Body(workspaceName: workspaceName))
    }

    // MARK: - Collections

    func getCollections() async throws -> [CollectionDTO] {
        return try await request("GET", path: "/api/collections")
    }

    func createCollection(_ request: CreateCollectionRequest) async throws -> CollectionDTO {
        return try await self.request("POST", path: "/api/collections", body: request)
    }

    func updateCollection(id: Int, _ request: CreateCollectionRequest) async throws -> CollectionDTO {
        return try await self.request("PUT", path: "/api/collections/\(id)", body: request)
    }

    func deleteCollection(id: Int) async throws {
        try await requestNoContent("DELETE", path: "/api/collections/\(id)")
    }

    // MARK: - Categories

    func getCategories(collectionId: Int) async throws -> [CategoryDTO] {
        return try await request("GET", path: "/api/categories?collectionId=\(collectionId)")
    }

    func createCategory(_ request: CreateCategoryRequest) async throws -> CategoryDTO {
        return try await self.request("POST", path: "/api/categories", body: request)
    }

    func updateCategory(id: Int, _ request: UpdateCategoryRequest) async throws -> CategoryDTO {
        return try await self.request("PUT", path: "/api/categories/\(id)", body: request)
    }

    func deleteCategory(id: Int) async throws {
        try await requestNoContent("DELETE", path: "/api/categories/\(id)")
    }

    // MARK: - Items

    func getItems(categoryId: Int) async throws -> [ItemDTO] {
        return try await request("GET", path: "/api/items?categoryId=\(categoryId)")
    }

    func getItem(id: Int) async throws -> ItemDTO {
        return try await request("GET", path: "/api/items/\(id)")
    }

    func createItem(_ request: CreateItemRequest) async throws -> ItemDTO {
        return try await self.request("POST", path: "/api/items", body: request)
    }

    func updateItem(id: Int, _ request: UpdateItemRequest) async throws -> ItemDTO {
        return try await self.request("PUT", path: "/api/items/\(id)", body: request)
    }

    func deleteItem(id: Int) async throws {
        try await requestNoContent("DELETE", path: "/api/items/\(id)")
    }

    // MARK: - Images

    func uploadImage(data: Data, filename: String) async throws -> ImageUploadResponse {
        guard !baseURL.isEmpty,
              let url = URL(string: baseURL + "/api/images"),
              url.scheme != nil,
              url.host != nil else {
            throw APIError.invalidURL
        }

        let boundary = UUID().uuidString
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"file\"; filename=\"\(filename)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: application/octet-stream\r\n\r\n".data(using: .utf8)!)
        body.append(data)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)
        urlRequest.httpBody = body

        let responseData: Data
        let response: URLResponse
        do {
            (responseData, response) = try await session.data(for: urlRequest)
        } catch {
            throw APIError.networkError(error)
        }

        try validateResponse(response)

        do {
            return try decoder.decode(ImageUploadResponse.self, from: responseData)
        } catch {
            throw APIError.decodingError(error)
        }
    }

    func deleteImage(key: UUID) async throws {
        try await requestNoContent("DELETE", path: "/api/images/\(key.uuidString)")
    }

    // MARK: - Workspaces

    func getWorkspaces() async throws -> [WorkspaceMembershipDTO] {
        return try await request("GET", path: "/api/workspaces")
    }

    func switchWorkspace(id: Int) async throws -> SwitchWorkspaceResponse {
        return try await request("POST", path: "/api/workspaces/\(id)/switch")
    }
}

import XCTest
@testable import OneBigHead

// MARK: - MockURLProtocol

final class MockURLProtocol: URLProtocol {
    /// Handler called for each request. Set this in your test to return canned responses.
    static var requestHandler: ((URLRequest) throws -> (HTTPURLResponse, Data?))?

    /// The last request that was intercepted, for inspection.
    static var lastRequest: URLRequest?

    override class func canInit(with request: URLRequest) -> Bool {
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }

    override func startLoading() {
        MockURLProtocol.lastRequest = request

        guard let handler = MockURLProtocol.requestHandler else {
            XCTFail("MockURLProtocol.requestHandler is not set.")
            return
        }

        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if let data {
                client?.urlProtocol(self, didLoad: data)
            }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

// MARK: - APIClientTests

final class APIClientTests: XCTestCase {

    private var client: APIClient!
    private var session: URLSession!

    override func setUp() {
        super.setUp()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        session = URLSession(configuration: config)
        client = APIClient(session: session, baseURL: "https://api.example.com")
        MockURLProtocol.lastRequest = nil
        MockURLProtocol.requestHandler = nil
    }

    override func tearDown() {
        client = nil
        session = nil
        MockURLProtocol.lastRequest = nil
        MockURLProtocol.requestHandler = nil
        super.tearDown()
    }

    // MARK: - APIError Descriptions

    func testAPIErrorInvalidURLDescription() {
        let error = APIError.invalidURL
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("URL"))
    }

    func testAPIErrorInvalidResponseDescription() {
        let error = APIError.invalidResponse
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("invalid response"))
    }

    func testAPIErrorUnauthorizedDescription() {
        let error = APIError.unauthorized
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("not authorized"))
    }

    func testAPIErrorNotFoundDescription() {
        let error = APIError.notFound
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("not found"))
    }

    func testAPIErrorConflictDescription() {
        let error = APIError.conflict
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("conflict"))
    }

    func testAPIErrorServerErrorDescription() {
        let error = APIError.serverError(statusCode: 500, message: "Internal error")
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("500"))
        XCTAssertTrue(error.errorDescription!.contains("Internal error"))
    }

    func testAPIErrorServerErrorDescriptionWithoutMessage() {
        let error = APIError.serverError(statusCode: 503, message: nil)
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("503"))
    }

    func testAPIErrorNetworkErrorDescription() {
        let underlyingError = NSError(domain: "Test", code: -1, userInfo: [NSLocalizedDescriptionKey: "No connection"])
        let error = APIError.networkError(underlyingError)
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("Network error"))
    }

    func testAPIErrorDecodingErrorDescription() {
        let underlyingError = NSError(domain: "Test", code: -1, userInfo: [NSLocalizedDescriptionKey: "Bad format"])
        let error = APIError.decodingError(underlyingError)
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("decode"))
    }

    // MARK: - URL Construction

    func testRequestURLConstruction() async throws {
        let responseJSON = """
        [{"id":1,"name":"Test","description":null,"heroImageUrl":null,"slug":"test","isPublic":false,"effectiveIsPublic":false}]
        """.data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.absoluteString, "https://api.example.com/api/collections")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: nil
            )!
            return (response, responseJSON)
        }

        let _: [CollectionDTO] = try await client.getCollections()
        XCTAssertNotNil(MockURLProtocol.lastRequest)
        XCTAssertEqual(MockURLProtocol.lastRequest?.url?.absoluteString, "https://api.example.com/api/collections")
    }

    func testRequestSendsContentTypeJSON() async throws {
        let responseJSON = """
        {"id":1,"name":"Test","description":null,"heroImageUrl":null,"slug":"test","isPublic":false,"effectiveIsPublic":false}
        """.data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: nil
            )!
            return (response, responseJSON)
        }

        let req = CreateCollectionRequest(name: "Test", description: nil, heroImageUrl: nil)
        let _ = try await client.createCollection(req)
        XCTAssertEqual(MockURLProtocol.lastRequest?.value(forHTTPHeaderField: "Content-Type"), "application/json")
    }

    // MARK: - Successful JSON Decoding

    func testGetCollectionsDecodesSuccessfully() async throws {
        let responseJSON = """
        [{"id":1,"name":"Collection A","description":"Desc","heroImageUrl":null,"slug":"collection-a","isPublic":true,"effectiveIsPublic":true}]
        """.data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, responseJSON)
        }

        let collections = try await client.getCollections()
        XCTAssertEqual(collections.count, 1)
        XCTAssertEqual(collections[0].name, "Collection A")
        XCTAssertEqual(collections[0].description, "Desc")
        XCTAssertEqual(collections[0].isPublic, true)
    }

    func testGetMeDecodesSuccessfully() async throws {
        let responseJSON = """
        {"userId":1,"email":"test@example.com","displayName":"User","workspaceId":1,"workspaceName":"WS","hasAcceptedTerms":true,"hasCompletedWelcome":false}
        """.data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, responseJSON)
        }

        let me = try await client.getMe()
        XCTAssertEqual(me.userId, 1)
        XCTAssertEqual(me.email, "test@example.com")
        XCTAssertEqual(me.displayName, "User")
        XCTAssertEqual(me.hasAcceptedTerms, true)
        XCTAssertEqual(me.hasCompletedWelcome, false)
    }

    func testGetItemDecodesSuccessfully() async throws {
        let uuid = UUID()
        let responseJSON = """
        {"id":5,"name":"Item","summary":"S","description":"D","collectionId":1,"categoryId":2,"templateKey":null,"properties":[{"key":"k","value":"v","templatePropertyId":null}],"images":[{"key":"\(uuid.uuidString)","url":"https://example.com/i.jpg","sortOrder":0,"isPrimary":true}],"userFlag":"Have","isPublic":false,"effectiveIsPublic":false}
        """.data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, responseJSON)
        }

        let item = try await client.getItem(id: 5)
        XCTAssertEqual(item.id, 5)
        XCTAssertEqual(item.name, "Item")
        XCTAssertEqual(item.properties.count, 1)
        XCTAssertEqual(item.properties[0].key, "k")
        XCTAssertEqual(item.images.count, 1)
        XCTAssertEqual(item.images[0].key, uuid)
        XCTAssertEqual(item.images[0].isPrimary, true)
    }

    // MARK: - Error Mapping

    func testUnauthorizedErrorMapping() async {
        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 401, httpVersion: nil, headerFields: nil)!
            return (response, nil)
        }

        do {
            let _ = try await client.getMe()
            XCTFail("Expected unauthorized error")
        } catch let error as APIError {
            if case .unauthorized = error {
                // Expected
            } else {
                XCTFail("Expected .unauthorized, got \(error)")
            }
        } catch {
            XCTFail("Expected APIError, got \(error)")
        }
    }

    func testNotFoundErrorMapping() async {
        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
            return (response, nil)
        }

        do {
            let _ = try await client.getItem(id: 999)
            XCTFail("Expected notFound error")
        } catch let error as APIError {
            if case .notFound = error {
                // Expected
            } else {
                XCTFail("Expected .notFound, got \(error)")
            }
        } catch {
            XCTFail("Expected APIError, got \(error)")
        }
    }

    func testConflictErrorMapping() async {
        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 409, httpVersion: nil, headerFields: nil)!
            return (response, nil)
        }

        do {
            let req = CreateCollectionRequest(name: "Dup", description: nil, heroImageUrl: nil)
            let _ = try await client.createCollection(req)
            XCTFail("Expected conflict error")
        } catch let error as APIError {
            if case .conflict = error {
                // Expected
            } else {
                XCTFail("Expected .conflict, got \(error)")
            }
        } catch {
            XCTFail("Expected APIError, got \(error)")
        }
    }

    func testServerErrorMapping() async {
        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 500, httpVersion: nil, headerFields: nil)!
            return (response, nil)
        }

        do {
            let _ = try await client.getCollections()
            XCTFail("Expected server error")
        } catch let error as APIError {
            if case .serverError(let statusCode, _) = error {
                XCTAssertEqual(statusCode, 500)
            } else {
                XCTFail("Expected .serverError, got \(error)")
            }
        } catch {
            XCTFail("Expected APIError, got \(error)")
        }
    }

    // MARK: - Upload Image Multipart

    func testUploadImageConstructsMultipartFormData() async throws {
        let imageData = Data([0xFF, 0xD8, 0xFF, 0xE0]) // Fake JPEG header
        let responseJSON = """
        {"key":"12345678-1234-1234-1234-123456789012","url":"https://example.com/img.jpg"}
        """.data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            // Verify Content-Type starts with multipart/form-data
            let contentType = request.value(forHTTPHeaderField: "Content-Type") ?? ""
            XCTAssertTrue(contentType.starts(with: "multipart/form-data"), "Expected multipart/form-data content type, got: \(contentType)")
            XCTAssertTrue(contentType.contains("boundary="), "Expected boundary in content type")

            // Verify HTTP method
            XCTAssertEqual(request.httpMethod, "POST")

            // Verify the body contains the filename (may come as httpBody or httpBodyStream)
            var bodyData: Data?
            if let httpBody = request.httpBody {
                bodyData = httpBody
            } else if let stream = request.httpBodyStream {
                bodyData = stream.readAllData()
            }
            if let bodyData, let bodyString = String(data: bodyData, encoding: .utf8) {
                XCTAssertTrue(bodyString.contains("filename=\"test.jpg\""), "Expected filename in body")
                XCTAssertTrue(bodyString.contains("Content-Disposition: form-data"), "Expected Content-Disposition in body")
                XCTAssertTrue(bodyString.contains("name=\"file\""), "Expected name=file in body")
            }

            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, responseJSON)
        }

        let result = try await client.uploadImage(data: imageData, filename: "test.jpg")
        XCTAssertEqual(result.url, "https://example.com/img.jpg")
    }

    // MARK: - Delete Operations (No Content)

    func testDeleteCollectionSucceeds() async throws {
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "DELETE")
            XCTAssertTrue(request.url!.absoluteString.hasSuffix("/api/collections/1"))
            let response = HTTPURLResponse(url: request.url!, statusCode: 204, httpVersion: nil, headerFields: nil)!
            return (response, nil)
        }

        try await client.deleteCollection(id: 1)
        // No assertion needed — success means no error thrown
    }

    func testDeleteItemSucceeds() async throws {
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "DELETE")
            let response = HTTPURLResponse(url: request.url!, statusCode: 204, httpVersion: nil, headerFields: nil)!
            return (response, nil)
        }

        try await client.deleteItem(id: 42)
    }

    func testDeleteCategorySucceeds() async throws {
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "DELETE")
            let response = HTTPURLResponse(url: request.url!, statusCode: 204, httpVersion: nil, headerFields: nil)!
            return (response, nil)
        }

        try await client.deleteCategory(id: 3)
    }

    func testDeleteImageSucceeds() async throws {
        let key = UUID()
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "DELETE")
            XCTAssertTrue(request.url!.absoluteString.contains("/api/images/"))
            let response = HTTPURLResponse(url: request.url!, statusCode: 204, httpVersion: nil, headerFields: nil)!
            return (response, nil)
        }

        try await client.deleteImage(key: key)
    }

    // MARK: - Base URL and Auth State

    func testIsAuthenticatedReturnsFalseWithEmptyBaseURL() {
        let emptyClient = APIClient(session: session, baseURL: "")
        XCTAssertFalse(emptyClient.isAuthenticated)
    }

    func testIsAuthenticatedReturnsFalseWithInvalidBaseURL() {
        let invalidClient = APIClient(session: session, baseURL: "not a url")
        XCTAssertFalse(invalidClient.isAuthenticated)
    }

    func testDefaultBaseURLIsProductionURL() {
        let newClient = APIClient(session: session)
        XCTAssertEqual(newClient.baseURL, APIClient.productionBaseURL)
    }

    func testProductionBaseURLPointsAtOneBigHead() {
        XCTAssertEqual(APIClient.productionBaseURL, "https://onebighead.com")
    }

    // MARK: - HTTP Methods

    func testLogoutSendsPostRequest() async throws {
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertTrue(request.url!.absoluteString.hasSuffix("/api/auth/logout"))
            let response = HTTPURLResponse(url: request.url!, statusCode: 204, httpVersion: nil, headerFields: nil)!
            return (response, nil)
        }

        try await client.logout()
    }

    func testGetCategoriesIncludesCollectionIdQuery() async throws {
        let responseJSON = """
        [{"id":1,"collectionId":5,"name":"Cat","description":null,"parentCategoryId":null,"sortOrder":0,"isSystem":false,"isPublic":true,"effectiveIsPublic":true}]
        """.data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            XCTAssertTrue(request.url!.absoluteString.contains("collectionId=5"))
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, responseJSON)
        }

        let categories = try await client.getCategories(collectionId: 5)
        XCTAssertEqual(categories.count, 1)
    }

    func testGetItemsIncludesCategoryIdQuery() async throws {
        let responseJSON = "[]".data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            XCTAssertTrue(request.url!.absoluteString.contains("categoryId=3"))
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, responseJSON)
        }

        let items = try await client.getItems(categoryId: 3)
        XCTAssertTrue(items.isEmpty)
    }

    func testUpdateCollectionSendsPutRequest() async throws {
        let responseJSON = """
        {"id":1,"name":"Updated","description":null,"heroImageUrl":null,"slug":"updated","isPublic":false,"effectiveIsPublic":false}
        """.data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "PUT")
            XCTAssertTrue(request.url!.absoluteString.hasSuffix("/api/collections/1"))
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, responseJSON)
        }

        let req = CreateCollectionRequest(name: "Updated", description: nil, heroImageUrl: nil)
        let result = try await client.updateCollection(id: 1, req)
        XCTAssertEqual(result.name, "Updated")
    }

    func testSwitchWorkspaceSendsPostRequest() async throws {
        let responseJSON = """
        {"workspaceId":5,"workspaceName":"New WS"}
        """.data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertTrue(request.url!.absoluteString.hasSuffix("/api/workspaces/5/switch"))
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, responseJSON)
        }

        let result = try await client.switchWorkspace(id: 5)
        XCTAssertEqual(result.workspaceId, 5)
        XCTAssertEqual(result.workspaceName, "New WS")
    }

    // MARK: - Decoding Error

    func testDecodingErrorOnInvalidJSON() async {
        let invalidJSON = "not json".data(using: .utf8)!

        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, invalidJSON)
        }

        do {
            let _ = try await client.getCollections()
            XCTFail("Expected decoding error")
        } catch let error as APIError {
            if case .decodingError = error {
                // Expected
            } else {
                XCTFail("Expected .decodingError, got \(error)")
            }
        } catch {
            XCTFail("Expected APIError, got \(error)")
        }
    }

    // MARK: - Invalid URL

    func testInvalidURLThrowsError() async {
        let emptyClient = APIClient(session: session, baseURL: "")

        do {
            let _ = try await emptyClient.getCollections()
            XCTFail("Expected invalidURL error")
        } catch let error as APIError {
            if case .invalidURL = error {
                // Expected
            } else {
                XCTFail("Expected .invalidURL, got \(error)")
            }
        } catch {
            XCTFail("Expected APIError, got \(error)")
        }
    }
}

// MARK: - InputStream Helper

private extension InputStream {
    func readAllData() -> Data {
        open()
        defer { close() }
        var data = Data()
        let bufferSize = 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        while hasBytesAvailable {
            let bytesRead = read(buffer, maxLength: bufferSize)
            if bytesRead > 0 {
                data.append(buffer, count: bytesRead)
            } else {
                break
            }
        }
        return data
    }
}

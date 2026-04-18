import XCTest
@testable import OneBigHead

final class DTOsTests: XCTestCase {

    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    // MARK: - CollectionDTO

    func testCollectionDTOCodableRoundTrip() throws {
        let dto = CollectionDTO(
            id: 1,
            name: "Test Collection",
            description: "A test collection",
            heroImageUrl: "https://example.com/hero.jpg",
            slug: "test-collection",
            isPublic: true,
            effectiveIsPublic: true
        )
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(CollectionDTO.self, from: data)
        XCTAssertEqual(decoded.id, dto.id)
        XCTAssertEqual(decoded.name, dto.name)
        XCTAssertEqual(decoded.description, dto.description)
        XCTAssertEqual(decoded.heroImageUrl, dto.heroImageUrl)
        XCTAssertEqual(decoded.slug, dto.slug)
        XCTAssertEqual(decoded.isPublic, dto.isPublic)
        XCTAssertEqual(decoded.effectiveIsPublic, dto.effectiveIsPublic)
    }

    func testCollectionDTOWithNilOptionals() throws {
        let json = """
        {"id":1,"name":"Test","description":null,"heroImageUrl":null,"slug":"test","isPublic":false,"effectiveIsPublic":false}
        """.data(using: .utf8)!
        let decoded = try decoder.decode(CollectionDTO.self, from: json)
        XCTAssertEqual(decoded.id, 1)
        XCTAssertEqual(decoded.name, "Test")
        XCTAssertNil(decoded.description)
        XCTAssertNil(decoded.heroImageUrl)
    }

    func testCollectionDTOWithMissingOptionals() throws {
        let json = """
        {"id":1,"name":"Test","slug":"test","isPublic":false,"effectiveIsPublic":false}
        """.data(using: .utf8)!
        let decoded = try decoder.decode(CollectionDTO.self, from: json)
        XCTAssertNil(decoded.description)
        XCTAssertNil(decoded.heroImageUrl)
    }

    func testCollectionDTOIdentifiable() throws {
        let dto = CollectionDTO(
            id: 42,
            name: "Test",
            description: nil,
            heroImageUrl: nil,
            slug: "test",
            isPublic: false,
            effectiveIsPublic: false
        )
        XCTAssertEqual(dto.id, 42)
    }

    // MARK: - ItemDTO

    func testItemDTOCodableRoundTrip() throws {
        let templateKey = UUID()
        let imageKey = UUID()
        let propId = UUID()
        let dto = ItemDTO(
            id: 10,
            name: "Test Item",
            summary: "A summary",
            description: "A description",
            collectionId: 1,
            categoryId: 2,
            templateKey: templateKey,
            properties: [ItemPropertyDTO(key: "color", value: "red", templatePropertyId: propId)],
            images: [ItemImageDTO(key: imageKey, url: "https://example.com/img.jpg", sortOrder: 0, isPrimary: true)],
            userFlag: "Have",
            isPublic: true,
            effectiveIsPublic: true
        )
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(ItemDTO.self, from: data)
        XCTAssertEqual(decoded.id, 10)
        XCTAssertEqual(decoded.name, "Test Item")
        XCTAssertEqual(decoded.summary, "A summary")
        XCTAssertEqual(decoded.description, "A description")
        XCTAssertEqual(decoded.collectionId, 1)
        XCTAssertEqual(decoded.categoryId, 2)
        XCTAssertEqual(decoded.templateKey, templateKey)
        XCTAssertEqual(decoded.properties.count, 1)
        XCTAssertEqual(decoded.properties[0].key, "color")
        XCTAssertEqual(decoded.properties[0].value, "red")
        XCTAssertEqual(decoded.properties[0].templatePropertyId, propId)
        XCTAssertEqual(decoded.images.count, 1)
        XCTAssertEqual(decoded.images[0].key, imageKey)
        XCTAssertEqual(decoded.images[0].isPrimary, true)
        XCTAssertEqual(decoded.userFlag, "Have")
        XCTAssertEqual(decoded.isPublic, true)
    }

    func testItemDTOWithNilOptionals() throws {
        let json = """
        {"id":1,"name":"Item","summary":null,"description":null,"collectionId":1,"categoryId":null,"templateKey":null,"properties":[],"images":[],"userFlag":null,"isPublic":false,"effectiveIsPublic":false}
        """.data(using: .utf8)!
        let decoded = try decoder.decode(ItemDTO.self, from: json)
        XCTAssertNil(decoded.summary)
        XCTAssertNil(decoded.description)
        XCTAssertNil(decoded.categoryId)
        XCTAssertNil(decoded.templateKey)
        XCTAssertNil(decoded.userFlag)
        XCTAssertTrue(decoded.properties.isEmpty)
        XCTAssertTrue(decoded.images.isEmpty)
    }

    func testItemPropertyDTOWithNilTemplatePropertyId() throws {
        let json = """
        {"key":"size","value":"large","templatePropertyId":null}
        """.data(using: .utf8)!
        let decoded = try decoder.decode(ItemPropertyDTO.self, from: json)
        XCTAssertEqual(decoded.key, "size")
        XCTAssertEqual(decoded.value, "large")
        XCTAssertNil(decoded.templatePropertyId)
    }

    func testItemImageDTOCodableRoundTrip() throws {
        let key = UUID()
        let dto = ItemImageDTO(key: key, url: "https://example.com/img.png", sortOrder: 1, isPrimary: false)
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(ItemImageDTO.self, from: data)
        XCTAssertEqual(decoded.key, key)
        XCTAssertEqual(decoded.url, "https://example.com/img.png")
        XCTAssertEqual(decoded.sortOrder, 1)
        XCTAssertEqual(decoded.isPrimary, false)
    }

    // MARK: - MeResponse

    func testMeResponseCodableRoundTrip() throws {
        let dto = MeResponse(
            userId: 1,
            email: "test@example.com",
            displayName: "Test User",
            workspaceId: 1,
            workspaceName: "My Workspace",
            hasAcceptedTerms: true,
            hasCompletedWelcome: false
        )
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(MeResponse.self, from: data)
        XCTAssertEqual(decoded.userId, 1)
        XCTAssertEqual(decoded.email, "test@example.com")
        XCTAssertEqual(decoded.displayName, "Test User")
        XCTAssertEqual(decoded.workspaceId, 1)
        XCTAssertEqual(decoded.workspaceName, "My Workspace")
        XCTAssertEqual(decoded.hasAcceptedTerms, true)
        XCTAssertEqual(decoded.hasCompletedWelcome, false)
    }

    func testMeResponseWithNilDisplayName() throws {
        let json = """
        {"userId":1,"email":"test@example.com","displayName":null,"workspaceId":1,"workspaceName":"WS","hasAcceptedTerms":false,"hasCompletedWelcome":false}
        """.data(using: .utf8)!
        let decoded = try decoder.decode(MeResponse.self, from: json)
        XCTAssertNil(decoded.displayName)
    }

    // MARK: - AuthCallbackResponse

    func testAuthCallbackResponseCodableRoundTrip() throws {
        let dto = AuthCallbackResponse(success: true, email: "a@b.com", workspaceId: 1, workspaceName: "WS")
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(AuthCallbackResponse.self, from: data)
        XCTAssertEqual(decoded.success, true)
        XCTAssertEqual(decoded.email, "a@b.com")
        XCTAssertEqual(decoded.workspaceId, 1)
        XCTAssertEqual(decoded.workspaceName, "WS")
    }

    // MARK: - AcceptTermsResponse

    func testAcceptTermsResponseCodableRoundTrip() throws {
        let dto = AcceptTermsResponse(hasAcceptedTerms: true, acceptedTermsAt: "2024-01-01T00:00:00Z")
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(AcceptTermsResponse.self, from: data)
        XCTAssertEqual(decoded.hasAcceptedTerms, true)
        XCTAssertEqual(decoded.acceptedTermsAt, "2024-01-01T00:00:00Z")
    }

    func testAcceptTermsResponseWithNilDate() throws {
        let json = """
        {"hasAcceptedTerms":false,"acceptedTermsAt":null}
        """.data(using: .utf8)!
        let decoded = try decoder.decode(AcceptTermsResponse.self, from: json)
        XCTAssertEqual(decoded.hasAcceptedTerms, false)
        XCTAssertNil(decoded.acceptedTermsAt)
    }

    // MARK: - CompleteWelcomeResponse

    func testCompleteWelcomeResponseCodableRoundTrip() throws {
        let dto = CompleteWelcomeResponse(workspaceId: 1, workspaceName: "WS", hasCompletedWelcome: true)
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(CompleteWelcomeResponse.self, from: data)
        XCTAssertEqual(decoded.workspaceId, 1)
        XCTAssertEqual(decoded.workspaceName, "WS")
        XCTAssertEqual(decoded.hasCompletedWelcome, true)
    }

    // MARK: - CategoryDTO

    func testCategoryDTOCodableRoundTrip() throws {
        let dto = CategoryDTO(
            id: 5,
            collectionId: 1,
            name: "Test Category",
            description: "Desc",
            parentCategoryId: nil,
            sortOrder: 0,
            isSystem: false,
            isPublic: true,
            effectiveIsPublic: true
        )
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(CategoryDTO.self, from: data)
        XCTAssertEqual(decoded.id, 5)
        XCTAssertEqual(decoded.collectionId, 1)
        XCTAssertEqual(decoded.name, "Test Category")
        XCTAssertEqual(decoded.description, "Desc")
        XCTAssertNil(decoded.parentCategoryId)
        XCTAssertEqual(decoded.sortOrder, 0)
        XCTAssertEqual(decoded.isSystem, false)
    }

    func testCategoryDTOWithParentCategoryId() throws {
        let json = """
        {"id":5,"collectionId":1,"name":"Sub","description":null,"parentCategoryId":3,"sortOrder":1,"isSystem":false,"isPublic":true,"effectiveIsPublic":true}
        """.data(using: .utf8)!
        let decoded = try decoder.decode(CategoryDTO.self, from: json)
        XCTAssertEqual(decoded.parentCategoryId, 3)
    }

    // MARK: - CreateCollectionRequest

    func testCreateCollectionRequestCodableRoundTrip() throws {
        let req = CreateCollectionRequest(name: "New", description: "Desc", heroImageUrl: nil)
        let data = try encoder.encode(req)
        let decoded = try decoder.decode(CreateCollectionRequest.self, from: data)
        XCTAssertEqual(decoded.name, "New")
        XCTAssertEqual(decoded.description, "Desc")
        XCTAssertNil(decoded.heroImageUrl)
    }

    // MARK: - CreateCategoryRequest

    func testCreateCategoryRequestCodableRoundTrip() throws {
        let req = CreateCategoryRequest(collectionId: 1, name: "Cat", description: nil, parentCategoryId: nil, itemTemplateIds: [1, 2])
        let data = try encoder.encode(req)
        let decoded = try decoder.decode(CreateCategoryRequest.self, from: data)
        XCTAssertEqual(decoded.collectionId, 1)
        XCTAssertEqual(decoded.name, "Cat")
        XCTAssertNil(decoded.description)
        XCTAssertNil(decoded.parentCategoryId)
        XCTAssertEqual(decoded.itemTemplateIds, [1, 2])
    }

    // MARK: - UpdateCategoryRequest

    func testUpdateCategoryRequestCodableRoundTrip() throws {
        let req = UpdateCategoryRequest(name: "Updated", description: "Desc", parentCategoryId: 3, itemTemplateIds: nil)
        let data = try encoder.encode(req)
        let decoded = try decoder.decode(UpdateCategoryRequest.self, from: data)
        XCTAssertEqual(decoded.name, "Updated")
        XCTAssertEqual(decoded.description, "Desc")
        XCTAssertEqual(decoded.parentCategoryId, 3)
        XCTAssertNil(decoded.itemTemplateIds)
    }

    // MARK: - CreateItemRequest

    func testCreateItemRequestCodableRoundTrip() throws {
        let req = CreateItemRequest(
            name: "Item",
            summary: "Sum",
            description: "Desc",
            collectionId: 1,
            categoryId: 2,
            templateKey: nil,
            properties: [],
            images: [],
            userFlag: "Have"
        )
        let data = try encoder.encode(req)
        let decoded = try decoder.decode(CreateItemRequest.self, from: data)
        XCTAssertEqual(decoded.name, "Item")
        XCTAssertEqual(decoded.summary, "Sum")
        XCTAssertEqual(decoded.collectionId, 1)
        XCTAssertEqual(decoded.categoryId, 2)
        XCTAssertNil(decoded.templateKey)
    }

    // MARK: - UpdateItemRequest

    func testUpdateItemRequestCodableRoundTrip() throws {
        let req = UpdateItemRequest(
            name: "Updated",
            summary: "Sum",
            description: "Desc",
            categoryId: nil,
            templateKey: nil,
            properties: [],
            images: [],
            userFlag: "Want"
        )
        let data = try encoder.encode(req)
        let decoded = try decoder.decode(UpdateItemRequest.self, from: data)
        XCTAssertEqual(decoded.name, "Updated")
        XCTAssertNil(decoded.categoryId)
        XCTAssertEqual(decoded.userFlag, "Want")
    }

    // MARK: - ImageUploadResponse

    func testImageUploadResponseCodableRoundTrip() throws {
        let key = UUID()
        let dto = ImageUploadResponse(key: key, url: "https://example.com/img.png")
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(ImageUploadResponse.self, from: data)
        XCTAssertEqual(decoded.key, key)
        XCTAssertEqual(decoded.url, "https://example.com/img.png")
    }

    // MARK: - WorkspaceMembershipDTO

    func testWorkspaceMembershipDTOCodableRoundTrip() throws {
        let dto = WorkspaceMembershipDTO(id: 1, workspaceId: 10, workspaceName: "WS", role: "Owner")
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(WorkspaceMembershipDTO.self, from: data)
        XCTAssertEqual(decoded.id, 1)
        XCTAssertEqual(decoded.workspaceId, 10)
        XCTAssertEqual(decoded.workspaceName, "WS")
        XCTAssertEqual(decoded.role, "Owner")
    }

    func testWorkspaceMembershipDTOIdentifiable() {
        let dto = WorkspaceMembershipDTO(id: 7, workspaceId: 10, workspaceName: "WS", role: "Member")
        XCTAssertEqual(dto.id, 7)
    }

    // MARK: - SwitchWorkspaceResponse

    func testSwitchWorkspaceResponseCodableRoundTrip() throws {
        let dto = SwitchWorkspaceResponse(workspaceId: 5, workspaceName: "New WS")
        let data = try encoder.encode(dto)
        let decoded = try decoder.decode(SwitchWorkspaceResponse.self, from: data)
        XCTAssertEqual(decoded.workspaceId, 5)
        XCTAssertEqual(decoded.workspaceName, "New WS")
    }
}

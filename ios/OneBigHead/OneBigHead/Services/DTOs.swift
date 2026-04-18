import Foundation

// MARK: - Auth

struct AuthCallbackResponse: Codable {
    let success: Bool
    let email: String
    let workspaceId: Int
    let workspaceName: String
}

struct MeResponse: Codable {
    let userId: Int
    let email: String
    let displayName: String?
    let workspaceId: Int
    let workspaceName: String
    let hasAcceptedTerms: Bool
    let hasCompletedWelcome: Bool
}

struct AcceptTermsResponse: Codable {
    let hasAcceptedTerms: Bool
    let acceptedTermsAt: String?
}

struct CompleteWelcomeResponse: Codable {
    let workspaceId: Int
    let workspaceName: String
    let hasCompletedWelcome: Bool
}

// MARK: - Collections

struct CollectionDTO: Codable, Identifiable {
    let id: Int
    let name: String
    let description: String?
    let heroImageUrl: String?
    let slug: String
    let isPublic: Bool
    let effectiveIsPublic: Bool
}

struct CreateCollectionRequest: Codable {
    let name: String
    let description: String?
    let heroImageUrl: String?
}

// MARK: - Categories

struct CategoryDTO: Codable, Identifiable {
    let id: Int
    let collectionId: Int
    let name: String
    let description: String?
    let parentCategoryId: Int?
    let sortOrder: Int
    let isSystem: Bool
    let isPublic: Bool
    let effectiveIsPublic: Bool
}

struct CreateCategoryRequest: Codable {
    let collectionId: Int
    let name: String
    let description: String?
    let parentCategoryId: Int?
    let itemTemplateIds: [Int]?
}

struct UpdateCategoryRequest: Codable {
    let name: String
    let description: String?
    let parentCategoryId: Int?
    let itemTemplateIds: [Int]?
}

// MARK: - Items

struct ItemDTO: Codable, Identifiable {
    let id: Int
    let name: String
    let summary: String?
    let description: String?
    let collectionId: Int
    let categoryId: Int?
    let templateKey: UUID?
    let properties: [ItemPropertyDTO]
    let images: [ItemImageDTO]
    let userFlag: String?
    let isPublic: Bool
    let effectiveIsPublic: Bool
}

struct ItemPropertyDTO: Codable {
    let key: String
    let value: String
    let templatePropertyId: UUID?
}

struct ItemImageDTO: Codable {
    let key: UUID
    let url: String
    let sortOrder: Int
    let isPrimary: Bool
}

struct CreateItemRequest: Codable {
    let name: String
    let summary: String
    let description: String
    let collectionId: Int
    let categoryId: Int?
    let templateKey: UUID?
    let properties: [ItemPropertyDTO]
    let images: [ItemImageDTO]
    let userFlag: String
}

struct UpdateItemRequest: Codable {
    let name: String
    let summary: String
    let description: String
    let categoryId: Int?
    let templateKey: UUID?
    let properties: [ItemPropertyDTO]
    let images: [ItemImageDTO]
    let userFlag: String
}

// MARK: - Images

struct ImageUploadResponse: Codable {
    let key: UUID
    let url: String
}

// MARK: - Workspaces

struct WorkspaceMembershipDTO: Codable, Identifiable {
    let id: Int
    let workspaceId: Int
    let workspaceName: String
    let role: String
}

struct SwitchWorkspaceResponse: Codable {
    let workspaceId: Int
    let workspaceName: String
}

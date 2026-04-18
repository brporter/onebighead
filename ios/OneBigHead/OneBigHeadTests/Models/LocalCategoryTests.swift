import XCTest
@testable import OneBigHead

final class LocalCategoryTests: XCTestCase {

    func testInitWithDefaults() {
        let collectionId = UUID()
        let category = LocalCategory(
            workspaceId: 1,
            collectionLocalId: collectionId,
            name: "Test Category"
        )

        XCTAssertNotNil(category.localId)
        XCTAssertNil(category.serverId)
        XCTAssertEqual(category.workspaceId, 1)
        XCTAssertEqual(category.collectionLocalId, collectionId)
        XCTAssertEqual(category.name, "Test Category")
        XCTAssertEqual(category.descriptionText, "")
        XCTAssertNil(category.parentLocalId)
        XCTAssertEqual(category.sortOrder, 0)
        XCTAssertFalse(category.isSystem)
        XCTAssertEqual(category.visibility, .privateVisibility)
        XCTAssertEqual(category.syncStatus, .synced)
    }

    func testInitWithAllParameters() {
        let fixedId = UUID()
        let collectionId = UUID()
        let parentId = UUID()

        let category = LocalCategory(
            localId: fixedId,
            serverId: 10,
            workspaceId: 3,
            collectionLocalId: collectionId,
            name: "Full Category",
            descriptionText: "Category description",
            parentLocalId: parentId,
            sortOrder: 5,
            isSystem: true,
            visibility: .publicVisibility,
            syncStatus: .pendingDelete
        )

        XCTAssertEqual(category.localId, fixedId)
        XCTAssertEqual(category.serverId, 10)
        XCTAssertEqual(category.workspaceId, 3)
        XCTAssertEqual(category.collectionLocalId, collectionId)
        XCTAssertEqual(category.name, "Full Category")
        XCTAssertEqual(category.descriptionText, "Category description")
        XCTAssertEqual(category.parentLocalId, parentId)
        XCTAssertEqual(category.sortOrder, 5)
        XCTAssertTrue(category.isSystem)
        XCTAssertEqual(category.visibility, .publicVisibility)
        XCTAssertEqual(category.syncStatus, .pendingDelete)
    }

    func testDefaultVisibilityIsPrivate() {
        let category = LocalCategory(
            workspaceId: 1,
            collectionLocalId: UUID(),
            name: "Private"
        )
        XCTAssertEqual(category.visibility, .privateVisibility)
    }

    func testDefaultSyncStatusIsSynced() {
        let category = LocalCategory(
            workspaceId: 1,
            collectionLocalId: UUID(),
            name: "Synced"
        )
        XCTAssertEqual(category.syncStatus, .synced)
    }

    func testDefaultIsSystemIsFalse() {
        let category = LocalCategory(
            workspaceId: 1,
            collectionLocalId: UUID(),
            name: "Non-system"
        )
        XCTAssertFalse(category.isSystem)
    }

    func testUniqueLocalIdPerInstance() {
        let collectionId = UUID()
        let cat1 = LocalCategory(workspaceId: 1, collectionLocalId: collectionId, name: "A")
        let cat2 = LocalCategory(workspaceId: 1, collectionLocalId: collectionId, name: "B")
        XCTAssertNotEqual(cat1.localId, cat2.localId)
    }

    func testMutableProperties() {
        let category = LocalCategory(
            workspaceId: 1,
            collectionLocalId: UUID(),
            name: "Original"
        )

        category.name = "Updated"
        category.sortOrder = 10
        category.syncStatus = .pendingUpdate

        XCTAssertEqual(category.name, "Updated")
        XCTAssertEqual(category.sortOrder, 10)
        XCTAssertEqual(category.syncStatus, .pendingUpdate)
    }
}

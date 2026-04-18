import XCTest
@testable import OneBigHead

final class LocalCollectionTests: XCTestCase {

    func testInitWithDefaults() {
        let collection = LocalCollection(
            workspaceId: 1,
            name: "Test Collection",
            slug: "test-collection"
        )

        XCTAssertNotNil(collection.localId)
        XCTAssertNil(collection.serverId)
        XCTAssertEqual(collection.workspaceId, 1)
        XCTAssertEqual(collection.name, "Test Collection")
        XCTAssertEqual(collection.descriptionText, "")
        XCTAssertNil(collection.heroImageUrl)
        XCTAssertEqual(collection.slug, "test-collection")
        XCTAssertEqual(collection.visibility, .privateVisibility)
        XCTAssertEqual(collection.syncStatus, .synced)
        XCTAssertNotNil(collection.lastModifiedLocally)
    }

    func testInitWithAllParameters() {
        let fixedId = UUID()
        let fixedDate = Date(timeIntervalSince1970: 1000)

        let collection = LocalCollection(
            localId: fixedId,
            serverId: 42,
            workspaceId: 5,
            name: "Full Collection",
            descriptionText: "A detailed description",
            heroImageUrl: "https://example.com/hero.jpg",
            slug: "full-collection",
            visibility: .publicVisibility,
            syncStatus: .pendingCreate,
            lastModifiedLocally: fixedDate
        )

        XCTAssertEqual(collection.localId, fixedId)
        XCTAssertEqual(collection.serverId, 42)
        XCTAssertEqual(collection.workspaceId, 5)
        XCTAssertEqual(collection.name, "Full Collection")
        XCTAssertEqual(collection.descriptionText, "A detailed description")
        XCTAssertEqual(collection.heroImageUrl, "https://example.com/hero.jpg")
        XCTAssertEqual(collection.slug, "full-collection")
        XCTAssertEqual(collection.visibility, .publicVisibility)
        XCTAssertEqual(collection.syncStatus, .pendingCreate)
        XCTAssertEqual(collection.lastModifiedLocally, fixedDate)
    }

    func testDefaultVisibilityIsPrivate() {
        let collection = LocalCollection(
            workspaceId: 1,
            name: "Private Collection",
            slug: "private"
        )
        XCTAssertEqual(collection.visibility, .privateVisibility)
    }

    func testDefaultSyncStatusIsSynced() {
        let collection = LocalCollection(
            workspaceId: 1,
            name: "Synced Collection",
            slug: "synced"
        )
        XCTAssertEqual(collection.syncStatus, .synced)
    }

    func testUniqueLocalIdPerInstance() {
        let collection1 = LocalCollection(workspaceId: 1, name: "A", slug: "a")
        let collection2 = LocalCollection(workspaceId: 1, name: "B", slug: "b")
        XCTAssertNotEqual(collection1.localId, collection2.localId)
    }

    func testMutableProperties() {
        let collection = LocalCollection(
            workspaceId: 1,
            name: "Original",
            slug: "original"
        )

        collection.name = "Updated"
        collection.serverId = 99
        collection.syncStatus = .pendingUpdate
        collection.visibility = .publicVisibility

        XCTAssertEqual(collection.name, "Updated")
        XCTAssertEqual(collection.serverId, 99)
        XCTAssertEqual(collection.syncStatus, .pendingUpdate)
        XCTAssertEqual(collection.visibility, .publicVisibility)
    }
}

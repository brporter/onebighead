import XCTest
@testable import OneBigHead

final class LocalItemTests: XCTestCase {

    func testInitWithDefaults() {
        let collectionId = UUID()
        let item = LocalItem(
            workspaceId: 1,
            collectionLocalId: collectionId,
            name: "Test Item"
        )

        XCTAssertNotNil(item.localId)
        XCTAssertNil(item.serverId)
        XCTAssertEqual(item.workspaceId, 1)
        XCTAssertEqual(item.collectionLocalId, collectionId)
        XCTAssertNil(item.categoryLocalId)
        XCTAssertNil(item.templateKey)
        XCTAssertEqual(item.name, "Test Item")
        XCTAssertEqual(item.summary, "")
        XCTAssertEqual(item.descriptionText, "")
        XCTAssertTrue(item.properties.isEmpty)
        XCTAssertTrue(item.images.isEmpty)
        XCTAssertEqual(item.visibility, .privateVisibility)
        XCTAssertEqual(item.userFlag, .have)
        XCTAssertEqual(item.syncStatus, .synced)
    }

    func testInitWithAllParameters() {
        let fixedId = UUID()
        let collectionId = UUID()
        let categoryId = UUID()
        let templateId = UUID()
        let propTemplateId = UUID()
        let imageKey = UUID()

        let properties = [
            ItemProperty(key: "color", value: "red", templatePropertyId: propTemplateId)
        ]
        let images = [
            ItemImage(key: imageKey, url: "https://example.com/img.jpg", sortOrder: 0, isPrimary: true)
        ]

        let item = LocalItem(
            localId: fixedId,
            serverId: 77,
            workspaceId: 2,
            collectionLocalId: collectionId,
            categoryLocalId: categoryId,
            templateKey: templateId,
            name: "Full Item",
            summary: "A summary",
            descriptionText: "A description",
            properties: properties,
            images: images,
            visibility: .publicVisibility,
            userFlag: .want,
            syncStatus: .pendingCreate
        )

        XCTAssertEqual(item.localId, fixedId)
        XCTAssertEqual(item.serverId, 77)
        XCTAssertEqual(item.workspaceId, 2)
        XCTAssertEqual(item.collectionLocalId, collectionId)
        XCTAssertEqual(item.categoryLocalId, categoryId)
        XCTAssertEqual(item.templateKey, templateId)
        XCTAssertEqual(item.name, "Full Item")
        XCTAssertEqual(item.summary, "A summary")
        XCTAssertEqual(item.descriptionText, "A description")
        XCTAssertEqual(item.properties.count, 1)
        XCTAssertEqual(item.images.count, 1)
        XCTAssertEqual(item.visibility, .publicVisibility)
        XCTAssertEqual(item.userFlag, .want)
        XCTAssertEqual(item.syncStatus, .pendingCreate)
    }

    func testDefaultUserFlagIsHave() {
        let item = LocalItem(
            workspaceId: 1,
            collectionLocalId: UUID(),
            name: "Default Flag"
        )
        XCTAssertEqual(item.userFlag, .have)
    }

    // MARK: - ItemProperty Codable

    func testItemPropertyCodableRoundTrip() throws {
        let templateId = UUID()
        let property = ItemProperty(key: "year", value: "2024", templatePropertyId: templateId)

        let data = try JSONEncoder().encode(property)
        let decoded = try JSONDecoder().decode(ItemProperty.self, from: data)

        XCTAssertEqual(decoded.key, "year")
        XCTAssertEqual(decoded.value, "2024")
        XCTAssertEqual(decoded.templatePropertyId, templateId)
    }

    func testItemPropertyCodableWithNilTemplatePropertyId() throws {
        let property = ItemProperty(key: "color", value: "blue", templatePropertyId: nil)

        let data = try JSONEncoder().encode(property)
        let decoded = try JSONDecoder().decode(ItemProperty.self, from: data)

        XCTAssertEqual(decoded.key, "color")
        XCTAssertEqual(decoded.value, "blue")
        XCTAssertNil(decoded.templatePropertyId)
    }

    func testItemPropertyEquality() {
        let id = UUID()
        let a = ItemProperty(key: "k", value: "v", templatePropertyId: id)
        let b = ItemProperty(key: "k", value: "v", templatePropertyId: id)
        XCTAssertEqual(a, b)
    }

    func testItemPropertyInequality() {
        let a = ItemProperty(key: "k1", value: "v", templatePropertyId: nil)
        let b = ItemProperty(key: "k2", value: "v", templatePropertyId: nil)
        XCTAssertNotEqual(a, b)
    }

    func testItemPropertyArrayCodableRoundTrip() throws {
        let properties = [
            ItemProperty(key: "a", value: "1", templatePropertyId: nil),
            ItemProperty(key: "b", value: "2", templatePropertyId: UUID())
        ]

        let data = try JSONEncoder().encode(properties)
        let decoded = try JSONDecoder().decode([ItemProperty].self, from: data)

        XCTAssertEqual(decoded.count, 2)
        XCTAssertEqual(decoded[0].key, "a")
        XCTAssertEqual(decoded[1].key, "b")
    }

    // MARK: - ItemImage Codable

    func testItemImageCodableRoundTrip() throws {
        let key = UUID()
        let image = ItemImage(key: key, url: "https://example.com/photo.png", sortOrder: 3, isPrimary: true)

        let data = try JSONEncoder().encode(image)
        let decoded = try JSONDecoder().decode(ItemImage.self, from: data)

        XCTAssertEqual(decoded.key, key)
        XCTAssertEqual(decoded.url, "https://example.com/photo.png")
        XCTAssertEqual(decoded.sortOrder, 3)
        XCTAssertTrue(decoded.isPrimary)
    }

    func testItemImageEquality() {
        let key = UUID()
        let a = ItemImage(key: key, url: "url", sortOrder: 0, isPrimary: false)
        let b = ItemImage(key: key, url: "url", sortOrder: 0, isPrimary: false)
        XCTAssertEqual(a, b)
    }

    func testItemImageInequality() {
        let a = ItemImage(key: UUID(), url: "url1", sortOrder: 0, isPrimary: false)
        let b = ItemImage(key: UUID(), url: "url2", sortOrder: 1, isPrimary: true)
        XCTAssertNotEqual(a, b)
    }

    func testItemImageArrayCodableRoundTrip() throws {
        let images = [
            ItemImage(key: UUID(), url: "url1", sortOrder: 0, isPrimary: true),
            ItemImage(key: UUID(), url: "url2", sortOrder: 1, isPrimary: false)
        ]

        let data = try JSONEncoder().encode(images)
        let decoded = try JSONDecoder().decode([ItemImage].self, from: data)

        XCTAssertEqual(decoded.count, 2)
        XCTAssertTrue(decoded[0].isPrimary)
        XCTAssertFalse(decoded[1].isPrimary)
    }

    // MARK: - Mutability

    func testMutableProperties() {
        let item = LocalItem(
            workspaceId: 1,
            collectionLocalId: UUID(),
            name: "Original"
        )

        item.name = "Updated"
        item.userFlag = .tradeOrSell
        item.syncStatus = .pendingUpdate

        XCTAssertEqual(item.name, "Updated")
        XCTAssertEqual(item.userFlag, .tradeOrSell)
        XCTAssertEqual(item.syncStatus, .pendingUpdate)
    }
}

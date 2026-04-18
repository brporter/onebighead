import XCTest
@testable import OneBigHead

final class LocalPendingImageTests: XCTestCase {

    func testInitWithDefaults() {
        let itemId = UUID()
        let image = LocalPendingImage(
            localFilePath: "/tmp/photo.jpg",
            itemLocalId: itemId
        )

        XCTAssertNotNil(image.localId)
        XCTAssertEqual(image.localFilePath, "/tmp/photo.jpg")
        XCTAssertEqual(image.uploadStatus, .pending)
        XCTAssertNil(image.serverKey)
        XCTAssertNil(image.serverUrl)
        XCTAssertEqual(image.retryCount, 0)
        XCTAssertEqual(image.itemLocalId, itemId)
    }

    func testInitWithAllParameters() {
        let fixedId = UUID()
        let itemId = UUID()

        let image = LocalPendingImage(
            localId: fixedId,
            localFilePath: "/documents/image.png",
            uploadStatus: .uploaded,
            serverKey: "abc-123",
            serverUrl: "https://cdn.example.com/abc-123.png",
            retryCount: 3,
            itemLocalId: itemId
        )

        XCTAssertEqual(image.localId, fixedId)
        XCTAssertEqual(image.localFilePath, "/documents/image.png")
        XCTAssertEqual(image.uploadStatus, .uploaded)
        XCTAssertEqual(image.serverKey, "abc-123")
        XCTAssertEqual(image.serverUrl, "https://cdn.example.com/abc-123.png")
        XCTAssertEqual(image.retryCount, 3)
        XCTAssertEqual(image.itemLocalId, itemId)
    }

    func testDefaultUploadStatusIsPending() {
        let image = LocalPendingImage(
            localFilePath: "/tmp/test.jpg",
            itemLocalId: UUID()
        )
        XCTAssertEqual(image.uploadStatus, .pending)
    }

    func testDefaultRetryCountIsZero() {
        let image = LocalPendingImage(
            localFilePath: "/tmp/test.jpg",
            itemLocalId: UUID()
        )
        XCTAssertEqual(image.retryCount, 0)
    }

    func testUniqueLocalIdPerInstance() {
        let itemId = UUID()
        let img1 = LocalPendingImage(localFilePath: "/a.jpg", itemLocalId: itemId)
        let img2 = LocalPendingImage(localFilePath: "/b.jpg", itemLocalId: itemId)
        XCTAssertNotEqual(img1.localId, img2.localId)
    }

    func testMutableProperties() {
        let image = LocalPendingImage(
            localFilePath: "/tmp/photo.jpg",
            itemLocalId: UUID()
        )

        image.uploadStatus = .uploading
        image.retryCount = 2
        image.serverKey = "key-456"
        image.serverUrl = "https://cdn.example.com/key-456.jpg"

        XCTAssertEqual(image.uploadStatus, .uploading)
        XCTAssertEqual(image.retryCount, 2)
        XCTAssertEqual(image.serverKey, "key-456")
        XCTAssertEqual(image.serverUrl, "https://cdn.example.com/key-456.jpg")
    }
}

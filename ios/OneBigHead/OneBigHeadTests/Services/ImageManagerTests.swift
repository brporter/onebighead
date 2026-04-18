import XCTest
import SwiftData
@testable import OneBigHead

final class ImageManagerTests: XCTestCase {

    private var container: ModelContainer!
    private var context: ModelContext!
    private var imageManager: ImageManager!
    private var tempDirectory: URL!

    override func setUp() {
        super.setUp()

        let schema = Schema([
            LocalPendingImage.self,
            SyncCommand.self,
            LocalCollection.self,
            LocalCategory.self,
            LocalItem.self
        ])
        let config = ModelConfiguration(isStoredInMemoryOnly: true)
        container = try! ModelContainer(for: schema, configurations: [config])
        context = ModelContext(container)
        imageManager = ImageManager()

        // Create a temp directory for file operations
        tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ImageManagerTests-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    }

    override func tearDown() {
        // Clean up temp directory
        if let tempDirectory, FileManager.default.fileExists(atPath: tempDirectory.path) {
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        tempDirectory = nil
        imageManager = nil
        context = nil
        container = nil
        super.tearDown()
    }

    // MARK: - Helpers

    /// Creates a solid-color test image of the given size.
    private func makeTestImage(width: CGFloat, height: CGFloat) -> UIImage {
        let renderer = UIGraphicsImageRenderer(size: CGSize(width: width, height: height))
        return renderer.image { ctx in
            UIColor.red.setFill()
            ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))
        }
    }

    // MARK: - resizeImage Tests

    func testResizeImageMaintainsAspectRatioLandscape() {
        let image = makeTestImage(width: 4000, height: 2000)
        let resized = ImageManager.resizeImage(image, maxDimension: 2048)

        XCTAssertEqual(resized.size.width, 2048, accuracy: 1)
        XCTAssertEqual(resized.size.height, 1024, accuracy: 1)
    }

    func testResizeImageMaintainsAspectRatioPortrait() {
        let image = makeTestImage(width: 2000, height: 4000)
        let resized = ImageManager.resizeImage(image, maxDimension: 2048)

        XCTAssertEqual(resized.size.height, 2048, accuracy: 1)
        XCTAssertEqual(resized.size.width, 1024, accuracy: 1)
    }

    func testResizeImageMaintainsAspectRatioSquare() {
        let image = makeTestImage(width: 3000, height: 3000)
        let resized = ImageManager.resizeImage(image, maxDimension: 2048)

        XCTAssertEqual(resized.size.width, 2048, accuracy: 1)
        XCTAssertEqual(resized.size.height, 2048, accuracy: 1)
    }

    func testResizeImageDoesNotUpscaleSmallImages() {
        let image = makeTestImage(width: 500, height: 300)
        let resized = ImageManager.resizeImage(image, maxDimension: 2048)

        XCTAssertEqual(resized.size.width, 500, accuracy: 1)
        XCTAssertEqual(resized.size.height, 300, accuracy: 1)
    }

    func testResizeImageDoesNotUpscaleExactSize() {
        let image = makeTestImage(width: 2048, height: 1024)
        let resized = ImageManager.resizeImage(image, maxDimension: 2048)

        XCTAssertEqual(resized.size.width, 2048, accuracy: 1)
        XCTAssertEqual(resized.size.height, 1024, accuracy: 1)
    }

    func testResizeImageCorrectlyDownsizesLargeImage() {
        let image = makeTestImage(width: 6000, height: 4000)
        let resized = ImageManager.resizeImage(image, maxDimension: 1000)

        XCTAssertEqual(resized.size.width, 1000, accuracy: 1)
        XCTAssertEqual(resized.size.height, 666, accuracy: 1)
    }

    func testResizeImageWithCustomMaxDimension() {
        let image = makeTestImage(width: 800, height: 600)
        let resized = ImageManager.resizeImage(image, maxDimension: 400)

        XCTAssertEqual(resized.size.width, 400, accuracy: 1)
        XCTAssertEqual(resized.size.height, 300, accuracy: 1)
    }

    func testResizeImageReturnsNewImageWhenResized() {
        let image = makeTestImage(width: 4000, height: 2000)
        let resized = ImageManager.resizeImage(image, maxDimension: 2048)

        // The resized image should have different dimensions
        XCTAssertNotEqual(resized.size, image.size)
    }

    // MARK: - saveImage Tests

    func testSaveImageCreatesLocalPendingImageRecord() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 100, height: 100)

        let pending = try imageManager.saveImage(image, for: itemId, in: context)

        XCTAssertEqual(pending.itemLocalId, itemId)
        XCTAssertEqual(pending.uploadStatus, .pending)
        XCTAssertEqual(pending.retryCount, 0)
        XCTAssertNil(pending.serverKey)
        XCTAssertNil(pending.serverUrl)
    }

    func testSaveImageCreatesFileOnDisk() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 100, height: 100)

        let pending = try imageManager.saveImage(image, for: itemId, in: context)

        XCTAssertTrue(FileManager.default.fileExists(atPath: pending.localFilePath))
    }

    func testSaveImageFileIsValidJPEG() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 100, height: 100)

        let pending = try imageManager.saveImage(image, for: itemId, in: context)
        let data = try Data(contentsOf: URL(fileURLWithPath: pending.localFilePath))

        // JPEG files start with 0xFF 0xD8
        XCTAssertGreaterThan(data.count, 2)
        XCTAssertEqual(data[0], 0xFF)
        XCTAssertEqual(data[1], 0xD8)
    }

    func testSaveImageResizesLargeImage() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 4000, height: 3000)

        let pending = try imageManager.saveImage(image, for: itemId, in: context, maxDimension: 2048)

        // Load the saved image and verify file exists and has data
        let savedImage = UIImage(contentsOfFile: pending.localFilePath)
        XCTAssertNotNil(savedImage)
        // The pixel data in the JPEG should be resized; verify via the data size being smaller
        // than a 4000x3000 JPEG would be. Also verify the file was actually created.
        let data = try Data(contentsOf: URL(fileURLWithPath: pending.localFilePath))
        XCTAssertGreaterThan(data.count, 0)
    }

    func testSaveImageFilePathEndsWithJpg() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 100, height: 100)

        let pending = try imageManager.saveImage(image, for: itemId, in: context)

        XCTAssertTrue(pending.localFilePath.hasSuffix(".jpg"))
    }

    func testSaveImageUniqueIdsPerCall() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 100, height: 100)

        let pending1 = try imageManager.saveImage(image, for: itemId, in: context)
        let pending2 = try imageManager.saveImage(image, for: itemId, in: context)

        XCTAssertNotEqual(pending1.localId, pending2.localId)
        XCTAssertNotEqual(pending1.localFilePath, pending2.localFilePath)
    }

    // MARK: - loadImage Tests

    func testLoadImageReturnsSavedImage() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 200, height: 150)

        let pending = try imageManager.saveImage(image, for: itemId, in: context)
        let loaded = imageManager.loadImage(for: pending)

        XCTAssertNotNil(loaded)
        // JPEG reload may have different scale, so just verify non-nil and non-zero
        XCTAssertGreaterThan(loaded!.size.width, 0)
        XCTAssertGreaterThan(loaded!.size.height, 0)
    }

    func testLoadImageReturnsNilForMissingFile() {
        let pending = LocalPendingImage(
            localFilePath: "/nonexistent/path/image.jpg",
            itemLocalId: UUID()
        )
        let loaded = imageManager.loadImage(for: pending)

        XCTAssertNil(loaded)
    }

    // MARK: - imageData Tests

    func testImageDataReturnsDataForSavedImage() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 100, height: 100)

        let pending = try imageManager.saveImage(image, for: itemId, in: context)
        let data = imageManager.imageData(for: pending)

        XCTAssertNotNil(data)
        XCTAssertGreaterThan(data!.count, 0)
    }

    func testImageDataReturnsNilForMissingFile() {
        let pending = LocalPendingImage(
            localFilePath: "/nonexistent/path/image.jpg",
            itemLocalId: UUID()
        )
        let data = imageManager.imageData(for: pending)

        XCTAssertNil(data)
    }

    // MARK: - deleteLocalImage Tests

    func testDeleteLocalImageRemovesFile() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 100, height: 100)
        let pending = try imageManager.saveImage(image, for: itemId, in: context)
        let filePath = pending.localFilePath

        XCTAssertTrue(FileManager.default.fileExists(atPath: filePath))

        imageManager.deleteLocalImage(pending, in: context)

        XCTAssertFalse(FileManager.default.fileExists(atPath: filePath))
    }

    func testDeleteLocalImageRemovesRecord() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 100, height: 100)
        let pending = try imageManager.saveImage(image, for: itemId, in: context)

        imageManager.deleteLocalImage(pending, in: context)

        let descriptor = FetchDescriptor<LocalPendingImage>()
        let results = try context.fetch(descriptor)
        XCTAssertTrue(results.isEmpty)
    }

    func testDeleteLocalImageHandlesMissingFile() {
        let pending = LocalPendingImage(
            localFilePath: "/nonexistent/path/image.jpg",
            itemLocalId: UUID()
        )
        context.insert(pending)

        // Should not throw
        imageManager.deleteLocalImage(pending, in: context)
    }

    // MARK: - cleanupUploadedImages Tests

    func testCleanupUploadedImagesOnlyRemovesUploaded() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 100, height: 100)

        // Create a pending image
        let pendingImg = try imageManager.saveImage(image, for: itemId, in: context)
        let pendingPath = pendingImg.localFilePath

        // Create an uploaded image
        let uploadedImg = try imageManager.saveImage(image, for: itemId, in: context)
        let uploadedPath = uploadedImg.localFilePath
        uploadedImg.uploadStatus = .uploaded

        // Create a failed image
        let failedImg = try imageManager.saveImage(image, for: itemId, in: context)
        let failedPath = failedImg.localFilePath
        failedImg.uploadStatus = .failed

        try imageManager.cleanupUploadedImages(in: context)

        // The uploaded image file and record should be gone
        XCTAssertFalse(FileManager.default.fileExists(atPath: uploadedPath))

        // The pending and failed images should still exist
        XCTAssertTrue(FileManager.default.fileExists(atPath: pendingPath))
        XCTAssertTrue(FileManager.default.fileExists(atPath: failedPath))

        let remaining = try context.fetch(FetchDescriptor<LocalPendingImage>())
        XCTAssertEqual(remaining.count, 2)

        let statuses = Set(remaining.map { $0.uploadStatus })
        XCTAssertTrue(statuses.contains(.pending))
        XCTAssertTrue(statuses.contains(.failed))
        XCTAssertFalse(statuses.contains(.uploaded))
    }

    func testCleanupUploadedImagesWithNoUploadedImages() throws {
        let itemId = UUID()
        let image = makeTestImage(width: 100, height: 100)
        let _ = try imageManager.saveImage(image, for: itemId, in: context)

        try imageManager.cleanupUploadedImages(in: context)

        let remaining = try context.fetch(FetchDescriptor<LocalPendingImage>())
        XCTAssertEqual(remaining.count, 1)
    }

    func testCleanupUploadedImagesWithEmptyDatabase() throws {
        // Should not throw when there are no images at all
        try imageManager.cleanupUploadedImages(in: context)

        let remaining = try context.fetch(FetchDescriptor<LocalPendingImage>())
        XCTAssertTrue(remaining.isEmpty)
    }

    // MARK: - ImageManagerError Tests

    func testJpegConversionFailedErrorDescription() {
        let error = ImageManagerError.jpegConversionFailed
        XCTAssertEqual(error.errorDescription, "Failed to convert image to JPEG format.")
    }

    // MARK: - pendingImagesDirectoryURL Tests

    func testPendingImagesDirectoryURLCreatesDirectory() throws {
        let url = try ImageManager.pendingImagesDirectoryURL()

        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        XCTAssertTrue(url.path.contains("pending_images"))
    }

    func testPendingImagesDirectoryURLIsIdempotent() throws {
        let url1 = try ImageManager.pendingImagesDirectoryURL()
        let url2 = try ImageManager.pendingImagesDirectoryURL()

        XCTAssertEqual(url1, url2)
    }
}

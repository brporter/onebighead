import XCTest
@testable import OneBigHead

final class CachedAsyncImageCacheTests: XCTestCase {

    override func tearDown() {
        CachedAsyncImageCache.shared.cache.removeAllObjects()
        super.tearDown()
    }

    func testSharedInstanceIsSingleton() {
        let a = CachedAsyncImageCache.shared
        let b = CachedAsyncImageCache.shared
        XCTAssertTrue(a === b)
    }

    func testCacheStoresAndRetrievesImage() {
        let cache = CachedAsyncImageCache.shared.cache
        let url = NSURL(string: "https://example.com/test.jpg")!

        let renderer = UIGraphicsImageRenderer(size: CGSize(width: 10, height: 10))
        let image = renderer.image { ctx in
            UIColor.blue.setFill()
            ctx.fill(CGRect(x: 0, y: 0, width: 10, height: 10))
        }

        cache.setObject(image, forKey: url)
        let retrieved = cache.object(forKey: url)

        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved!.size.width, 10, accuracy: 1)
    }

    func testCacheReturnsNilForMissingKey() {
        let cache = CachedAsyncImageCache.shared.cache
        let url = NSURL(string: "https://example.com/missing.jpg")!

        let retrieved = cache.object(forKey: url)
        XCTAssertNil(retrieved)
    }

    func testCacheCountLimit() {
        let cache = CachedAsyncImageCache.shared.cache
        XCTAssertEqual(cache.countLimit, 100)
    }
}

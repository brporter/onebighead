import XCTest
@testable import OneBigHead

final class ExtensionsTests: XCTestCase {

    // MARK: - Date ISO 8601

    func testDateISO8601StringFormat() {
        // January 15, 2024, 10:30:00 UTC
        let date = Date(timeIntervalSince1970: 1705312200)
        let result = date.iso8601String

        XCTAssertTrue(result.contains("2024-01-15"))
        XCTAssertTrue(result.contains("T"))
        XCTAssertTrue(result.hasSuffix("Z"))
    }

    func testDateISO8601StringConsistency() {
        let date = Date(timeIntervalSince1970: 0)
        let result = date.iso8601String
        XCTAssertEqual(result, "1970-01-01T00:00:00Z")
    }

    func testDateFromISO8601ValidString() {
        let date = Date.fromISO8601("2024-01-15T10:30:00Z")
        XCTAssertNotNil(date)

        if let date = date {
            XCTAssertEqual(date.iso8601String, "2024-01-15T10:30:00Z")
        }
    }

    func testDateFromISO8601InvalidString() {
        let date = Date.fromISO8601("not-a-date")
        XCTAssertNil(date)
    }

    func testDateFromISO8601EmptyString() {
        let date = Date.fromISO8601("")
        XCTAssertNil(date)
    }

    func testDateISO8601RoundTrip() {
        let original = Date()
        let string = original.iso8601String
        let restored = Date.fromISO8601(string)

        XCTAssertNotNil(restored)
        // ISO 8601 has second precision, so compare within 1 second
        if let restored = restored {
            XCTAssertEqual(original.timeIntervalSince1970, restored.timeIntervalSince1970, accuracy: 1.0)
        }
    }

    // MARK: - Data Pretty-Printed JSON

    func testDataPrettyPrintedJSONWithValidJSON() throws {
        let dict = ["name": "test", "value": "123"]
        let data = try JSONSerialization.data(withJSONObject: dict, options: [])

        let result = data.prettyPrintedJSONString
        XCTAssertNotNil(result)

        if let result = result {
            XCTAssertTrue(result.contains("\"name\""))
            XCTAssertTrue(result.contains("\"test\""))
            XCTAssertTrue(result.contains("\"value\""))
            XCTAssertTrue(result.contains("\"123\""))
        }
    }

    func testDataPrettyPrintedJSONWithArray() throws {
        let array = [1, 2, 3]
        let data = try JSONSerialization.data(withJSONObject: array, options: [])

        let result = data.prettyPrintedJSONString
        XCTAssertNotNil(result)

        if let result = result {
            XCTAssertTrue(result.contains("1"))
            XCTAssertTrue(result.contains("2"))
            XCTAssertTrue(result.contains("3"))
        }
    }

    func testDataPrettyPrintedJSONWithInvalidJSON() {
        let data = Data("not json at all".utf8)
        let result = data.prettyPrintedJSONString
        XCTAssertNil(result)
    }

    func testDataPrettyPrintedJSONWithEmptyObject() throws {
        let data = Data("{}".utf8)
        let result = data.prettyPrintedJSONString
        XCTAssertNotNil(result)

        if let result = result {
            XCTAssertTrue(result.contains("{"))
            XCTAssertTrue(result.contains("}"))
        }
    }

    func testDataPrettyPrintedJSONWithEmptyData() {
        let data = Data()
        let result = data.prettyPrintedJSONString
        XCTAssertNil(result)
    }

    func testDataPrettyPrintedJSONContainsNewlines() throws {
        let dict: [String: Any] = ["key1": "value1", "key2": "value2"]
        let data = try JSONSerialization.data(withJSONObject: dict, options: [])

        let result = data.prettyPrintedJSONString
        XCTAssertNotNil(result)

        if let result = result {
            // Pretty-printed JSON should contain newlines for formatting
            XCTAssertTrue(result.contains("\n"))
        }
    }
}

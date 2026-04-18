import XCTest
@testable import OneBigHead

final class EnumsTests: XCTestCase {

    // MARK: - SyncStatus

    func testSyncStatusRawValues() {
        XCTAssertEqual(SyncStatus.synced.rawValue, "synced")
        XCTAssertEqual(SyncStatus.pendingCreate.rawValue, "pendingCreate")
        XCTAssertEqual(SyncStatus.pendingUpdate.rawValue, "pendingUpdate")
        XCTAssertEqual(SyncStatus.pendingDelete.rawValue, "pendingDelete")
    }

    func testSyncStatusCodableRoundTrip() throws {
        for status in [SyncStatus.synced, .pendingCreate, .pendingUpdate, .pendingDelete] {
            let data = try JSONEncoder().encode(status)
            let decoded = try JSONDecoder().decode(SyncStatus.self, from: data)
            XCTAssertEqual(status, decoded)
        }
    }

    func testSyncStatusDecodesFromRawValueString() throws {
        let json = Data("\"pendingCreate\"".utf8)
        let decoded = try JSONDecoder().decode(SyncStatus.self, from: json)
        XCTAssertEqual(decoded, .pendingCreate)
    }

    func testSyncStatusFailsForInvalidRawValue() {
        let json = Data("\"invalid\"".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(SyncStatus.self, from: json))
    }

    // MARK: - CommandStatus

    func testCommandStatusRawValues() {
        XCTAssertEqual(CommandStatus.pending.rawValue, "pending")
        XCTAssertEqual(CommandStatus.executing.rawValue, "executing")
        XCTAssertEqual(CommandStatus.completed.rawValue, "completed")
        XCTAssertEqual(CommandStatus.failed.rawValue, "failed")
        XCTAssertEqual(CommandStatus.cancelled.rawValue, "cancelled")
    }

    func testCommandStatusCodableRoundTrip() throws {
        for status in [CommandStatus.pending, .executing, .completed, .failed, .cancelled] {
            let data = try JSONEncoder().encode(status)
            let decoded = try JSONDecoder().decode(CommandStatus.self, from: data)
            XCTAssertEqual(status, decoded)
        }
    }

    func testCommandStatusDecodesFromRawValueString() throws {
        let json = Data("\"cancelled\"".utf8)
        let decoded = try JSONDecoder().decode(CommandStatus.self, from: json)
        XCTAssertEqual(decoded, .cancelled)
    }

    func testCommandStatusFailsForInvalidRawValue() {
        let json = Data("\"unknown\"".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(CommandStatus.self, from: json))
    }

    // MARK: - UploadStatus

    func testUploadStatusRawValues() {
        XCTAssertEqual(UploadStatus.pending.rawValue, "pending")
        XCTAssertEqual(UploadStatus.uploading.rawValue, "uploading")
        XCTAssertEqual(UploadStatus.uploaded.rawValue, "uploaded")
        XCTAssertEqual(UploadStatus.failed.rawValue, "failed")
    }

    func testUploadStatusCodableRoundTrip() throws {
        for status in [UploadStatus.pending, .uploading, .uploaded, .failed] {
            let data = try JSONEncoder().encode(status)
            let decoded = try JSONDecoder().decode(UploadStatus.self, from: data)
            XCTAssertEqual(status, decoded)
        }
    }

    func testUploadStatusDecodesFromRawValueString() throws {
        let json = Data("\"uploading\"".utf8)
        let decoded = try JSONDecoder().decode(UploadStatus.self, from: json)
        XCTAssertEqual(decoded, .uploading)
    }

    func testUploadStatusFailsForInvalidRawValue() {
        let json = Data("\"bogus\"".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(UploadStatus.self, from: json))
    }

    // MARK: - AuthProvider

    func testAuthProviderRawValues() {
        XCTAssertEqual(AuthProvider.apple.rawValue, "apple")
        XCTAssertEqual(AuthProvider.google.rawValue, "google")
        XCTAssertEqual(AuthProvider.microsoft.rawValue, "microsoft")
    }

    func testAuthProviderCodableRoundTrip() throws {
        for provider in [AuthProvider.apple, .google, .microsoft] {
            let data = try JSONEncoder().encode(provider)
            let decoded = try JSONDecoder().decode(AuthProvider.self, from: data)
            XCTAssertEqual(provider, decoded)
        }
    }

    func testAuthProviderDecodesFromRawValueString() throws {
        let json = Data("\"google\"".utf8)
        let decoded = try JSONDecoder().decode(AuthProvider.self, from: json)
        XCTAssertEqual(decoded, .google)
    }

    func testAuthProviderFailsForInvalidRawValue() {
        let json = Data("\"facebook\"".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(AuthProvider.self, from: json))
    }

    // MARK: - UserFlag

    func testUserFlagRawValues() {
        XCTAssertEqual(UserFlag.have.rawValue, "Have")
        XCTAssertEqual(UserFlag.want.rawValue, "Want")
        XCTAssertEqual(UserFlag.tradeOrSell.rawValue, "TradeOrSell")
    }

    func testUserFlagCodableRoundTrip() throws {
        for flag in [UserFlag.have, .want, .tradeOrSell] {
            let data = try JSONEncoder().encode(flag)
            let decoded = try JSONDecoder().decode(UserFlag.self, from: data)
            XCTAssertEqual(flag, decoded)
        }
    }

    func testUserFlagDecodesFromRawValueString() throws {
        let json = Data("\"TradeOrSell\"".utf8)
        let decoded = try JSONDecoder().decode(UserFlag.self, from: json)
        XCTAssertEqual(decoded, .tradeOrSell)
    }

    func testUserFlagFailsForInvalidRawValue() {
        let json = Data("\"trade\"".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(UserFlag.self, from: json))
    }

    // MARK: - Visibility

    func testVisibilityRawValues() {
        XCTAssertEqual(Visibility.privateVisibility.rawValue, "Private")
        XCTAssertEqual(Visibility.publicVisibility.rawValue, "Public")
    }

    func testVisibilityCodableRoundTrip() throws {
        for visibility in [Visibility.privateVisibility, .publicVisibility] {
            let data = try JSONEncoder().encode(visibility)
            let decoded = try JSONDecoder().decode(Visibility.self, from: data)
            XCTAssertEqual(visibility, decoded)
        }
    }

    func testVisibilityDecodesFromRawValueString() throws {
        let json = Data("\"Public\"".utf8)
        let decoded = try JSONDecoder().decode(Visibility.self, from: json)
        XCTAssertEqual(decoded, .publicVisibility)
    }

    func testVisibilityFailsForInvalidRawValue() {
        let json = Data("\"public\"".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(Visibility.self, from: json))
    }
}

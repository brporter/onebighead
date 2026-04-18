import Foundation

// MARK: - Date Extensions

extension Date {
    /// Formats the date as an ISO 8601 string (e.g. "2024-01-15T10:30:00Z").
    var iso8601String: String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: self)
    }

    /// Creates a Date from an ISO 8601 string. Returns nil if the string is invalid.
    static func fromISO8601(_ string: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: string)
    }
}

// MARK: - Data Extensions

extension Data {
    /// Returns the data as a pretty-printed JSON string, or nil if the data is not valid JSON.
    var prettyPrintedJSONString: String? {
        guard let jsonObject = try? JSONSerialization.jsonObject(with: self, options: []),
              let prettyData = try? JSONSerialization.data(withJSONObject: jsonObject, options: [.prettyPrinted]),
              let prettyString = String(data: prettyData, encoding: .utf8) else {
            return nil
        }
        return prettyString
    }
}

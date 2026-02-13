using System.Text.Json;

namespace OneBigHead.Server.Services.Seeding;

/// <summary>
/// Represents a seed file containing table definitions.
/// </summary>
public class SeedFile
{
    public List<SeedTable> Tables { get; set; } = new();
}

/// <summary>
/// Represents a table to seed with its rows.
/// </summary>
public class SeedTable
{
    /// <summary>
    /// The database table name.
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// Single column to check for idempotency (simple case).
    /// </summary>
    public string? CheckColumn { get; set; }

    /// <summary>
    /// Multiple columns to check for idempotency (composite keys).
    /// </summary>
    public List<string>? CheckColumns { get; set; }

    /// <summary>
    /// Whether to enable identity insert for this table.
    /// </summary>
    public bool IdentityInsert { get; set; }

    /// <summary>
    /// The rows to insert.
    /// </summary>
    public List<Dictionary<string, object?>> Rows { get; set; } = new();

    /// <summary>
    /// Gets the effective list of columns to check for idempotency.
    /// </summary>
    public List<string> GetCheckColumns()
    {
        var columns = CheckColumns?.ToList() ?? new List<string>();
        if (!string.IsNullOrEmpty(CheckColumn) && !columns.Contains(CheckColumn))
        {
            columns.Add(CheckColumn);
        }
        return columns;
    }
}

/// <summary>
/// Result of a seeding operation.
/// </summary>
public class SeedResult
{
    public string TableName { get; set; } = "";
    public int InsertedCount { get; set; }
    public int SkippedCount { get; set; }
}

/// <summary>
/// Helper class for JSON value conversion.
/// </summary>
public static class JsonValueConverter
{
    /// <summary>
    /// Converts a JsonElement to its native .NET type.
    /// </summary>
    public static object? ConvertJsonElement(object? value)
    {
        if (value is JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.String => element.GetString(),
                JsonValueKind.Number => element.TryGetInt32(out var i) ? i :
                                        element.TryGetInt64(out var l) ? l :
                                        element.GetDouble(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Null => null,
                _ => element.ToString()
            };
        }
        return value;
    }
}

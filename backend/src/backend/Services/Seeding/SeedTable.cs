namespace OneBigHead.Server.Services.Seeding;

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
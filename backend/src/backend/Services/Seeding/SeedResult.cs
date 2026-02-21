namespace OneBigHead.Server.Services.Seeding;

/// <summary>
/// Result of a seeding operation.
/// </summary>
public class SeedResult
{
    public string TableName { get; set; } = "";
    public int InsertedCount { get; set; }
    public int SkippedCount { get; set; }
}
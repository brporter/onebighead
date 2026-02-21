namespace OneBigHead.Server.Services.Seeding;

/// <summary>
/// Represents a seed file containing table definitions.
/// </summary>
public class SeedFile
{
    public List<SeedTable> Tables { get; set; } = new();
}
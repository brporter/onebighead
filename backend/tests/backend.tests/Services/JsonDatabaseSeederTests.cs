using System.Text.Json;
using Npgsql;
using OneBigHead.Server.Services.Seeding;

namespace OneBigHead.Server.Tests.Services;

/// <summary>
/// Tests for JsonDatabaseSeeder covering file discovery and dry-run seeding.
/// Dry-run mode never touches the database, so an unopened connection is used.
/// </summary>
public class JsonDatabaseSeederTests : IDisposable
{
    private readonly string _tempDir;

    public JsonDatabaseSeederTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"seeder-tests-{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        GC.SuppressFinalize(this);
    }

    private void WriteSeedFile(string fileName, string json)
        => File.WriteAllText(Path.Combine(_tempDir, fileName), json);

    [Fact]
    public void GetSeedFiles_ReturnsEmpty_WhenDirectoryDoesNotExist()
    {
        var seeder = new JsonDatabaseSeeder(Path.Combine(_tempDir, "missing"));

        Assert.Empty(seeder.GetSeedFiles());
    }

    [Fact]
    public void GetSeedFiles_ReturnsEmpty_WhenDirectoryHasNoJsonFiles()
    {
        var seeder = new JsonDatabaseSeeder(_tempDir);

        Assert.Empty(seeder.GetSeedFiles());
    }

    [Fact]
    public void GetSeedFiles_ReturnsFileNames_InAlphabeticalOrder()
    {
        WriteSeedFile("02-second.json", "{}");
        WriteSeedFile("01-first.json", "{}");
        var seeder = new JsonDatabaseSeeder(_tempDir);

        var files = seeder.GetSeedFiles();

        Assert.Equal(new[] { "01-first.json", "02-second.json" }, files);
    }

    [Fact]
    public void GetSeedFiles_IgnoresNonJsonFiles()
    {
        WriteSeedFile("readme.txt", "not json");
        WriteSeedFile("01-data.json", "{}");
        var seeder = new JsonDatabaseSeeder(_tempDir);

        var files = seeder.GetSeedFiles();

        Assert.Equal(new[] { "01-data.json" }, files);
    }

    [Fact]
    public async Task SeedAsync_ReturnsEmpty_WhenDirectoryDoesNotExist()
    {
        var seeder = new JsonDatabaseSeeder(Path.Combine(_tempDir, "missing"));
        using var connection = new NpgsqlConnection();

        var results = await seeder.SeedAsync(connection, dryRun: true);

        Assert.Empty(results);
    }

    [Fact]
    public async Task SeedAsync_ReturnsEmpty_WhenNoSeedFiles()
    {
        var seeder = new JsonDatabaseSeeder(_tempDir);
        using var connection = new NpgsqlConnection();

        var results = await seeder.SeedAsync(connection, dryRun: true);

        Assert.Empty(results);
    }

    [Fact]
    public async Task SeedAsync_SkipsFiles_WithNoTables()
    {
        WriteSeedFile("01-empty.json", "{}");
        WriteSeedFile("02-empty-tables.json", """{"tables": []}""");
        var seeder = new JsonDatabaseSeeder(_tempDir);
        using var connection = new NpgsqlConnection();

        var results = await seeder.SeedAsync(connection, dryRun: true);

        Assert.Empty(results);
    }

    [Fact]
    public async Task SeedAsync_DryRun_CountsRowsWithoutDatabaseAccess()
    {
        WriteSeedFile("01-data.json", """
            {
              "tables": [
                {
                  "name": "ItemTemplates",
                  "checkColumn": "Name",
                  "identityInsert": true,
                  "rows": [
                    { "Id": 1, "Name": "Book", "CreatedAt": "2026-01-01T00:00:00Z" },
                    { "Id": 2, "Name": "Coin", "CreatedAt": "2026-01-01T00:00:00Z" }
                  ]
                }
              ]
            }
            """);
        var seeder = new JsonDatabaseSeeder(_tempDir);
        // Dry run must not touch the database - an unopened connection proves it
        using var connection = new NpgsqlConnection();

        var results = await seeder.SeedAsync(connection, dryRun: true);

        var result = Assert.Single(results);
        Assert.Equal("ItemTemplates", result.TableName);
        Assert.Equal(2, result.InsertedCount);
        Assert.Equal(0, result.SkippedCount);
    }

    [Fact]
    public async Task SeedAsync_DryRun_ReturnsResultPerTable_AcrossFiles()
    {
        WriteSeedFile("01-first.json", """
            {
              "tables": [
                { "name": "TableA", "rows": [ { "Name": "a" } ] },
                { "name": "TableB", "rows": [ { "Name": "b1" }, { "Name": "b2" } ] }
              ]
            }
            """);
        WriteSeedFile("02-second.json", """
            {
              "tables": [
                { "name": "TableC", "rows": [ { "Name": "c" } ] }
              ]
            }
            """);
        var seeder = new JsonDatabaseSeeder(_tempDir);
        using var connection = new NpgsqlConnection();

        var results = await seeder.SeedAsync(connection, dryRun: true);

        Assert.Equal(3, results.Count);
        Assert.Equal(new[] { "TableA", "TableB", "TableC" }, results.Select(r => r.TableName));
        Assert.Equal(new[] { 1, 2, 1 }, results.Select(r => r.InsertedCount));
    }

    [Fact]
    public async Task SeedAsync_ReturnsZeroCounts_ForTableWithNoRows()
    {
        WriteSeedFile("01-no-rows.json", """
            {
              "tables": [
                { "name": "EmptyTable", "rows": [] }
              ]
            }
            """);
        var seeder = new JsonDatabaseSeeder(_tempDir);
        using var connection = new NpgsqlConnection();

        var results = await seeder.SeedAsync(connection, dryRun: true);

        var result = Assert.Single(results);
        Assert.Equal("EmptyTable", result.TableName);
        Assert.Equal(0, result.InsertedCount);
        Assert.Equal(0, result.SkippedCount);
    }

    [Fact]
    public async Task SeedAsync_AllowsCommentsAndTrailingCommas_InSeedFiles()
    {
        WriteSeedFile("01-commented.json", """
            {
              // seed data with comments
              "tables": [
                { "name": "TableA", "rows": [ { "Name": "a" }, ] },
              ],
            }
            """);
        var seeder = new JsonDatabaseSeeder(_tempDir);
        using var connection = new NpgsqlConnection();

        var results = await seeder.SeedAsync(connection, dryRun: true);

        var result = Assert.Single(results);
        Assert.Equal(1, result.InsertedCount);
    }
}

/// <summary>
/// Tests for the SeedTable check-column resolution logic.
/// </summary>
public class SeedTableTests
{
    [Fact]
    public void GetCheckColumns_ReturnsEmpty_WhenNothingConfigured()
    {
        var table = new SeedTable();

        Assert.Empty(table.GetCheckColumns());
    }

    [Fact]
    public void GetCheckColumns_ReturnsSingleColumn_FromCheckColumn()
    {
        var table = new SeedTable { CheckColumn = "Name" };

        Assert.Equal(new[] { "Name" }, table.GetCheckColumns());
    }

    [Fact]
    public void GetCheckColumns_ReturnsCompositeColumns_FromCheckColumns()
    {
        var table = new SeedTable { CheckColumns = new List<string> { "ThemeId", "ItemTemplateId" } };

        Assert.Equal(new[] { "ThemeId", "ItemTemplateId" }, table.GetCheckColumns());
    }

    [Fact]
    public void GetCheckColumns_CombinesBoth_WithoutDuplicates()
    {
        var table = new SeedTable
        {
            CheckColumn = "Name",
            CheckColumns = new List<string> { "Name", "ThemeId" }
        };

        Assert.Equal(new[] { "Name", "ThemeId" }, table.GetCheckColumns());
    }
}

/// <summary>
/// Tests for JSON seed value conversion to native .NET types.
/// </summary>
public class JsonValueConverterTests
{
    private static object? Convert(string json)
        => JsonValueConverter.ConvertJsonElement(JsonSerializer.Deserialize<JsonElement>(json));

    [Fact]
    public void ConvertJsonElement_ConvertsString() => Assert.Equal("hello", Convert("\"hello\""));

    [Fact]
    public void ConvertJsonElement_ConvertsInt() => Assert.Equal(42, Convert("42"));

    [Fact]
    public void ConvertJsonElement_ConvertsLong() => Assert.Equal(5_000_000_000L, Convert("5000000000"));

    [Fact]
    public void ConvertJsonElement_ConvertsDouble() => Assert.Equal(3.14, Convert("3.14"));

    [Fact]
    public void ConvertJsonElement_ConvertsTrue() => Assert.Equal(true, Convert("true"));

    [Fact]
    public void ConvertJsonElement_ConvertsFalse() => Assert.Equal(false, Convert("false"));

    [Fact]
    public void ConvertJsonElement_ConvertsNull() => Assert.Null(Convert("null"));

    [Fact]
    public void ConvertJsonElement_PassesThroughNonJsonElement()
    {
        Assert.Equal("plain", JsonValueConverter.ConvertJsonElement("plain"));
        Assert.Null(JsonValueConverter.ConvertJsonElement(null));
    }

    [Fact]
    public void ConvertJsonElement_StringifiesComplexValues()
    {
        var result = Convert("""{"a": 1}""");
        Assert.Equal("""{"a": 1}""", result);
    }
}

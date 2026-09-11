using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Seeding;

namespace OneBigHead.Server.Tests.Integration.Postgres;

/// <summary>
/// Exercises JsonDatabaseSeeder against a real PostgreSQL database: actual
/// inserts, convergent re-runs that update existing rows to match the seed
/// files, transactional rollback on failure, parameter type inference for
/// uuid/timestamptz columns, and identity sequence resynchronization after
/// explicit-ID inserts.
/// </summary>
[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class PostgresJsonDatabaseSeederTests : IAsyncLifetime
{
    private readonly PostgresIntegrationFixture _fixture;
    private readonly string _tempDir;

    public PostgresJsonDatabaseSeederTests(PostgresIntegrationFixture fixture)
    {
        _fixture = fixture;
        _tempDir = Path.Combine(Path.GetTempPath(), $"pg-seeder-tests-{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDir);
    }

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        return Task.CompletedTask;
    }

    private void WriteSeedFile(string fileName, string json)
        => File.WriteAllText(Path.Combine(_tempDir, fileName), json);

    private const string ItemTemplatesSeed = """
        {
          "tables": [
            {
              "name": "ItemTemplates",
              "checkColumn": "TemplateKey",
              "identityInsert": true,
              "rows": [
                {
                  "Id": 10,
                  "TemplateKey": "a1b2c3d4-1111-4000-8000-00000000f001",
                  "Name": "Integration Book",
                  "Description": "Seeded by integration test",
                  "CreatedAt": "2026-01-01T00:00:00Z",
                  "UpdatedAt": "2026-01-01T00:00:00Z"
                },
                {
                  "Id": 20,
                  "TemplateKey": "a1b2c3d4-2222-4000-8000-00000000f002",
                  "Name": "Integration Coin",
                  "Description": "Seeded by integration test",
                  "CreatedAt": "2026-01-01T00:00:00Z",
                  "UpdatedAt": "2026-01-01T00:00:00Z"
                }
              ]
            }
          ]
        }
        """;

    [Fact]
    public async Task SeedAsync_InsertsRows_ConvertingStringValuesToUuidAndTimestamptz()
    {
        WriteSeedFile("01-templates.json", ItemTemplatesSeed);
        var seeder = new JsonDatabaseSeeder(_tempDir);

        var results = await seeder.SeedAsync(_fixture.ConnectionString);

        var result = Assert.Single(results);
        Assert.Equal(2, result.InsertedCount);
        Assert.Equal(0, result.UpdatedCount);
        Assert.Equal(0, result.SkippedCount);

        await using var context = _fixture.CreateContext();
        var book = await context.ItemTemplates.SingleAsync(t => t.Id == 10);
        Assert.Equal("Integration Book", book.Name);
        Assert.Equal(Guid.Parse("a1b2c3d4-1111-4000-8000-00000000f001"), book.TemplateKey);
        Assert.Equal(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), book.CreatedAt);
    }

    [Fact]
    public async Task SeedAsync_SecondRun_UpdatesExistingRows_WithoutDuplicating()
    {
        WriteSeedFile("01-templates.json", ItemTemplatesSeed);
        var seeder = new JsonDatabaseSeeder(_tempDir);
        await seeder.SeedAsync(_fixture.ConnectionString);

        var results = await seeder.SeedAsync(_fixture.ConnectionString);

        var result = Assert.Single(results);
        Assert.Equal(0, result.InsertedCount);
        Assert.Equal(2, result.UpdatedCount);
        Assert.Equal(0, result.SkippedCount);

        await using var context = _fixture.CreateContext();
        Assert.Equal(2, await context.ItemTemplates.CountAsync());
    }

    [Fact]
    public async Task SeedAsync_PropagatesEditedSeedValues_ToExistingRows()
    {
        WriteSeedFile("01-templates.json", ItemTemplatesSeed);
        var seeder = new JsonDatabaseSeeder(_tempDir);
        await seeder.SeedAsync(_fixture.ConnectionString);

        // Edit the seed file the way a developer fixes a typo: same
        // TemplateKey (the check column), different name and description.
        WriteSeedFile("01-templates.json", ItemTemplatesSeed
            .Replace("Integration Book", "Integration Book (Revised)")
            .Replace("Seeded by integration test", "Corrected description"));

        var results = await seeder.SeedAsync(_fixture.ConnectionString);

        var result = Assert.Single(results);
        Assert.Equal(0, result.InsertedCount);
        Assert.Equal(2, result.UpdatedCount);

        await using var context = _fixture.CreateContext();
        var book = await context.ItemTemplates.SingleAsync(t => t.Id == 10);
        Assert.Equal("Integration Book (Revised)", book.Name);
        Assert.Equal("Corrected description", book.Description);
        Assert.Equal(2, await context.ItemTemplates.CountAsync());
    }

    [Fact]
    public async Task SeedAsync_NeverRewritesId_WhenExistingRowHasDifferentIdentity()
    {
        WriteSeedFile("01-templates.json", ItemTemplatesSeed);
        var seeder = new JsonDatabaseSeeder(_tempDir);
        await seeder.SeedAsync(_fixture.ConnectionString);

        // Same rows with different explicit Ids: the update path must leave
        // the stored Ids untouched because foreign keys may reference them.
        WriteSeedFile("01-templates.json", ItemTemplatesSeed
            .Replace("\"Id\": 10,", "\"Id\": 99,")
            .Replace("\"Id\": 20,", "\"Id\": 88,"));

        await seeder.SeedAsync(_fixture.ConnectionString);

        await using var context = _fixture.CreateContext();
        Assert.NotNull(await context.ItemTemplates.SingleOrDefaultAsync(t => t.Id == 10));
        Assert.NotNull(await context.ItemTemplates.SingleOrDefaultAsync(t => t.Id == 20));
    }

    [Fact]
    public async Task SeedAsync_CountsRowAsSkipped_WhenEveryColumnIsACheckColumn()
    {
        // Every column doubles as a check column, so a re-run has nothing to
        // update and reports the row as skipped.
        var seed = """
            {
              "tables": [
                {
                  "name": "ItemTemplates",
                  "checkColumns": ["TemplateKey", "Name", "Description", "CreatedAt", "UpdatedAt"],
                  "rows": [
                    {
                      "TemplateKey": "a1b2c3d4-3333-4000-8000-00000000f003",
                      "Name": "Check-Only Template",
                      "Description": "All columns are identity",
                      "CreatedAt": "2026-01-01T00:00:00Z",
                      "UpdatedAt": "2026-01-01T00:00:00Z"
                    }
                  ]
                }
              ]
            }
            """;
        WriteSeedFile("01-check-only.json", seed);
        var seeder = new JsonDatabaseSeeder(_tempDir);
        await seeder.SeedAsync(_fixture.ConnectionString);

        var results = await seeder.SeedAsync(_fixture.ConnectionString);

        var result = Assert.Single(results);
        Assert.Equal(0, result.InsertedCount);
        Assert.Equal(0, result.UpdatedCount);
        Assert.Equal(1, result.SkippedCount);
    }

    [Fact]
    public async Task SeedAsync_RollsBackAllChanges_WhenAnyRowFails()
    {
        // The second table references a column that does not exist, so the
        // whole run must fail and the first table's rows must not persist.
        var seed = """
            {
              "tables": [
                {
                  "name": "ItemTemplates",
                  "checkColumn": "TemplateKey",
                  "identityInsert": true,
                  "rows": [
                    {
                      "Id": 10,
                      "TemplateKey": "a1b2c3d4-1111-4000-8000-00000000f001",
                      "Name": "Doomed Template",
                      "Description": "Must roll back",
                      "CreatedAt": "2026-01-01T00:00:00Z",
                      "UpdatedAt": "2026-01-01T00:00:00Z"
                    }
                  ]
                },
                {
                  "name": "ItemTemplates",
                  "checkColumn": "TemplateKey",
                  "rows": [
                    { "TemplateKey": "a1b2c3d4-2222-4000-8000-00000000f002", "NoSuchColumn": true }
                  ]
                }
              ]
            }
            """;
        WriteSeedFile("01-failing.json", seed);
        var seeder = new JsonDatabaseSeeder(_tempDir);

        await Assert.ThrowsAsync<PostgresException>(
            () => seeder.SeedAsync(_fixture.ConnectionString));

        await using var context = _fixture.CreateContext();
        Assert.Equal(0, await context.ItemTemplates.CountAsync());
    }

    [Fact]
    public async Task SeedAsync_ResyncsIdentitySequence_SoSubsequentInsertsDoNotCollide()
    {
        WriteSeedFile("01-templates.json", ItemTemplatesSeed);
        var seeder = new JsonDatabaseSeeder(_tempDir);
        await seeder.SeedAsync(_fixture.ConnectionString);

        await using var context = _fixture.CreateContext();
        var newTemplate = new ItemTemplate
        {
            TemplateKey = ItemTemplate.GenerateTemplateKey(),
            Name = "Created After Seeding",
            Description = "Must receive an ID past the seeded values"
        };
        context.ItemTemplates.Add(newTemplate);
        await context.SaveChangesAsync();

        Assert.Equal(21, newTemplate.Id);
    }

    [Fact]
    public async Task SeedAsync_AppliesRealSeedFiles_InsertingEveryRow_AndConvergesOnRerun()
    {
        // The production seed files ship with the repo at backend/seeds;
        // tests run from backend/tests/backend.tests/bin/<Config>/<tfm>.
        var seedsPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "seeds"));
        Assert.True(Directory.Exists(seedsPath), $"Expected seeds directory at {seedsPath}");
        var seeder = new JsonDatabaseSeeder(seedsPath);
        var expectedRowCounts = CountSeedFileRows(seedsPath);

        var firstRun = await seeder.SeedAsync(_fixture.ConnectionString);

        // Every row in every seed file must insert. A shortfall means the
        // check columns are ambiguous and rows were silently dropped.
        Assert.NotEmpty(firstRun);
        Assert.All(firstRun, r => Assert.Equal(expectedRowCounts[r.TableName], r.InsertedCount));

        // A re-run finds every row present and converges it to the file.
        var secondRun = await seeder.SeedAsync(_fixture.ConnectionString);

        Assert.All(secondRun, r => Assert.Equal(0, r.InsertedCount));
        Assert.All(secondRun, r => Assert.Equal(expectedRowCounts[r.TableName], r.UpdatedCount));

        // Identity sequences must be past the seeded IDs for application inserts
        await using var context = _fixture.CreateContext();
        var maxThemeId = await context.CollectionThemes.MaxAsync(t => t.Id);
        var newTheme = new CollectionTheme
        {
            Name = "Post-Seed Theme",
            Description = "Inserted after seeding",
            IconName = "star",
            SortOrder = 999
        };
        context.CollectionThemes.Add(newTheme);
        await context.SaveChangesAsync();

        Assert.True(newTheme.Id > maxThemeId,
            $"Expected new theme ID to exceed seeded max {maxThemeId}, got {newTheme.Id}");
    }

    private static Dictionary<string, int> CountSeedFileRows(string seedsPath)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        var counts = new Dictionary<string, int>();
        foreach (var file in Directory.GetFiles(seedsPath, "*.json").OrderBy(f => f))
        {
            var seedFile = JsonSerializer.Deserialize<SeedFile>(File.ReadAllText(file), options)!;
            foreach (var table in seedFile.Tables)
            {
                counts[table.Name] = counts.GetValueOrDefault(table.Name) + table.Rows.Count;
            }
        }
        return counts;
    }
}

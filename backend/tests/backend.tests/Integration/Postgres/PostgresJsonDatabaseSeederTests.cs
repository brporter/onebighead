using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Seeding;

namespace OneBigHead.Server.Tests.Integration.Postgres;

/// <summary>
/// Exercises JsonDatabaseSeeder against a real PostgreSQL database: actual
/// inserts, idempotent re-runs, parameter type inference for uuid/timestamptz
/// columns, and identity sequence resynchronization after explicit-ID inserts.
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
              "checkColumn": "Name",
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
        Assert.Equal(0, result.SkippedCount);

        await using var context = _fixture.CreateContext();
        var book = await context.ItemTemplates.SingleAsync(t => t.Id == 10);
        Assert.Equal("Integration Book", book.Name);
        Assert.Equal(Guid.Parse("a1b2c3d4-1111-4000-8000-00000000f001"), book.TemplateKey);
        Assert.Equal(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), book.CreatedAt);
    }

    [Fact]
    public async Task SeedAsync_SecondRun_SkipsExistingRows()
    {
        WriteSeedFile("01-templates.json", ItemTemplatesSeed);
        var seeder = new JsonDatabaseSeeder(_tempDir);
        await seeder.SeedAsync(_fixture.ConnectionString);

        var results = await seeder.SeedAsync(_fixture.ConnectionString);

        var result = Assert.Single(results);
        Assert.Equal(0, result.InsertedCount);
        Assert.Equal(2, result.SkippedCount);

        await using var context = _fixture.CreateContext();
        Assert.Equal(2, await context.ItemTemplates.CountAsync());
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
    public async Task SeedAsync_AppliesRealSeedFiles_AndIsIdempotent()
    {
        // The production seed files ship with the repo at backend/seeds;
        // tests run from backend/tests/backend.tests/bin/<Config>/<tfm>.
        var seedsPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "seeds"));
        Assert.True(Directory.Exists(seedsPath), $"Expected seeds directory at {seedsPath}");
        var seeder = new JsonDatabaseSeeder(seedsPath);

        var firstRun = await seeder.SeedAsync(_fixture.ConnectionString);

        Assert.NotEmpty(firstRun);
        Assert.All(firstRun, r => Assert.True(r.InsertedCount > 0, $"{r.TableName} inserted no rows"));

        // Every seed table declares check columns, so a re-run must skip everything
        var secondRun = await seeder.SeedAsync(_fixture.ConnectionString);

        Assert.All(secondRun, r => Assert.Equal(0, r.InsertedCount));
        Assert.All(secondRun, r => Assert.True(r.SkippedCount > 0, $"{r.TableName} skipped no rows"));

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
}

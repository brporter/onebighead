#if DEBUG
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Tests.Hosting;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class PostgresSeedCommandTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"seed-command-{Guid.NewGuid()}");

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(Path.Combine(_root, "seeds"));
        await fixture.ResetAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Program_SeedsRealDatabaseThenExits_UsingDefaultOrAbsolutePath(bool absolute)
    {
        var path = Path.Combine(_root, "seeds");
        await File.WriteAllTextAsync(Path.Combine(path, "templates.json"), """
            { "tables": [{ "name": "ItemTemplates", "checkColumn": "TemplateKey", "rows": [{
              "TemplateKey": "a1b2c3d4-1111-4000-8000-00000000f001", "Name": "Command template",
              "Description": "Seed command integration test", "CreatedAt": "2026-01-01T00:00:00Z",
              "UpdatedAt": "2026-01-01T00:00:00Z"
            }]}]}
            """);
        var arguments = new List<string>
        {
            "--seed", "--environment=Testing", $"--contentRoot={_root}",
            $"--ConnectionStrings:DefaultConnection={fixture.ConnectionString}"
        };
        if (absolute) arguments.Add($"--Seeding:Path={path}");

        Assert.Equal(0, await DevelopmentSeedCommandTests.RunProgramAsync(arguments.ToArray()));
        // The command converges on a second invocation instead of duplicating rows.
        Assert.Equal(0, await DevelopmentSeedCommandTests.RunProgramAsync(arguments.ToArray()));
        await using var context = fixture.CreateContext();
        Assert.Equal("Command template", (await context.ItemTemplates.SingleAsync()).Name);
    }

    public Task DisposeAsync()
    {
        Directory.Delete(_root, recursive: true);
        return Task.CompletedTask;
    }
}
#endif

using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

/// <summary>
/// Verifies the generated InitialCreate migration produces a working schema
/// on a real PostgreSQL server.
/// </summary>
[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class PostgresSchemaTests : IAsyncLifetime
{
    private readonly PostgresIntegrationFixture _fixture;

    public PostgresSchemaTests(PostgresIntegrationFixture fixture)
    {
        _fixture = fixture;
    }

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Migrations_ApplyCleanly_WithNonePending()
    {
        await using var context = _fixture.CreateContext();

        var pending = await context.Database.GetPendingMigrationsAsync();

        Assert.Empty(pending);
    }

    [Fact]
    public async Task IdentityColumns_GenerateSequentialIds()
    {
        await using var context = _fixture.CreateContext();
        var first = new Workspace { Name = "First" };
        var second = new Workspace { Name = "Second" };
        context.Workspaces.AddRange(first, second);

        await context.SaveChangesAsync();

        Assert.Equal(1, first.Id);
        Assert.Equal(2, second.Id);
    }

    [Fact]
    public async Task WorkspaceSlugIndex_AllowsMultipleNullSlugs()
    {
        await using var context = _fixture.CreateContext();
        context.Workspaces.AddRange(
            new Workspace { Name = "One" },
            new Workspace { Name = "Two" });

        await context.SaveChangesAsync();

        Assert.Equal(2, await context.Workspaces.CountAsync());
    }

    [Fact]
    public async Task WorkspaceSlugIndex_RejectsDuplicateSlugs()
    {
        await using (var context = _fixture.CreateContext())
        {
            context.Workspaces.Add(new Workspace { Name = "One", Slug = "shared" });
            await context.SaveChangesAsync();
        }

        await using (var context = _fixture.CreateContext())
        {
            context.Workspaces.Add(new Workspace { Name = "Two", Slug = "shared" });

            await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());
        }
    }
}

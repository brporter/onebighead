using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

/// <summary>
/// Pins down PostgreSQL provider behaviors that the InMemory-based test suite
/// cannot observe: foreign key enforcement of the Restrict delete rules, the
/// Npgsql requirement that timestamptz values have DateTimeKind.Utc, and
/// case-sensitive string comparison under PostgreSQL's default collation.
/// </summary>
[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class PostgresProviderBehaviorTests : IAsyncLifetime
{
    private readonly PostgresIntegrationFixture _fixture;

    public PostgresProviderBehaviorTests(PostgresIntegrationFixture fixture)
    {
        _fixture = fixture;
    }

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(int workspaceId, int collectionId)> CreateWorkspaceWithCollectionAsync()
    {
        await using var context = _fixture.CreateContext();
        var workspace = new Workspace { Name = "Test Workspace" };
        context.Workspaces.Add(workspace);
        await context.SaveChangesAsync();

        var collection = new Collection
        {
            WorkspaceId = workspace.Id,
            Name = "Test Collection",
            Slug = "test-collection"
        };
        context.Collections.Add(collection);
        await context.SaveChangesAsync();

        return (workspace.Id, collection.Id);
    }

    [Fact]
    public async Task RestrictForeignKey_BlocksCollectionDelete_WhileItemsExist()
    {
        var (workspaceId, collectionId) = await CreateWorkspaceWithCollectionAsync();
        await using (var context = _fixture.CreateContext())
        {
            context.Items.Add(new Item
            {
                WorkspaceId = workspaceId,
                CollectionId = collectionId,
                Name = "Blocking Item"
            });
            await context.SaveChangesAsync();
        }

        // Delete only the collection - the Restrict FK from Items must block it
        await using (var context = _fixture.CreateContext())
        {
            var collection = await context.Collections.SingleAsync(c => c.Id == collectionId);
            context.Collections.Remove(collection);

            await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());
        }
    }

    [Fact]
    public async Task RestrictForeignKey_AllowsCollectionDelete_AfterItemsRemoved()
    {
        var (workspaceId, collectionId) = await CreateWorkspaceWithCollectionAsync();
        await using (var context = _fixture.CreateContext())
        {
            context.Items.Add(new Item
            {
                WorkspaceId = workspaceId,
                CollectionId = collectionId,
                Name = "Removable Item"
            });
            await context.SaveChangesAsync();
        }

        // Mirror CollectionRepository.DeleteAsync: remove items, then the collection
        await using (var context = _fixture.CreateContext())
        {
            var items = await context.Items.Where(i => i.CollectionId == collectionId).ToListAsync();
            context.Items.RemoveRange(items);
            var collection = await context.Collections.SingleAsync(c => c.Id == collectionId);
            context.Collections.Remove(collection);
            await context.SaveChangesAsync();
        }

        await using (var context = _fixture.CreateContext())
        {
            Assert.False(await context.Collections.AnyAsync(c => c.Id == collectionId));
            Assert.False(await context.Items.AnyAsync(i => i.CollectionId == collectionId));
        }
    }

    [Fact]
    public async Task Timestamptz_AcceptsUtcDateTimes_AndRoundTripsAsUtc()
    {
        var createdAt = new DateTime(2026, 7, 12, 8, 30, 0, DateTimeKind.Utc);
        await using (var context = _fixture.CreateContext())
        {
            context.Workspaces.Add(new Workspace { Name = "UTC Workspace", CreatedAt = createdAt });
            await context.SaveChangesAsync();
        }

        await using (var context = _fixture.CreateContext())
        {
            var workspace = await context.Workspaces.SingleAsync(w => w.Name == "UTC Workspace");

            Assert.Equal(createdAt, workspace.CreatedAt);
            Assert.Equal(DateTimeKind.Utc, workspace.CreatedAt.Kind);
        }
    }

    [Fact]
    public async Task Timestamptz_RejectsUnspecifiedKindDateTimes()
    {
        await using var context = _fixture.CreateContext();
        context.Workspaces.Add(new Workspace
        {
            Name = "Unspecified Workspace",
            CreatedAt = new DateTime(2026, 7, 12, 8, 30, 0, DateTimeKind.Unspecified)
        });

        // Npgsql refuses non-UTC DateTimes for timestamptz columns; any value
        // deserialized without an explicit UTC marker will fail like this.
        var exception = await Record.ExceptionAsync(() => context.SaveChangesAsync());

        Assert.NotNull(exception);
    }

    [Fact]
    public async Task EmailEquality_IsCaseSensitive_UnderDefaultCollation()
    {
        await using var context = _fixture.CreateContext();
        var workspace = new Workspace { Name = "Email Workspace" };
        context.Workspaces.Add(workspace);
        await context.SaveChangesAsync();
        context.Users.Add(new User
        {
            ActiveWorkspaceId = workspace.Id,
            Email = "user@example.com"
        });
        await context.SaveChangesAsync();

        // Unlike SQL Server's default case-insensitive collation, PostgreSQL
        // compares strings case-sensitively. Lookups must use the same
        // normalized (lowercase) form that AuthController writes.
        var exactMatch = await context.Users.FirstOrDefaultAsync(u => u.Email == "user@example.com");
        var differentCase = await context.Users.FirstOrDefaultAsync(u => u.Email == "User@Example.com");

        Assert.NotNull(exactMatch);
        Assert.Null(differentCase);
    }
}

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class CollectionSetupServiceTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private CollectionSetupService CreateService() => new(fixture.CreateContextFactory(),
        new WorkspaceStatisticsRepository(fixture.CreateContextFactory()), NullLogger<CollectionSetupService>.Instance);

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Existing" });
        context.Users.Add(new User { Id = 1, ActiveWorkspaceId = 1, Email = "user@example.com" });
        context.ItemTemplates.Add(new ItemTemplate { Id = 1, Name = "Template", TemplateKey = Guid.NewGuid() });
        await context.SaveChangesAsync();
        // Explicit seed IDs do not advance PostgreSQL identity sequences.
        await context.Database.ExecuteSqlRawAsync("ALTER SEQUENCE \"Workspaces_Id_seq\" RESTART WITH 2");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task CreateAsync_CreatesPrivateCollectionAndSystemCategory_WithUniqueSlug()
    {
        var service = CreateService();
        var first = await service.CreateAsync(new Collection { WorkspaceId = 1, Name = "Books", Visibility = Visibility.Public }, null);
        var second = await service.CreateAsync(new Collection { WorkspaceId = 1, Name = "Books" }, null);
        Assert.Equal("books", first.Slug);
        Assert.StartsWith("books-", second.Slug);
        Assert.Equal(Visibility.Private, first.Visibility);
        Assert.True(Assert.Single(first.Categories).IsSystem);
        var stats = await new WorkspaceStatisticsRepository(fixture.CreateContextFactory()).GetAggregatesAsync(1);
        Assert.Equal(2, stats[StatisticType.CollectionCount]);
    }

    private static CollectionTheme Theme() => new()
    {
        Name = "Theme",
        ThemeTemplates = [new() { ItemTemplateId = 1 }, new() { ItemTemplateId = 1 }, new() { ItemTemplateId = 0 }],
        ThemeCategories = [
            new() { Name = "Grandchild", ParentName = "Child", SortOrder = 0 },
            new() { Name = "Child", ParentName = "Root", SortOrder = 1 },
            new() { Name = "Root", SortOrder = 2 },
            new() { Name = "Case variant", ParentName = "root" },
            new() { Name = "Empty parent", ParentName = "" },
            new() { Name = "Orphan", ParentName = "Missing" },
            new() { Name = "Cycle", ParentName = "Cycle" }]
    };

    [Fact]
    public async Task CreateAsync_AppliesDistinctTemplatesAndNestedCategories_UsingExactParentNames()
    {
        var collection = await CreateService().CreateAsync(new Collection { WorkspaceId = 1, Name = "Books" }, Theme());
        await using var context = fixture.CreateContext();
        Assert.Single(await context.CollectionItemTemplates.ToListAsync());
        var categories = await context.Categories.ToDictionaryAsync(c => c.Name);
        Assert.Equal(4, categories.Count);
        Assert.Equal(categories["Root"].Id, categories["Child"].ParentCategoryId);
        Assert.Equal(categories["Child"].Id, categories["Grandchild"].ParentCategoryId);
        Assert.All(categories.Values, c => Assert.Equal(collection.Id, c.CollectionId));
    }

    [Fact]
    public async Task SetupWorkspaceAsync_CommitsMembershipActiveWorkspaceAndThemeTogether()
    {
        var workspace = new Workspace { Name = "New", HasCompletedWelcome = true };
        var collection = await CreateService().SetupWorkspaceAsync(1, workspace, new Collection { Name = "Books" }, Theme());
        await using var context = fixture.CreateContext();
        Assert.Equal(workspace.Id, (await context.Users.SingleAsync()).ActiveWorkspaceId);
        var membership = await context.WorkspaceUsers.SingleAsync();
        Assert.Equal(workspace.Id, membership.WorkspaceId);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, membership.WorkspaceRole);
        var categories = await context.Categories.ToDictionaryAsync(c => c.Name);
        Assert.Equal(6, categories.Count);
        Assert.Equal(categories["Root"].Id, categories["Case variant"].ParentCategoryId);
        Assert.Null(categories["Empty parent"].ParentCategoryId);
        Assert.All(categories.Values, c => Assert.Equal(workspace.Id, c.WorkspaceId));
        Assert.Equal(workspace.Id, collection.WorkspaceId);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidTemplate_RollsBackEntireSetup(bool newWorkspace)
    {
        var theme = new CollectionTheme { Name = "Invalid", ThemeTemplates = [new() { ItemTemplateId = 999 }] };
        var collection = new Collection { WorkspaceId = 1, Name = "Books" };
        var service = CreateService();
        await Assert.ThrowsAsync<DbUpdateException>(() => newWorkspace
            ? service.SetupWorkspaceAsync(1, new Workspace { Name = "New" }, collection, theme)
            : service.CreateAsync(collection, theme));
        await using var context = fixture.CreateContext();
        Assert.Empty(await context.Collections.ToListAsync());
        Assert.Empty(await context.Categories.ToListAsync());
        Assert.Empty(await context.WorkspaceUsers.ToListAsync());
        Assert.Single(await context.Workspaces.ToListAsync());
        Assert.Equal(1, (await context.Users.SingleAsync()).ActiveWorkspaceId);
    }
}

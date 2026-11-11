using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Collections;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class CollectionSetupServiceTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private CollectionSetupService CreateService(IWorkspaceStatisticsWriter? writer = null) =>
        new(fixture.CreateContextFactory(), writer ?? new WorkspaceStatisticsWriter());
    private WorkspaceStatisticsRepository Statistics()
    {
        var writer = new WorkspaceStatisticsWriter();
        return new(fixture.CreateContextFactory(), writer, writer);
    }

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Existing" });
        context.Users.Add(new User { Id = 1, ActiveWorkspaceId = 1, Email = "user@example.com" });
        context.ItemTemplates.AddRange(
            new ItemTemplate { Id = 1, Name = "System", TemplateKey = Guid.NewGuid() },
            new ItemTemplate { Id = 2, WorkspaceId = 1, Name = "Workspace owned", TemplateKey = Guid.NewGuid() });
        await context.SaveChangesAsync();
        await context.Database.ExecuteSqlRawAsync("ALTER SEQUENCE \"Workspaces_Id_seq\" RESTART WITH 2");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData("Books")]
    [InlineData("Long")]
    public async Task CreateAsync_CreatesPrivateCollectionsAndBoundedUniqueSlugs(string name)
    {
        if (name == "Long") name = new string('a', 99) + " " + new string('b', 100);
        var service = CreateService();
        var first = await service.CreateAsync(new Collection { WorkspaceId = 1, Name = name, Visibility = Visibility.Public }, null);
        var second = await service.CreateAsync(new Collection { WorkspaceId = 1, Name = name }, null);
        Assert.InRange(first.Slug.Length, 1, 100);
        Assert.InRange(second.Slug.Length, 1, 100);
        Assert.NotEqual(first.Slug, second.Slug);
        Assert.False(first.Slug.EndsWith('-'));
        Assert.Equal(Visibility.Private, first.Visibility);
        Assert.True(Assert.Single(first.Categories).IsSystem);
        Assert.Equal(2, (await Statistics().GetAggregatesAsync(1))[StatisticType.CollectionCount]);
    }

    private static CollectionTheme Theme() => new()
    {
        Name = "Theme",
        ThemeTemplates = [new() { ItemTemplateId = 1 }, new() { ItemTemplateId = 1 }, new() { ItemTemplateId = 0 }],
        ThemeCategories = [
            new() { Name = "Grandchild", ParentName = "Child", SortOrder = 0 },
            new() { Name = " Child ", ParentName = " Root ", Description = "Child description", SortOrder = 1 },
            new() { Name = "Root", SortOrder = 7 },
            new() { Name = "Empty parent", ParentName = "  ", SortOrder = 12 }]
    };

    [Fact]
    public async Task Create_PreservesTheThemeGraphAndCommitsItsCount()
    {
        var collection = new Collection { WorkspaceId = 1, Name = "Books" };
        await CreateService().CreateAsync(collection, Theme());
        await using var context = fixture.CreateContext();
        Assert.Single(await context.CollectionItemTemplates.ToListAsync());
        var categories = await context.Categories.ToDictionaryAsync(c => c.Name);
        Assert.Equal(5, categories.Count);
        Assert.Equal(categories["Root"].Id, categories["Child"].ParentCategoryId);
        Assert.Equal(categories["Child"].Id, categories["Grandchild"].ParentCategoryId);
        Assert.Null(categories["Empty parent"].ParentCategoryId);
        Assert.Equal(7, categories["Root"].SortOrder);
        Assert.Equal(1, categories["Child"].SortOrder);
        Assert.Equal("Child description", categories["Child"].Description);
        Assert.All(categories.Values, c => { Assert.Equal(collection.Id, c.CollectionId); Assert.Equal(collection.WorkspaceId, c.WorkspaceId); });
        Assert.Equal(1, (await Statistics().GetAggregatesAsync(collection.WorkspaceId))[StatisticType.CollectionCount]);
        Assert.Empty(await context.WorkspaceUsers.ToListAsync());
    }

    [Theory]
    [InlineData("case")]
    [InlineData("missing")]
    [InlineData("cycle")]
    [InlineData("duplicate")]
    public async Task InvalidHierarchy_RejectsTheWholeThemeBeforeSaving(string error)
    {
        var theme = Theme();
        theme.ThemeCategories.Add(new CollectionThemeCategory
        { Name = error == "duplicate" ? "Root" : "Invalid", ParentName = error == "case" ? "root" : error == "cycle" ? "Invalid" : "Missing" });
        await Assert.ThrowsAsync<InvalidCollectionThemeException>(() => CreateService().CreateAsync(new Collection { WorkspaceId = 1, Name = "Books" }, theme));
        await AssertNothingCreated();
    }

    [Fact]
    public async Task UnavailableTemplate_RejectsSetupWithoutChangingTheUser()
    {
        var theme = new CollectionTheme { ThemeTemplates = [new() { ItemTemplateId = 999 }] };
        await Assert.ThrowsAsync<InvalidCollectionThemeException>(() => CreateService().CreateAsync(new Collection { WorkspaceId = 1, Name = "Books" }, theme));
        await AssertNothingCreated();
    }

    [Fact]
    public async Task ExistingWorkspace_CanUseItsOwnTemplate_WithoutBorrowingItFromAnotherWorkspace()
    {
        var theme = new CollectionTheme { ThemeTemplates = [new() { ItemTemplateId = 2 }] };
        await CreateService().CreateAsync(new Collection { WorkspaceId = 1, Name = "Owned" }, theme);
        await using var context = fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 3, Name = "Other" });
        await context.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidCollectionThemeException>(() => CreateService().CreateAsync(new Collection { WorkspaceId = 3, Name = "Foreign" }, theme));
        Assert.Single(await context.Collections.ToListAsync());
        Assert.Equal(2, (await context.CollectionItemTemplates.SingleAsync()).ItemTemplateId);
        Assert.Empty(await Statistics().GetAggregatesAsync(3));
    }

    [Fact]
    public async Task StatisticsFailure_RollsBackAlreadySavedGraph()
    {
        await using var context = fixture.CreateContext();
        await context.Database.ExecuteSqlRawAsync("ALTER TABLE \"WorkspaceStatistics\" ADD CONSTRAINT \"SetupCountFailure\" CHECK (\"Value\" < 1)");
        try
        {
            var observed = new ObserveSavedGraph();
            var service = CreateService(observed);
            var collection = new Collection { WorkspaceId = 1, Name = "Books" };
            var error = await Assert.ThrowsAsync<PostgresException>(() => service.CreateAsync(collection, Theme()));
            Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
            Assert.True(observed.SawSavedGraph);
            await AssertNothingCreated();
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("ALTER TABLE \"WorkspaceStatistics\" DROP CONSTRAINT \"SetupCountFailure\"");
        }
    }

    [Fact]
    public async Task ConcurrentCollections_CommitEveryGraphAndIncrementWithoutLostUpdates()
    {
        await Task.WhenAll(Enumerable.Range(0, 12).Select(index =>
            CreateService().CreateAsync(new Collection { WorkspaceId = 1, Name = $"Collection {index}" }, Theme())));
        await using var context = fixture.CreateContext();
        Assert.Equal(12, await context.Collections.CountAsync());
        Assert.Equal(60, await context.Categories.CountAsync());
        Assert.Equal(12, (await Statistics().GetAggregatesAsync(1))[StatisticType.CollectionCount]);
    }

    private async Task AssertNothingCreated()
    {
        await using var context = fixture.CreateContext();
        Assert.Empty(await context.Collections.ToListAsync());
        Assert.Empty(await context.Categories.ToListAsync());
        Assert.Empty(await context.CollectionItemTemplates.ToListAsync());
        Assert.Empty(await context.WorkspaceUsers.ToListAsync());
        Assert.Empty(await context.WorkspaceStatistics.ToListAsync());
        Assert.Single(await context.Workspaces.ToListAsync());
        Assert.Equal(1, (await context.Users.SingleAsync()).ActiveWorkspaceId);
    }

    private sealed class ObserveSavedGraph : IWorkspaceStatisticsWriter
    {
        public bool SawSavedGraph { get; private set; }
        public async Task IncrementAsync(AppDbContext context, int workspaceId, StatisticType type, long amount = 1, DateOnly? date = null)
        {
            Assert.NotNull(context.Database.CurrentTransaction);
            Assert.Equal(1, await context.Collections.AsNoTracking().CountAsync());
            Assert.Equal(5, await context.Categories.AsNoTracking().CountAsync());
            Assert.Equal(1, await context.CollectionItemTemplates.AsNoTracking().CountAsync());
            SawSavedGraph = true;
            await new WorkspaceStatisticsWriter().IncrementAsync(context, workspaceId, type, amount, date);
        }
    }
}

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Administration;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class AdministratorWorkspaceDeletionTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private AdministratorWorkspaceDeletion Commands() => new(fixture.CreateContextFactory());
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.AddRange(new Workspace { Id = 1, Name = "Remove" }, new Workspace { Id = 2, Name = "Keep" },
            new Workspace { Id = 3, Name = "Deleted alternative", IsDeleted = true }, new Workspace { Id = 4, Name = "Later alternative" });
        context.Users.AddRange(new User { Id = 1, ActiveWorkspaceId = 1, Email = "only@example.test" },
            new User { Id = 2, ActiveWorkspaceId = 1, Email = "several@example.test" },
            new User { Id = 3, ActiveWorkspaceId = 2, Email = "unaffected@example.test" });
        context.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 1 },
            new WorkspaceUser { UserId = 1, WorkspaceId = 3 }, new WorkspaceUser { UserId = 2, WorkspaceId = 1 },
            new WorkspaceUser { UserId = 2, WorkspaceId = 4 }, new WorkspaceUser { UserId = 2, WorkspaceId = 2 },
            new WorkspaceUser { UserId = 3, WorkspaceId = 2 });
        context.Collections.AddRange(new OneBigHead.Server.Models.Collection { Id = 1, WorkspaceId = 1, Name = "Remove" },
            new OneBigHead.Server.Models.Collection { Id = 2, WorkspaceId = 2, Name = "Keep" });
        context.Categories.AddRange(new Category { Id = 1, WorkspaceId = 1, CollectionId = 1, Name = "Parent" },
            new Category { Id = 2, WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Name = "Child" },
            new Category { Id = 3, WorkspaceId = 2, CollectionId = 2, Name = "Keep" });
        context.Items.AddRange(new Item { Id = 1, WorkspaceId = 1, CollectionId = 1, CategoryId = 2, Name = "Remove" },
            new Item { Id = 2, WorkspaceId = 2, CollectionId = 2, CategoryId = 3, Name = "Keep" });
        context.ItemTemplates.AddRange(new ItemTemplate { Id = 1, WorkspaceId = 1, Name = "Owned", TemplateKey = Guid.NewGuid(),
                Properties = [new ItemTemplateProperty { Category = "Details", Name = "Title" }] },
            new ItemTemplate { Id = 2, WorkspaceId = 2, Name = "Keep", TemplateKey = Guid.NewGuid() },
            new ItemTemplate { Id = 3, Name = "Shared", TemplateKey = Guid.NewGuid() });
        context.CollectionItemTemplates.AddRange(new CollectionItemTemplate { CollectionId = 1, ItemTemplateId = 1 },
            new CollectionItemTemplate { CollectionId = 1, ItemTemplateId = 3 }, new CollectionItemTemplate { CollectionId = 2, ItemTemplateId = 3 });
        context.CategoryItemTemplates.Add(new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 1 });
        context.PropertySuggestions.AddRange(new PropertySuggestion { WorkspaceId = 1, CollectionId = 1, Value = "Remove" },
            new PropertySuggestion { WorkspaceId = 2, CollectionId = 2, Value = "Keep" });
        context.StoredImages.AddRange(new StoredImage { Id = Guid.NewGuid(), WorkspaceId = 1 }, new StoredImage { Id = Guid.NewGuid(), WorkspaceId = 2 });
        context.WorkspaceStatistics.AddRange(new WorkspaceStatistic { WorkspaceId = 1, Value = 10 }, new WorkspaceStatistic { WorkspaceId = 2, Value = 20 });
        context.CollectionStatistics.AddRange(new CollectionStatistic { CollectionId = 1, Value = 10 }, new CollectionStatistic { CollectionId = 2, Value = 20 });
        context.CollectionItemHighlights.AddRange(new CollectionItemHighlight { CollectionId = 1, ItemId = 1 }, new CollectionItemHighlight { CollectionId = 2, ItemId = 2 });
        context.ContentScanLogs.Add(new ContentScanLog { Id = Guid.NewGuid(), WorkspaceId = 1, UserId = 1, ScannedAt = DateTime.UtcNow });
        context.SupportRequests.Add(new SupportRequest { Id = 1, UserId = 1, Email = "only@example.test", Subject = "Keep", Description = "History" });
        await context.SaveChangesAsync();
    }
    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData("active")]
    [InlineData("soft-deleted")]
    [InlineData("cyclic categories")]
    public async Task Deletion_RemovesTheFullOwnedGraph_AndPreservesAccountsAndOtherWorkspaces(string state)
    {
        await using (var context = fixture.CreateContext())
        {
            if (state == "soft-deleted") (await context.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted = true;
            if (state == "cyclic categories") (await context.Categories.SingleAsync(c => c.Id == 1)).ParentCategoryId = 2;
            await context.SaveChangesAsync();
        }
        Assert.Equal(AdministratorWorkspaceDeletionResult.Deleted, await Commands().DeleteAsync(1));
        await using var check = fixture.CreateContext();
        Assert.False(await check.Workspaces.AnyAsync(w => w.Id == 1));
        Assert.Equal(2, (await check.Collections.SingleAsync()).Id);
        Assert.Equal(3, (await check.Categories.SingleAsync()).Id);
        Assert.Equal(2, (await check.Items.SingleAsync()).Id);
        Assert.Equal(new[] { 2, 3 }, await check.ItemTemplates.OrderBy(t => t.Id).Select(t => t.Id).ToArrayAsync());
        Assert.Empty(await check.ItemTemplateProperties.ToListAsync());
        Assert.Equal(2, (await check.CollectionItemTemplates.SingleAsync()).CollectionId);
        Assert.Empty(await check.CategoryItemTemplates.ToListAsync());
        Assert.Equal(2, (await check.PropertySuggestions.SingleAsync()).WorkspaceId);
        Assert.Equal(2, (await check.StoredImages.SingleAsync()).WorkspaceId);
        Assert.Equal(2, (await check.WorkspaceStatistics.SingleAsync()).WorkspaceId);
        Assert.Equal(2, (await check.CollectionStatistics.SingleAsync()).CollectionId);
        Assert.Equal(2, (await check.CollectionItemHighlights.SingleAsync()).ItemId);
        Assert.False(await check.WorkspaceUsers.AnyAsync(m => m.WorkspaceId == 1));
        var users = await check.Users.OrderBy(u => u.Id).ToListAsync();
        Assert.Equal(new int?[] { null, 2, 2 }, users.Select(u => u.ActiveWorkspaceId));
        Assert.All(users, u => Assert.False(u.IsDeleted));
        Assert.Equal(1, (await check.SupportRequests.SingleAsync()).UserId);
        Assert.Equal(1, (await check.ContentScanLogs.SingleAsync()).WorkspaceId);
        Assert.Equal(AdministratorWorkspaceDeletionResult.NotFound, await Commands().DeleteAsync(1));
    }

    [Fact]
    public async Task EmptyWorkspace_CanBeDeleted_AndMissingWorkspaceDoesNotChangeData()
    {
        Assert.Equal(AdministratorWorkspaceDeletionResult.NotFound, await Commands().DeleteAsync(999));
        await using var context = fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 5, Name = "Empty" });
        await context.SaveChangesAsync();
        Assert.Equal(AdministratorWorkspaceDeletionResult.Deleted, await Commands().DeleteAsync(5));
        Assert.Equal(4, await context.Workspaces.CountAsync());
        Assert.Equal(2, await context.Items.CountAsync());
    }

    [Fact]
    public async Task ConcurrentDeletions_CommitOnceAndReportTheLosingSnapshotAsAConflict()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString)
            .AddInterceptors(new BothLoaded()).Options;
        var commands = new AdministratorWorkspaceDeletion(new TestDbContextFactory(options));
        var results = await Task.WhenAll(commands.DeleteAsync(1), commands.DeleteAsync(1)).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Contains(AdministratorWorkspaceDeletionResult.Deleted, results);
        Assert.Contains(AdministratorWorkspaceDeletionResult.ConcurrentChange, results);
        await using var check = fixture.CreateContext();
        Assert.False(await check.Workspaces.AnyAsync(w => w.Id == 1));
        Assert.Null((await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        Assert.Equal(2, (await check.Users.SingleAsync(u => u.Id == 2)).ActiveWorkspaceId);
        Assert.Equal(2, (await check.Items.SingleAsync()).Id);
    }

    private sealed class BothLoaded : SaveChangesInterceptor
    {
        private readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int arrived;
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref arrived) == 2) ready.SetResult();
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            return result;
        }
    }

    [Theory]
    [InlineData("category collection")]
    [InlineData("category parent")]
    [InlineData("item collection")]
    [InlineData("item category")]
    [InlineData("suggestion")]
    [InlineData("collection template")]
    [InlineData("category template")]
    [InlineData("shared theme")]
    [InlineData("highlight")]
    public async Task ForeignReferences_RejectDeletionWithoutChangingAnyData(string relationship)
    {
        await using var context = fixture.CreateContext();
        switch (relationship)
        {
            case "category collection": (await context.Categories.SingleAsync(c => c.Id == 3)).CollectionId = 1; break;
            case "category parent": (await context.Categories.SingleAsync(c => c.Id == 3)).ParentCategoryId = 1; break;
            case "item collection": (await context.Items.SingleAsync(i => i.Id == 2)).CollectionId = 1; break;
            case "item category": (await context.Items.SingleAsync(i => i.Id == 2)).CategoryId = 1; break;
            case "suggestion": (await context.PropertySuggestions.SingleAsync(p => p.WorkspaceId == 2)).CollectionId = 1; break;
            case "collection template": context.CollectionItemTemplates.Add(new CollectionItemTemplate { CollectionId = 2, ItemTemplateId = 1 }); break;
            case "category template": context.CategoryItemTemplates.Add(new CategoryItemTemplate { CategoryId = 3, ItemTemplateId = 1 }); break;
            case "shared theme": context.CollectionThemes.Add(new CollectionTheme { Id = 1, Name = "Shared", ThemeTemplates = [new CollectionThemeTemplate { ItemTemplateId = 1 }] }); break;
            case "highlight": context.CollectionItemHighlights.Add(new CollectionItemHighlight { CollectionId = 2, ItemId = 1 }); break;
        }
        await context.SaveChangesAsync();
        Assert.Equal(AdministratorWorkspaceDeletionResult.ConflictingReferences, await Commands().DeleteAsync(1));
        Assert.Equal(4, await context.Workspaces.CountAsync());
        Assert.Equal(2, await context.Items.CountAsync());
        Assert.Equal(1, (await context.Users.AsNoTracking().SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        Assert.Equal(1, (await context.Categories.AsNoTracking().SingleAsync(c => c.Id == 2)).ParentCategoryId);
    }

    [Fact]
    public async Task FailureAfterDeletion_RollsBackTheGraphAndActiveWorkspaceAssignments()
    {
        await using var context = fixture.CreateContext();
        await context.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION reject_workspace_deletion() RETURNS trigger AS $$
            BEGIN
                IF EXISTS (SELECT 1 FROM "Items" WHERE "WorkspaceId" = OLD."Id")
                    OR EXISTS (SELECT 1 FROM "Users" WHERE "ActiveWorkspaceId" = OLD."Id") THEN
                    RAISE EXCEPTION 'Expected dependent changes before failure';
                END IF;
                RAISE EXCEPTION 'Failure after dependent changes' USING ERRCODE = '23514';
            END; $$ LANGUAGE plpgsql
            """);
        await context.Database.ExecuteSqlRawAsync("CREATE TRIGGER z_reject_workspace_deletion AFTER DELETE ON \"Workspaces\" FOR EACH ROW EXECUTE FUNCTION reject_workspace_deletion()");
        try
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => Commands().DeleteAsync(1));
            Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
            Assert.Equal("Failure after dependent changes", error.MessageText);
            Assert.Equal(2, await context.Items.CountAsync());
            Assert.Equal(3, await context.Categories.CountAsync());
            Assert.Equal(1, (await context.Categories.SingleAsync(c => c.Id == 2)).ParentCategoryId);
            Assert.Equal(1, (await context.Users.SingleAsync(u => u.Id == 2)).ActiveWorkspaceId);
            Assert.Equal(2, await context.WorkspaceUsers.CountAsync(m => m.WorkspaceId == 1));
            Assert.True(await context.Workspaces.AnyAsync(w => w.Id == 1));
            Assert.True(await context.ItemTemplates.AnyAsync(t => t.Id == 1));
            Assert.Equal(2, await context.WorkspaceStatistics.CountAsync());
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("DROP TRIGGER z_reject_workspace_deletion ON \"Workspaces\"");
            await context.Database.ExecuteSqlRawAsync("DROP FUNCTION reject_workspace_deletion()");
        }
    }
}

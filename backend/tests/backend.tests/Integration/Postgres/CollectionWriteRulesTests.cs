using System.Text.Json;
using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Collections;

namespace OneBigHead.Server.Tests.Integration.Postgres;

public partial class CollectionWriteTests
{
    [Theory]
    [InlineData(WorkspaceRole.WorkspaceAdmin, WorkspaceRole.WorkspaceAdmin, HttpStatusCode.NoContent)]
    [InlineData(WorkspaceRole.Normal, WorkspaceRole.Normal, HttpStatusCode.Forbidden)]
    [InlineData(WorkspaceRole.Normal, WorkspaceRole.WorkspaceAdmin, HttpStatusCode.Forbidden)]
    public async Task HttpDeletion_RequiresAdministratorClaimsAndCurrentMembership(WorkspaceRole currentRole, WorkspaceRole claimedRole, HttpStatusCode expected)
    {
        await using (var db = fixture.CreateContext())
        {
            (await db.WorkspaceUsers.SingleAsync()).WorkspaceRole = currentRole;
            await db.SaveChangesAsync();
        }
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = Authenticate(app.CreateClient());
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, claimedRole.ToString());
        using var response = await client.DeleteAsync("/api/collections/1");
        Assert.Equal(expected, response.StatusCode);
        await using var check = fixture.CreateContext();
        Assert.Equal(expected == HttpStatusCode.NoContent ? 1 : 2, await check.Collections.CountAsync());
    }

    [Theory]
    [InlineData("missing-user")] [InlineData("deleted-user")] [InlineData("no-membership")]
    [InlineData("deleted-workspace")] [InlineData("missing-collection")] [InlineData("foreign-collection")]
    public async Task UnavailableAccess_RejectsMetadataAndDeletionWithoutWriting(string state)
    {
        await using (var db = fixture.CreateContext())
        {
            if (state == "deleted-user") (await db.Users.SingleAsync()).IsDeleted = true;
            if (state == "deleted-workspace") (await db.Workspaces.SingleAsync()).IsDeleted = true;
            if (state == "no-membership") db.WorkspaceUsers.Remove(await db.WorkspaceUsers.SingleAsync());
            if (state == "foreign-collection")
            {
                db.Workspaces.Add(new Workspace { Id = 2, Name = "Other" });
                db.Collections.Add(new Collection { Id = 3, WorkspaceId = 2, Name = "Foreign", Slug = "foreign" });
            }
            await db.SaveChangesAsync();
        }
        var before = await Snapshot();
        var userId = state == "missing-user" ? 999 : 1;
        var collectionId = state == "missing-collection" ? 999 : state == "foreign-collection" ? 3 : 1;
        Assert.Equal(CollectionWriteStatus.NotFound, (await Details().UpdateAsync(userId, 1, collectionId, new() { Name = "Edited" }, CancellationToken.None)).Status);
        Assert.Equal(CollectionWriteStatus.NotFound, (await Deletion().DeleteAsync(userId, 1, collectionId, CancellationToken.None)).Status);
        Assert.Equal(before, await Snapshot());
    }

    [Fact]
    public async Task NormalMembers_CanEditMetadataButCannotDeleteCollections()
    {
        await using (var db = fixture.CreateContext())
        {
            (await db.WorkspaceUsers.SingleAsync()).WorkspaceRole = WorkspaceRole.Normal;
            (await db.Collections.SingleAsync(c => c.Id == 1)).Slug = "stable-url";
            await db.SaveChangesAsync();
        }
        var result = await Details().UpdateAsync(1, 1, 1, new() { Name = " First ", Description = "Updated", HeroImageUrl = "/photo" }, CancellationToken.None);
        Assert.Equal(CollectionWriteStatus.Success, result.Status);
        Assert.Equal("stable-url", result.Collection!.Slug);
        Assert.Equal("First", result.Collection.Name);
        Assert.Equal("Updated", result.Collection.Description);
        Assert.Equal("/photo", result.Collection.HeroImageUrl);
        Assert.Equal(Visibility.Public, result.Collection.Visibility);
        var before = await Snapshot();
        Assert.Equal(CollectionWriteStatus.Forbidden, (await Deletion().DeleteAsync(1, 1, 1, CancellationToken.None)).Status);
        Assert.Equal(before, await Snapshot());
    }

    [Theory]
    [InlineData("name")] [InlineData("description")] [InlineData("image")]
    public async Task InvalidMetadata_IsRejectedWithoutWriting(string field)
    {
        var request = new UpdateCollectionRequest { Name = "Edited" };
        if (field == "name") request.Name = " ";
        if (field == "description") request.Description = new string('x', 1001);
        if (field == "image") request.HeroImageUrl = new string('x', 501);
        var before = await Snapshot();
        Assert.Equal(CollectionWriteStatus.Invalid, (await Details().UpdateAsync(1, 1, 1, request, CancellationToken.None)).Status);
        Assert.Equal(before, await Snapshot());
    }

    [Theory]
    [InlineData("Second", "second-")]
    [InlineData("收藏", "collection")]
    public async Task Slugs_HandleCollisionsAndNonLatinNamesAndRemainStableOnLaterEdits(string name, string prefix)
    {
        var result = await Details().UpdateAsync(1, 1, 1, new() { Name = name }, CancellationToken.None);
        Assert.Equal(CollectionWriteStatus.Success, result.Status);
        Assert.StartsWith(prefix, result.Collection!.Slug);
        Assert.InRange(result.Collection.Slug.Length, 1, 100);
        Assert.Equal("", result.Collection.Description);
        var edited = await Details().UpdateAsync(1, 1, 1, new() { Name = name, Description = "Details" }, CancellationToken.None);
        Assert.Equal(result.Collection.Slug, edited.Collection!.Slug);
    }

    [Fact]
    public async Task CompetingRenames_CommitOneUniqueSlugAndReturnAConflict()
    {
        var details = Details(new SynchronizedSaves());
        var results = await Task.WhenAll(details.UpdateAsync(1, 1, 1, new() { Name = "Shared name" }, CancellationToken.None),
            details.UpdateAsync(1, 1, 2, new() { Name = "Shared name" }, CancellationToken.None)).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Contains(results, result => result.Status == CollectionWriteStatus.Success);
        Assert.Contains(results, result => result.Status == CollectionWriteStatus.Conflict);
        await using var db = fixture.CreateContext();
        Assert.Equal(1, await db.Collections.CountAsync(c => c.Slug == "shared-name"));
    }

    [Theory]
    [InlineData("40001", null, true)]
    [InlineData("23505", "IX_Collections_WorkspaceId_Slug", true)]
    [InlineData("23505", "another_constraint", false)]
    [InlineData("23514", null, false)]
    [InlineData(null, null, false)]
    public async Task Metadata_ClassifiesOnlyKnownConcurrencyFailures(string? state, string? constraint, bool conflict)
    {
        Exception failure = state is null ? new InvalidOperationException("Storage unavailable") :
            new DbUpdateException("Write failed", new PostgresException("Storage error", "ERROR", "ERROR", state, constraintName: constraint));
        var details = Details(new BeforeMembershipSave(() => Task.FromException(failure)));
        var before = await Snapshot();
        var action = () => details.UpdateAsync(1, 1, 1, new() { Name = "Edited" }, CancellationToken.None);
        if (conflict)
        {
            var result = await action();
            Assert.Equal(CollectionWriteStatus.Conflict, result.Status);
            Assert.Contains("Reload", result.Error);
            Assert.DoesNotContain("Storage", result.Error);
        }
        else Assert.Same(failure, await Assert.ThrowsAnyAsync<Exception>(action));
        Assert.Equal(before, await Snapshot());
    }

    [Fact]
    public async Task LastCollection_CannotBeDeleted()
    {
        await using (var db = fixture.CreateContext()) await db.Collections.Where(c => c.Id == 2).ExecuteDeleteAsync();
        var before = await Snapshot();
        var result = await Deletion().DeleteAsync(1, 1, 1, CancellationToken.None);
        Assert.Equal(CollectionWriteStatus.Invalid, result.Status);
        Assert.Contains("last collection", result.Error);
        Assert.Equal(before, await Snapshot());
    }

    [Theory]
    [InlineData("foreign-category")] [InlineData("external-child")] [InlineData("foreign-item")]
    [InlineData("external-item")] [InlineData("foreign-suggestion")] [InlineData("external-highlight")]
    public async Task InconsistentReferences_AreRejectedWithoutAlteringOtherContent(string state)
    {
        await AddGraph();
        await using (var db = fixture.CreateContext())
        {
            db.Workspaces.Add(new Workspace { Id = 2, Name = "Other" });
            switch (state)
            {
                case "foreign-category": db.Categories.Add(new Category { Id = 3, WorkspaceId = 2, CollectionId = 1, Name = "Foreign" }); break;
                case "external-child": db.Categories.Add(new Category { Id = 3, WorkspaceId = 1, CollectionId = 2, ParentCategoryId = 1, Name = "External" }); break;
                case "foreign-item": db.Items.Add(new Item { Id = 2, WorkspaceId = 2, CollectionId = 1, Name = "Foreign" }); break;
                case "external-item": db.Items.Add(new Item { Id = 2, WorkspaceId = 1, CollectionId = 2, CategoryId = 1, Name = "External" }); break;
                case "foreign-suggestion": db.PropertySuggestions.Add(new PropertySuggestion { WorkspaceId = 2, CollectionId = 1, Value = "Foreign" }); break;
                case "external-highlight": db.CollectionItemHighlights.Add(new CollectionItemHighlight { CollectionId = 2, ItemId = 1 }); break;
            }
            await db.SaveChangesAsync();
        }
        var before = await Snapshot();
        Assert.Equal(CollectionWriteStatus.Conflict, (await Deletion().DeleteAsync(1, 1, 1, CancellationToken.None)).Status);
        Assert.Equal(before, await Snapshot());
    }

    [Fact]
    public async Task Delete_HandlesCategoryCyclesAndPreservesSharedAssetsAndDailyCounters()
    {
        await AddGraph();
        await using (var db = fixture.CreateContext())
        {
            (await db.Categories.SingleAsync(c => c.Id == 1)).ParentCategoryId = 2;
            db.WorkspaceStatistics.Add(new WorkspaceStatistic { WorkspaceId = 1, StatisticType = StatisticType.ItemCount, Date = new DateOnly(2026, 11, 1), Value = 7 });
            db.StoredImages.Add(new StoredImage { Id = Guid.NewGuid(), WorkspaceId = 1, Data = [1, 2], FileName = "photo.png", ContentType = "image/png" });
            db.ItemTemplates.Add(new ItemTemplate { Id = 1, Name = "Shared", TemplateKey = Guid.NewGuid() });
            db.CollectionItemTemplates.AddRange(new CollectionItemTemplate { CollectionId = 1, ItemTemplateId = 1 }, new CollectionItemTemplate { CollectionId = 2, ItemTemplateId = 1 });
            db.CategoryItemTemplates.Add(new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1 });
            db.PropertySuggestions.Add(new PropertySuggestion { CollectionId = 1, WorkspaceId = 1, Value = "Suggestion" });
            await db.SaveChangesAsync();
        }
        Assert.Equal(CollectionWriteStatus.Success, (await Deletion().DeleteAsync(1, 1, 1, CancellationToken.None)).Status);
        await using var check = fixture.CreateContext();
        Assert.Empty(await check.Categories.ToListAsync());
        Assert.Empty(await check.CategoryItemTemplates.ToListAsync());
        Assert.Empty(await check.PropertySuggestions.ToListAsync());
        Assert.Equal(2, (await check.CollectionItemTemplates.SingleAsync()).CollectionId);
        Assert.Equal(1, (await check.ItemTemplates.SingleAsync()).Id);
        Assert.Equal(new byte[] { 1, 2 }, (await check.StoredImages.SingleAsync()).Data);
        Assert.Equal(7, (await check.WorkspaceStatistics.SingleAsync(s => s.Date != DateOnly.MinValue)).Value);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task CounterFailureOrCancellation_RollsBackDeletedContentAndCounters(bool cancel)
    {
        await AddGraph();
        var before = await Snapshot();
        using var cancellation = new CancellationTokenSource();
        var failure = new InvalidOperationException("Counter unavailable");
        var command = new CollectionDeletion(Factory(), new Counter(async (db, workspaceId, type, amount, token) =>
        {
            Assert.Equal(cancellation.Token, token);
            await new WorkspaceStatisticsWriter().DecrementAsync(db, workspaceId, type, amount, token);
            Assert.Equal(1, await db.Collections.CountAsync(token));
            if (cancel) { cancellation.Cancel(); token.ThrowIfCancellationRequested(); }
            throw failure;
        }));
        if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => command.DeleteAsync(1, 1, 1, cancellation.Token));
        else Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => command.DeleteAsync(1, 1, 1, cancellation.Token)));
        Assert.Equal(before, await Snapshot());
    }

    [Fact]
    public async Task CommitFailure_RollsBackAllDeletionWrites()
    {
        await AddGraph();
        var before = await Snapshot();
        await using var db = fixture.CreateContext();
        await db.Database.ExecuteSqlRawAsync("""CREATE FUNCTION reject_collection_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Commit test failure'; END $$""");
        await db.Database.ExecuteSqlRawAsync("""CREATE CONSTRAINT TRIGGER reject_collection_delete AFTER DELETE ON "Collections" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_collection_delete()""");
        try
        {
            await Assert.ThrowsAsync<PostgresException>(() => Deletion().DeleteAsync(1, 1, 1, CancellationToken.None));
            Assert.Equal(before, await Snapshot());
        }
        finally
        {
            await db.Database.ExecuteSqlRawAsync("DROP TRIGGER reject_collection_delete ON \"Collections\"");
            await db.Database.ExecuteSqlRawAsync("DROP FUNCTION reject_collection_delete()");
        }
    }

    [Fact]
    public async Task CancelledMetadataRequest_DoesNotWrite()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var before = await Snapshot();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Details().UpdateAsync(1, 1, 1, new() { Name = "Edited" }, cancellation.Token));
        Assert.Equal(before, await Snapshot());
    }

    private IDbContextFactory<AppDbContext> Factory(params IInterceptor[] interceptors) => new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options);
    private CollectionDetails Details(params IInterceptor[] interceptors) => new(Factory(interceptors));
    private CollectionDeletion Deletion() => new(Factory(), new WorkspaceStatisticsWriter());

    private async Task AddGraph()
    {
        await using var db = fixture.CreateContext();
        db.Categories.AddRange(new Category { Id = 1, WorkspaceId = 1, CollectionId = 1, Name = "Parent" },
            new Category { Id = 2, WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Name = "Child" });
        db.Items.Add(new Item { Id = 1, WorkspaceId = 1, CollectionId = 1, CategoryId = 2, Name = "Item" });
        db.CollectionItemHighlights.Add(new CollectionItemHighlight { CollectionId = 1, ItemId = 1, ViewCount = 2 });
        db.CollectionStatistics.Add(new CollectionStatistic { CollectionId = 1, StatisticType = CollectionStatisticType.ItemCount, Value = 1 });
        (await db.WorkspaceStatistics.SingleAsync(s => s.StatisticType == StatisticType.ItemCount)).Value = 1;
        await db.SaveChangesAsync();
    }

    private async Task<string> Snapshot()
    {
        await using var db = fixture.CreateContext();
        return JsonSerializer.Serialize(new
        {
            Collections = await db.Collections.AsNoTracking().OrderBy(c => c.Id).ToListAsync(),
            Categories = await db.Categories.AsNoTracking().OrderBy(c => c.Id).ToListAsync(),
            Items = await db.Items.AsNoTracking().OrderBy(i => i.Id).ToListAsync(),
            Highlights = await db.CollectionItemHighlights.AsNoTracking().OrderBy(h => h.Id).ToListAsync(),
            Statistics = await db.WorkspaceStatistics.AsNoTracking().OrderBy(s => s.Id).ToListAsync(),
            CollectionStatistics = await db.CollectionStatistics.AsNoTracking().OrderBy(s => s.Id).ToListAsync(),
            Images = await db.StoredImages.AsNoTracking().OrderBy(image => image.Id).ToListAsync(),
            Templates = await db.CollectionItemTemplates.AsNoTracking().OrderBy(link => link.CollectionId).ThenBy(link => link.ItemTemplateId).ToListAsync(),
            CategoryTemplates = await db.CategoryItemTemplates.AsNoTracking().OrderBy(link => link.CategoryId).ThenBy(link => link.ItemTemplateId).ToListAsync()
        });
    }

    private sealed class Counter(Func<AppDbContext, int, StatisticType, long, CancellationToken, Task> write) : IWorkspaceStatisticsDecrementer
    {
        public Task DecrementAsync(AppDbContext context, int workspaceId, StatisticType type, long amount = 1, CancellationToken cancellationToken = default) =>
            write(context, workspaceId, type, amount, cancellationToken);
    }
}

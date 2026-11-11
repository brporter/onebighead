using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.BulkUpdate;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class BulkUpdateItemStoreTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly Guid Template = Guid.Parse("a1b2c3d4-1111-4000-8000-00000000f001");

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(new Workspace { Id = 1, Name = "Workspace one" }, new Workspace { Id = 2, Name = "Workspace two" });
        db.Users.Add(new User { Id = 1, Email = "bulk-user@example.test", ActiveWorkspaceId = 1 });
        db.WorkspaceUsers.Add(new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.Normal });
        db.Collections.AddRange(
            new Collection { Id = 11, WorkspaceId = 1, Name = "First", Slug = "first" },
            new Collection { Id = 12, WorkspaceId = 1, Name = "Second", Slug = "second" },
            new Collection { Id = 21, WorkspaceId = 2, Name = "Other", Slug = "other" });
        db.Categories.AddRange(
            new Category { Id = 111, WorkspaceId = 1, CollectionId = 11, Name = "Selected" },
            new Category { Id = 112, WorkspaceId = 1, CollectionId = 11, Name = "Other" },
            new Category { Id = 121, WorkspaceId = 1, CollectionId = 12, Name = "Second" });
        db.Items.AddRange(
            Item(1, 1, 11, 111, Template), Item(2, 1, 11, 112, Template), Item(3, 1, 12, 121, Template),
            Item(4, 1, 11, 111, Guid.NewGuid()), Item(5, 2, 21, null, Template),
            // Legacy inconsistent references must never expand a workspace's target selection.
            Item(6, 1, 21, null, Template));
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(BulkUpdateScope.Template, null, new[] { 1, 2, 3 })]
    [InlineData(BulkUpdateScope.Template, 1, new[] { 2, 3 })]
    [InlineData(BulkUpdateScope.Template, 4, new[] { 1, 2, 3 })]
    [InlineData(BulkUpdateScope.Template, 5, new[] { 1, 2, 3 })]
    [InlineData(BulkUpdateScope.Template, 999, new[] { 1, 2, 3 })]
    [InlineData(BulkUpdateScope.Category, null, new[] { 1, 4 })]
    [InlineData(BulkUpdateScope.Category, 1, new[] { 4 })]
    [InlineData(BulkUpdateScope.Category, 2, new[] { 1, 4 })]
    [InlineData(BulkUpdateScope.Collection, null, new[] { 1, 2, 4 })]
    [InlineData(BulkUpdateScope.Collection, 1, new[] { 2, 4 })]
    [InlineData(BulkUpdateScope.Collection, 3, new[] { 1, 2, 4 })]
    public async Task PreviewAndExecution_UseIdenticalWorkspaceScopeAndExclusion(BulkUpdateScope scope, int? excluded, int[] expected)
    {
        var target = new BulkUpdateTarget(scope, Template, 111, 11, excluded);
        var store = Store();
        Assert.Equal(expected.Length, await store.CountAsync(target, 1, CancellationToken.None));
        var selected = await store.GetAsync(target, 1, CancellationToken.None);
        Assert.Equal(expected, selected.Select(item => item.Id));
        Assert.All(selected, item => Assert.Contains(item.CollectionId, new[] { 11, 12 }));
    }

    [Fact]
    public async Task WritesUseCurrentProperties_AndPreserveUnrelatedFields()
    {
        var store = Store();
        var job = Job();
        await store.GetAsync(job.Target, 1, CancellationToken.None);
        await using (var edit = fixture.CreateContext())
        {
            var item = await edit.Items.SingleAsync(value => value.Id == 1);
            item.Name = "New name";
            item.Summary = "New summary";
            item.Description = "New description";
            item.CategoryId = 112;
            item.Visibility = Visibility.Public;
            item.UserFlag = UserFlag.Want;
            item.Images = [new("/images/new", "New image")];
            item.Properties = [new("Specs", "Old", "current value"), new("Custom", "Keep", "custom value")];
            await edit.SaveChangesAsync();
        }
        Assert.True(await store.ApplyAsync(job, 1, CancellationToken.None));
        await using var check = fixture.CreateContext();
        var saved = await check.Items.SingleAsync(item => item.Id == 1);
        Assert.Equal([new ItemProperty("Specs", "New", "current value"), new ItemProperty("Custom", "Keep", "custom value")], saved.Properties);
        Assert.Equal("New name", saved.Name);
        Assert.Equal("New summary", saved.Summary);
        Assert.Equal("New description", saved.Description);
        Assert.Equal(112, saved.CategoryId);
        Assert.Equal(Visibility.Public, saved.Visibility);
        Assert.Equal(UserFlag.Want, saved.UserFlag);
        Assert.Equal([new ItemImage("/images/new", "New image")], saved.Images);
        Assert.Equal("value-2", (await check.Items.SingleAsync(item => item.Id == 2)).Properties.Single().Value);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(999)]
    public async Task OutOfScopeAndMissingItems_AreNotReportedAsUpdated(int itemId)
        => Assert.False(await Store().ApplyAsync(Job(), itemId, CancellationToken.None));

    [Fact]
    public async Task ItemsExcludedOrMovedAfterSelection_AreNotUpdated()
    {
        var excluded = Job(new(BulkUpdateScope.Template, TemplateKey: Template, ExcludeItemId: 1));
        Assert.False(await Store().ApplyAsync(excluded, 1, CancellationToken.None));
        var categoryJob = Job(new(BulkUpdateScope.Category, CategoryId: 111));
        await Store().GetAsync(categoryJob.Target, 1, CancellationToken.None);
        await using var edit = fixture.CreateContext();
        await edit.Items.Where(item => item.Id == 1).ExecuteUpdateAsync(update => update.SetProperty(item => item.CategoryId, 112));
        Assert.False(await Store().ApplyAsync(categoryJob, 1, CancellationToken.None));
    }

    [Theory]
    [InlineData(121, 1)]
    [InlineData(211, 0)]
    public async Task CategoryTargets_RejectReferencesToAnotherCollectionOrWorkspace(int categoryId, int expectedCount)
    {
        await using var setup = fixture.CreateContext();
        setup.Categories.Add(new Category { Id = 211, WorkspaceId = 2, CollectionId = 21, Name = "Foreign category" });
        setup.Items.Add(Item(7, 1, 11, categoryId, Template));
        await setup.SaveChangesAsync();
        var target = new BulkUpdateTarget(BulkUpdateScope.Category, CategoryId: categoryId);
        Assert.Equal(expectedCount, await Store().CountAsync(target, 1, CancellationToken.None));
        Assert.DoesNotContain(await Store().GetAsync(target, 1, CancellationToken.None), item => item.Id == 7);
        Assert.False(await Store().ApplyAsync(Job(target), 7, CancellationToken.None));
        await AssertOriginalProperties(7);
    }

    [Theory]
    [InlineData("membership")]
    [InlineData("user")]
    [InlineData("workspace")]
    public async Task LostAuthority_PreventsQueuedWrites(string change)
    {
        await using var edit = fixture.CreateContext();
        if (change == "membership") await edit.WorkspaceUsers.ExecuteDeleteAsync();
        if (change == "user") await edit.Users.ExecuteUpdateAsync(update => update.SetProperty(user => user.IsDeleted, true));
        if (change == "workspace") await edit.Workspaces.Where(workspace => workspace.Id == 1)
            .ExecuteUpdateAsync(update => update.SetProperty(workspace => workspace.IsDeleted, true));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Store().ApplyAsync(Job(), 1, CancellationToken.None));
        await AssertOriginalProperties(1);
        if (change == "workspace")
        {
            Assert.Equal(0, await Store().CountAsync(Job().Target, 1, CancellationToken.None));
            Assert.Empty(await Store().GetAsync(Job().Target, 1, CancellationToken.None));
        }
    }

    [Fact]
    public async Task SaveFailureAndCancellation_RollBackProperties()
    {
        var failure = new InvalidOperationException("Injected save failure");
        await Assert.ThrowsAsync<InvalidOperationException>(() => Store(new BeforeMembershipSave(() => throw failure))
            .ApplyAsync(Job(), 1, CancellationToken.None));
        await AssertOriginalProperties(1);
        using var cancellation = new CancellationTokenSource();
        var cancelBeforeSave = new BeforeMembershipSave(() =>
        {
            cancellation.Cancel();
            return Task.CompletedTask;
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Store(cancelBeforeSave).ApplyAsync(Job(), 1, cancellation.Token));
        await AssertOriginalProperties(1);
    }

    [Fact]
    public async Task CommitFailure_RollsBackSavedProperties()
    {
        await using var db = fixture.CreateContext();
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION bulk_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Injected bulk commit failure'; END $$;
            CREATE CONSTRAINT TRIGGER bulk_commit_failure AFTER UPDATE ON "Items"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION bulk_commit_failure();
            """);
        try
        {
            await Assert.ThrowsAsync<PostgresException>(() => Store().ApplyAsync(Job(), 1, CancellationToken.None));
            await AssertOriginalProperties(1);
        }
        finally
        {
            await db.Database.ExecuteSqlRawAsync("DROP TRIGGER bulk_commit_failure ON \"Items\"; DROP FUNCTION bulk_commit_failure()");
        }
    }

    [Fact]
    public async Task ConcurrentPropertyWrites_CommitOnlyOneWithoutOverwritingOrRetrying()
    {
        var synchronization = new SynchronizedSaves();
        var first = Job(newName: "First");
        var second = Job(newName: "Second");
        async Task<Exception?> Apply(BulkUpdateJob job)
        {
            try { await Store(synchronization).ApplyAsync(job, 1, CancellationToken.None); return null; }
            catch (Exception exception) { return exception; }
        }
        var results = await Task.WhenAll(Apply(first), Apply(second)).WaitAsync(TimeSpan.FromSeconds(15));
        Assert.Single(results, exception => exception is null);
        var failure = Assert.Single(results, exception => exception is not null)!;
        Assert.Contains("40001", failure.ToString());
        await using var check = fixture.CreateContext();
        var property = (await check.Items.SingleAsync(item => item.Id == 1)).Properties.Single();
        Assert.Contains(property.Name, new[] { "First", "Second" });
        Assert.Equal("value-1", property.Value);
    }

    [Fact]
    public async Task ConcurrentUnrelatedEdit_IsNeverOverwrittenByBulkUpdate()
    {
        var concurrentEdit = new BeforeMembershipSave(async () =>
        {
            await using var edit = fixture.CreateContext();
            await edit.Items.Where(item => item.Id == 1).ExecuteUpdateAsync(update => update.SetProperty(item => item.Name, "Concurrent name"));
        });
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => Store(concurrentEdit).ApplyAsync(Job(), 1, CancellationToken.None));
        Assert.Equal(PostgresErrorCodes.SerializationFailure, Assert.IsType<PostgresException>(failure.GetBaseException()).SqlState);
        await using var check = fixture.CreateContext();
        Assert.Equal("Concurrent name", (await check.Items.SingleAsync(item => item.Id == 1)).Name);
        await AssertOriginalProperties(1);
    }

    [Fact]
    public async Task HttpPreviewAndQueuedWorker_UseRegisteredStoreAndMatchResponseCounts()
    {
        using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        var preview = await client.PostAsJsonAsync("/api/bulkupdates/preview", new BulkUpdatePreviewRequest
        {
            Scope = "template", TemplateKey = Template, ExcludeItemId = 5
        });
        Assert.Equal(HttpStatusCode.OK, preview.StatusCode);
        Assert.Equal(3, (await preview.Content.ReadFromJsonAsync<BulkUpdatePreviewResponse>())!.AffectedItemCount);
        var response = await client.PostAsJsonAsync("/api/bulkupdates", new EnqueueBulkUpdateRequest
        {
            Scope = "template", TemplateKey = Template, ExcludeItemId = 1,
            OldProperties = [new() { Category = "Specs", Name = "Old" }],
            NewProperties = [new() { Category = "Specs", Name = "New" }],
            RenameMappings = [new() { OldCategory = "Specs", OldName = "Old", NewCategory = "Specs", NewName = "New" }]
        });
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var job = (await response.Content.ReadFromJsonAsync<BulkUpdateJobResponse>())!;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        do
        {
            await Task.Delay(10, timeout.Token);
            job = (await client.GetFromJsonAsync<BulkUpdateJobResponse>($"/api/bulkupdates/{job.JobId}", timeout.Token))!;
        } while (job.Status is "Queued" or "Running");
        Assert.Equal("Completed", job.Status);
        Assert.Equal(2, job.TotalItems);
        Assert.Equal(2, job.ProcessedItems);
        Assert.Equal(0, job.FailedItems);
        await AssertOriginalProperties(1);
        await AssertOriginalProperties(5);
        await AssertOriginalProperties(6);
        await using var check = fixture.CreateContext();
        Assert.All(await check.Items.Where(item => item.Id == 2 || item.Id == 3).ToListAsync(),
            item => Assert.Equal("New", item.Properties.Single().Name));
    }

    private BulkUpdateItemStore Store(params IInterceptor[] interceptors) => new(
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString)
            .AddInterceptors(interceptors).Options), new PropertyDiffService());

    private static BulkUpdateJob Job(BulkUpdateTarget? target = null, string newName = "New") => new()
    {
        WorkspaceId = 1, RequestedByUserId = 1, Target = target ?? new(BulkUpdateScope.Template, TemplateKey: Template),
        Diff = new([new(PropertyChangeType.Renamed, "Specs", "Old", "Specs", newName)]),
        NewPropertyOrder = [new("Specs", newName)]
    };

    private async Task AssertOriginalProperties(int id)
    {
        await using var check = fixture.CreateContext();
        Assert.Equal([new ItemProperty("Specs", "Old", $"value-{id}")],
            (await check.Items.SingleAsync(item => item.Id == id)).Properties);
    }

    private static Item Item(int id, int workspace, int collection, int? category, Guid template) => new()
    {
        Id = id, WorkspaceId = workspace, CollectionId = collection, CategoryId = category,
        TemplateKey = template, Name = $"Item {id}", Properties = [new("Specs", "Old", $"value-{id}")]
    };
}

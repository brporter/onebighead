using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Publishing;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class PublicationServiceTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.AddRange(new Workspace { Id = 1, Name = "Library", Slug = "library" }, new Workspace { Id = 2, Name = "Other", Slug = "other" });
        context.Collections.AddRange(
            new Collection { Id = 1, WorkspaceId = 1, Name = "Books", Slug = "books", Description = "Preserved", HeroImageUrl = "/cover" },
            new Collection { Id = 2, WorkspaceId = 1, Name = "Records", Slug = "records", Visibility = Visibility.Public },
            new Collection { Id = 3, WorkspaceId = 2, Name = "Foreign", Slug = "foreign" });
        context.Categories.AddRange(
            new Category { Id = 1, WorkspaceId = 1, CollectionId = 1, Name = "Root", SortOrder = 5, Description = "Preserved" },
            new Category { Id = 2, WorkspaceId = 1, CollectionId = 1, Name = "Child", ParentCategoryId = 1 },
            new Category { Id = 3, WorkspaceId = 1, CollectionId = 1, Name = "Sibling", Visibility = Visibility.Public },
            new Category { Id = 4, WorkspaceId = 1, CollectionId = 2, Name = "Other collection", Visibility = Visibility.Public },
            new Category { Id = 5, WorkspaceId = 2, CollectionId = 3, Name = "Foreign" },
            new Category { Id = 6, WorkspaceId = 1, CollectionId = 3, Name = "Inconsistent" });
        context.Items.AddRange(
            new Item { Id = 1, WorkspaceId = 1, CollectionId = 1, CategoryId = 2, Name = "Dune", Description = "Preserved", Properties = [new("Edition", "Year", "1965")] },
            new Item { Id = 2, WorkspaceId = 1, CollectionId = 1, CategoryId = 2, Name = "Second" },
            new Item { Id = 3, WorkspaceId = 1, CollectionId = 1, CategoryId = 3, Name = "Sibling item", Visibility = Visibility.Public },
            new Item { Id = 4, WorkspaceId = 1, CollectionId = 1, Name = "Uncategorized", Visibility = Visibility.Public },
            new Item { Id = 5, WorkspaceId = 1, CollectionId = 2, CategoryId = 4, Name = "Record", Visibility = Visibility.Public },
            new Item { Id = 6, WorkspaceId = 2, CollectionId = 3, Name = "Foreign" },
            new Item { Id = 7, WorkspaceId = 1, CollectionId = 3, Name = "Inconsistent" });
        await context.SaveChangesAsync();
    }
    public Task DisposeAsync() => Task.CompletedTask;
    private PublicationService Service() => new(fixture.CreateContextFactory(), new VisibilityService());
    private PublicationService ServiceWith(IInterceptor interceptor) => new(new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString, options => options.MaxBatchSize(1)).AddInterceptors(interceptor).Options), new VisibilityService());
    private static List<EntityRef> Select(string type = "item", int id = 1) => [new() { Type = type, Id = id }];
    private static List<PublishResolution> Consent(List<PublishRequirement> requirements, string slug = "new-library") => requirements.Select<PublishRequirement, PublishResolution>(requirement => requirement switch
    {
        WorkspaceSlugRequiredRequirement => new WorkspaceSlugResolution { Slug = slug },
        CollectionNotPublicRequirement collection => new CollectionNotPublicResolution { CollectionId = collection.CollectionId },
        CategoryNotPublicRequirement category => new CategoryNotPublicResolution { CategoryId = category.CategoryId },
        UnpublishWillHideChildrenRequirement impact => new UnpublishWillHideChildrenResolution { EntityType = impact.EntityType, EntityId = impact.EntityId,
            AffectedPublicItems = impact.AffectedPublicItems, AffectedPublicCategories = impact.AffectedPublicCategories },
        _ => throw new InvalidOperationException()
    }).ToList();
    private async Task<ExecuteRequest> Reviewed(string type = "item", int id = 1, PublishAction action = PublishAction.Publish, string slug = "new-library")
    {
        var entities = Select(type, id);
        var preflight = await Service().PreflightAsync(1, new() { Action = action, Entities = entities });
        Assert.Null(preflight.Error);
        return new() { Action = action, Entities = entities, Resolutions = Consent(preflight.Value!.Requirements, slug) };
    }
    private async Task AssertPrivateAsync()
    {
        await using var context = fixture.CreateContext();
        Assert.Equal(Visibility.Private, (await context.Collections.FindAsync(1))!.Visibility);
        Assert.Equal(Visibility.Private, (await context.Categories.FindAsync(1))!.Visibility);
        Assert.Equal(Visibility.Private, (await context.Categories.FindAsync(2))!.Visibility);
        Assert.Equal(Visibility.Private, (await context.Items.FindAsync(1))!.Visibility);
    }

    [Fact]
    public async Task Publish_CommitsAncestorsAndItemTogether_PreservesMetadata_AndReplayIsANoop()
    {
        var request = await Reviewed();
        request.Entities.Add(new() { Type = "item", Id = 1 });
        await AssertPrivateAsync();
        var result = await Service().ExecuteAsync(1, request);
        Assert.Null(result.Error);
        Assert.True(result.Value!.Success);
        Assert.Equal("Dune", Assert.Single(result.Value.Changed).Name);
        Assert.Equal(["collection", "category", "category"], result.Value.Promoted.Select(entity => entity.Type));
        await using var context = fixture.CreateContext();
        var collection = (await context.Collections.FindAsync(1))!;
        var category = (await context.Categories.FindAsync(1))!;
        var item = (await context.Items.FindAsync(1))!;
        Assert.Equal(Visibility.Public, collection.Visibility);
        Assert.Equal(Visibility.Public, category.Visibility);
        Assert.Equal(Visibility.Public, item.Visibility);
        Assert.Equal("Preserved", collection.Description);
        Assert.Equal("/cover", collection.HeroImageUrl);
        Assert.Equal("Preserved", category.Description);
        Assert.Equal(5, category.SortOrder);
        Assert.Equal(2, item.CategoryId);
        Assert.Equal("Preserved", item.Description);
        Assert.Equal("1965", Assert.Single(item.Properties).Value);
        Assert.Equal(Visibility.Private, (await context.Items.FindAsync(2))!.Visibility);
        var replay = await Service().ExecuteAsync(1, request);
        Assert.True(replay.Value!.Success);
        Assert.Empty(replay.Value.Changed);
        Assert.Empty(replay.Value.Promoted);
    }

    [Theory]
    [InlineData("collection", 1)] [InlineData("category", 2)] [InlineData("item", 4)]
    public async Task Publish_HandlesEachEntityType(string type, int id)
    {
        var result = await Service().ExecuteAsync(1, await Reviewed(type, id));
        Assert.Null(result.Error);
        Assert.True(result.Value!.Success);
        var ready = await Service().PreflightAsync(1, new() { Action = PublishAction.Publish, Entities = Select(type, id) });
        Assert.True(ready.Value!.Ready);
    }

    [Theory]
    [InlineData("item", 6)] [InlineData("item", 7)] [InlineData("item", 999)]
    [InlineData("category", 5)] [InlineData("category", 6)] [InlineData("category", 999)]
    [InlineData("collection", 3)] [InlineData("collection", 999)]
    public async Task MissingForeignAndInconsistentReferences_RejectTheWholeSelection(string type, int id)
    {
        var entities = Select(); entities.Add(new() { Type = type, Id = id });
        var preflight = await Service().PreflightAsync(1, new() { Entities = entities });
        var execute = await Service().ExecuteAsync(1, new() { Entities = entities });
        Assert.Equal(PublicationFailure.NotFound, preflight.Error!.Kind);
        Assert.Equal(PublicationFailure.NotFound, execute.Error!.Kind);
        await AssertPrivateAsync();
    }

    [Theory]
    [InlineData("empty")] [InlineData("type")] [InlineData("id")] [InlineData("action")]
    public async Task InvalidSelections_AreRejectedBeforeWrites(string scenario)
    {
        var entities = scenario == "empty" ? [] : Select(scenario == "type" ? "unknown" : "item", scenario == "id" ? 0 : 1);
        var action = scenario == "action" ? (PublishAction)999 : PublishAction.Publish;
        Assert.Equal(PublicationFailure.Invalid, (await Service().PreflightAsync(1, new() { Action = action, Entities = entities })).Error!.Kind);
        Assert.Equal(PublicationFailure.Invalid, (await Service().ExecuteAsync(1, new() { Action = action, Entities = entities })).Error!.Kind);
        await AssertPrivateAsync();
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task MissingOrDeletedWorkspace_IsUnavailable(bool deleted)
    {
        if (deleted) { await using var context = fixture.CreateContext(); (await context.Workspaces.FindAsync(1))!.IsDeleted = true; await context.SaveChangesAsync(); }
        var id = deleted ? 1 : 999;
        Assert.Equal(PublicationFailure.NotFound, (await Service().PreflightAsync(id, new() { Entities = Select() })).Error!.Kind);
        Assert.Equal(PublicationFailure.NotFound, (await Service().ExecuteAsync(id, new() { Entities = Select() })).Error!.Kind);
        await AssertPrivateAsync();
    }

    [Theory]
    [InlineData(2)] [InlineData(4)] [InlineData(5)]
    public async Task CyclicOrForeignAncestry_FailsClosed(int parentId)
    {
        await using (var context = fixture.CreateContext()) { (await context.Categories.FindAsync(1))!.ParentCategoryId = parentId; await context.SaveChangesAsync(); }
        Assert.Equal(PublicationFailure.Conflict, (await Service().PreflightAsync(1, new() { Entities = Select() })).Error!.Kind);
        Assert.Equal(PublicationFailure.Conflict, (await Service().ExecuteAsync(1, new() { Entities = Select() })).Error!.Kind);
        await AssertPrivateAsync();
    }

    [Fact]
    public async Task MissingConsent_ReturnsCurrentRequirementsWithoutWriting()
    {
        var result = await Service().ExecuteAsync(1, new() { Entities = Select() });
        Assert.Null(result.Error);
        Assert.False(result.Value!.Success);
        Assert.Equal(3, result.Value.Requirements!.Count);
        await AssertPrivateAsync();
    }

    [Theory]
    [InlineData("new-library", true)] [InlineData("other", false)] [InlineData("INVALID", false)]
    public async Task GalleryUrl_IsValidatedAndCommittedWithVisibility(string slug, bool success)
    {
        await using (var context = fixture.CreateContext()) { (await context.Workspaces.FindAsync(1))!.Slug = null; await context.SaveChangesAsync(); }
        var result = await Service().ExecuteAsync(1, await Reviewed(slug: slug));
        Assert.Null(result.Error);
        Assert.Equal(success, result.Value!.Success);
        await using var check = fixture.CreateContext();
        Assert.Equal(success ? slug : null, (await check.Workspaces.FindAsync(1))!.Slug);
        if (success) Assert.Equal(slug, result.Value.WorkspaceSlugSet);
        else { Assert.NotEmpty(result.Value.Requirements!); await AssertPrivateAsync(); }
    }

    [Theory]
    [InlineData(PublishAction.Publish)] [InlineData(PublishAction.Unpublish)]
    public async Task ExtraneousUrlResolution_CannotRenameExistingGallery(PublishAction action)
    {
        var request = await Reviewed(action: action);
        request.Resolutions.Add(new WorkspaceSlugResolution { Slug = "renamed" });
        Assert.True((await Service().ExecuteAsync(1, request)).Value!.Success);
        await using var context = fixture.CreateContext();
        Assert.Equal("library", (await context.Workspaces.FindAsync(1))!.Slug);
    }

    [Theory]
    [InlineData("item", 1)] [InlineData("category", 2)] [InlineData("collection", 1)]
    public async Task Unpublish_HidesOnlyTheSelectionAndPreservesChildPreferences(string type, int id)
    {
        Assert.True((await Service().ExecuteAsync(1, await Reviewed())).Value!.Success);
        var request = await Reviewed(type, id, PublishAction.Unpublish);
        var result = await Service().ExecuteAsync(1, request);
        Assert.True(result.Value!.Success);
        Assert.Equal(type, Assert.Single(result.Value.Changed).Type);
        await using var context = fixture.CreateContext();
        Assert.Equal(type == "item" ? Visibility.Private : Visibility.Public, (await context.Items.FindAsync(1))!.Visibility);
        Assert.Equal(Visibility.Public, (await context.Categories.FindAsync(3))!.Visibility);
        Assert.Equal(Visibility.Public, (await context.Items.FindAsync(3))!.Visibility);
    }

    [Fact]
    public async Task ChangedUnpublishImpact_RequiresFreshAcknowledgment()
    {
        await Service().ExecuteAsync(1, await Reviewed());
        var request = await Reviewed("category", 2, PublishAction.Unpublish);
        var first = Assert.IsType<UnpublishWillHideChildrenResolution>(Assert.Single(request.Resolutions));
        Assert.Equal(1, first.AffectedPublicItems);
        await using (var context = fixture.CreateContext()) { (await context.Items.FindAsync(2))!.Visibility = Visibility.Public; await context.SaveChangesAsync(); }
        var result = await Service().ExecuteAsync(1, request);
        Assert.False(result.Value!.Success);
        var impact = Assert.IsType<UnpublishWillHideChildrenRequirement>(Assert.Single(result.Value.Requirements!));
        Assert.Equal(2, impact.AffectedPublicItems);
        request.Resolutions = Consent(result.Value.Requirements!);
        Assert.True((await Service().ExecuteAsync(1, request)).Value!.Success);
    }

    [Fact]
    public async Task DatabaseFailure_RollsBackEarlierVisibilityUpdatesAndGalleryUrl()
    {
        await using var context = fixture.CreateContext();
        (await context.Workspaces.FindAsync(1))!.Slug = null;
        await context.SaveChangesAsync();
        await context.Database.ExecuteSqlRawAsync("""
            ALTER TABLE "Workspaces" ADD CONSTRAINT "PublicationRollbackTest" CHECK ("Slug" <> 'rollback')
            """);
        try
        {
            var completed = new CompletedCommands();
            var request = await Reviewed(slug: "rollback");
            await Assert.ThrowsAsync<DbUpdateException>(() => ServiceWith(completed).ExecuteAsync(1, request));
            Assert.Contains(completed.Sql, sql => sql.StartsWith("UPDATE \"Categories\"", StringComparison.Ordinal));
            Assert.Contains(completed.Sql, sql => sql.StartsWith("UPDATE \"Collections\"", StringComparison.Ordinal));
            Assert.Contains(completed.Sql, sql => sql.StartsWith("UPDATE \"Items\"", StringComparison.Ordinal));
            await AssertPrivateAsync();
            context.ChangeTracker.Clear();
            Assert.Null((await context.Workspaces.FindAsync(1))!.Slug);
        }
        finally { await context.Database.ExecuteSqlRawAsync("ALTER TABLE \"Workspaces\" DROP CONSTRAINT \"PublicationRollbackTest\""); }
    }

    [Fact]
    public async Task ConcurrentPublications_CommitOneSnapshotAndRequireRecheckingTheOther()
    {
        var first = await Reviewed();
        var second = await Reviewed(id: 2);
        var service = ServiceWith(new BothLoaded());
        var results = await Task.WhenAll(service.ExecuteAsync(1, first), service.ExecuteAsync(1, second)).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.True(Assert.Single(results, result => result.Error is null).Value!.Success);
        Assert.Equal(PublicationFailure.Conflict, Assert.Single(results, result => result.Error != null).Error!.Kind);
        await using var context = fixture.CreateContext();
        Assert.Single(await context.Items.Where(item => item.Id <= 2 && item.Visibility == Visibility.Public).ToListAsync());
        Assert.True((await Service().ExecuteAsync(1, results[0].Error != null ? first : second)).Value!.Success);
    }

    [Theory]
    [InlineData("serialization")] [InlineData("wrapped")] [InlineData("deadlock")] [InlineData("concurrency")] [InlineData("slug")]
    public async Task KnownDatabaseConflicts_ReturnRetryableRejections(string kind)
    {
        var postgres = new PostgresException("Injected", "ERROR", "ERROR", kind == "deadlock" ? PostgresErrorCodes.DeadlockDetected :
            kind == "slug" ? PostgresErrorCodes.UniqueViolation : PostgresErrorCodes.SerializationFailure, constraintName: "IX_Workspaces_Slug");
        Exception error = kind == "concurrency" ? new DbUpdateConcurrencyException("Injected") : kind is "wrapped" or "slug" ? new DbUpdateException("Injected", postgres) : postgres;
        var result = await ServiceWith(new FailingSave(error)).ExecuteAsync(1, await Reviewed());
        Assert.Equal(PublicationFailure.Conflict, result.Error!.Kind);
        await AssertPrivateAsync();
    }

    [Theory]
    [InlineData("unexpected")] [InlineData("other-constraint")] [InlineData("database")]
    public async Task UnexpectedFailures_AreNotMisreportedAsConflicts(string kind)
    {
        Exception error = kind switch {
            "unexpected" => new InvalidOperationException("Injected"),
            "database" => new DbUpdateException("Injected"),
            _ => new DbUpdateException("Injected", new PostgresException("Injected", "ERROR", "ERROR", PostgresErrorCodes.UniqueViolation, constraintName: "DifferentConstraint"))
        };
        var request = await Reviewed();
        Assert.Same(error, await Record.ExceptionAsync(() => ServiceWith(new FailingSave(error)).ExecuteAsync(1, request)));
        await AssertPrivateAsync();
    }

    [Fact]
    public async Task Cancellation_DoesNotWrite()
    {
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Service().PreflightAsync(1, new() { Entities = Select() }, new(true)));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Service().ExecuteAsync(1, new() { Entities = Select() }, new(true)));
        await AssertPrivateAsync();
    }

    private sealed class CompletedCommands : DbCommandInterceptor
    {
        public List<string> Sql { get; } = [];
        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData, DbDataReader result, CancellationToken cancellationToken = default)
        { Sql.Add(command.CommandText); return ValueTask.FromResult(result); }
    }
    private sealed class BothLoaded : SaveChangesInterceptor
    {
        private readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int arrived;
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref arrived) == 2) ready.SetResult();
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            return result;
        }
    }
    private sealed class FailingSave(Exception failure) : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default) =>
            ValueTask.FromException<InterceptionResult<int>>(failure);
    }
}

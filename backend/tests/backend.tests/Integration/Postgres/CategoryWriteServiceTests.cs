using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Categories;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class CategoryWriteServiceTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private CategoryWriteService Service() => new(fixture.CreateContextFactory());

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.AddRange(new Workspace { Id = 1, Name = "Own" }, new Workspace { Id = 2, Name = "Other" });
        context.Collections.AddRange(
            new Collection { Id = 1, WorkspaceId = 1, Name = "Public", Slug = "public", Visibility = Visibility.Public },
            new Collection { Id = 2, WorkspaceId = 1, Name = "Private", Slug = "private" },
            new Collection { Id = 3, WorkspaceId = 2, Name = "Foreign", Slug = "foreign" });
        context.Categories.AddRange(
            Category(1, "Unassigned Items", system: true), Category(2, "Root", sortOrder: 4),
            Category(3, "Child", parentId: 2), Category(4, "Grandchild", parentId: 3),
            Category(5, "Other collection", collectionId: 2), Category(6, "Foreign", collectionId: 3, workspaceId: 2),
            Category(7, "Private parent", visibility: Visibility.Private), Category(8, "Wrong collection workspace", collectionId: 3),
            Category(9, "Unassigned Items", collectionId: 2, system: true), Category(10, "Other root"));
        context.ItemTemplates.AddRange(Template(1, null), Template(2, 1), Template(3, 2), Template(4, null));
        context.CategoryItemTemplates.AddRange(new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 1, SortOrder = 2 },
            new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 2, SortOrder = 5 });
        context.Items.AddRange(new Item { Id = 1, WorkspaceId = 1, CollectionId = 1, CategoryId = 2, Name = "First" },
            new Item { Id = 2, WorkspaceId = 1, CollectionId = 1, CategoryId = 2, Name = "Second" });
        await context.SaveChangesAsync();
        await context.Database.ExecuteSqlRawAsync("ALTER SEQUENCE \"Categories_Id_seq\" RESTART WITH 100");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static Category Category(int id, string name, int collectionId = 1, int workspaceId = 1,
        int? parentId = null, bool system = false, int sortOrder = 0, Visibility visibility = Visibility.Public) => new()
    {
        Id = id, WorkspaceId = workspaceId, CollectionId = collectionId, Name = name,
        ParentCategoryId = parentId, IsSystem = system, SortOrder = sortOrder, Visibility = visibility
    };
    private static ItemTemplate Template(int id, int? workspaceId) => new()
    { Id = id, WorkspaceId = workspaceId, Name = $"Template {id}", TemplateKey = Guid.NewGuid() };

    [Theory]
    [InlineData(1, null, true)]
    [InlineData(2, null, false)]
    [InlineData(1, 2, true)]
    [InlineData(1, 7, false)]
    public async Task Create_CommitsNormalizedFieldsAndOrderedDistinctTemplates_WithInheritedVisibility(int collectionId, int? parentId, bool visible)
    {
        var result = await Service().CreateAsync(1, new CreateCategoryRequest
        { CollectionId = collectionId, Name = "  New category  ", ParentCategoryId = parentId, ItemTemplateIds = [2, 1, 2] });

        Assert.Null(result.Error);
        var category = result.Value!;
        Assert.True(category.CategoryId >= 100);
        Assert.Equal("New category", category.Name);
        Assert.Equal("", category.Description);
        Assert.Equal(parentId, category.ParentCategoryId);
        Assert.Equal(visible, category.EffectiveIsPublic);
        Assert.Equal(visible ? Visibility.Public : Visibility.Private, category.Visibility);
        Assert.False(category.IsSystem);
        Assert.Equal([2, 1], category.ItemTemplateIds);
        await using var context = fixture.CreateContext();
        Assert.Equal("New category", (await context.Categories.FindAsync(category.CategoryId))!.Name);
        Assert.Equal([2, 1], await context.CategoryItemTemplates.Where(link => link.CategoryId == category.CategoryId)
            .OrderBy(link => link.SortOrder).Select(link => link.ItemTemplateId).ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Create_AllowsNoTemplateAssignments(bool explicitEmpty)
    {
        var result = await Service().CreateAsync(1, new CreateCategoryRequest
        { CollectionId = 1, Name = "No templates", Description = "Description", ItemTemplateIds = explicitEmpty ? [] : null });
        Assert.Null(result.Error);
        Assert.Empty(result.Value!.ItemTemplateIds);
        Assert.Equal("Description", result.Value.Description);
    }

    [Fact]
    public async Task Update_ReparentsAndReplacesAssignmentsTogether_WhilePreservingVisibilityAndOrder()
    {
        var result = await Service().UpdateAsync(2, 1, new UpdateCategoryRequest
        { Name = "  Edited  ", ParentCategoryId = 7, ItemTemplateIds = [4, 2, 4] });
        Assert.Null(result.Error);
        Assert.Equal("Edited", result.Value!.Name);
        Assert.Equal(7, result.Value.ParentCategoryId);
        Assert.Equal(Visibility.Public, result.Value.Visibility);
        Assert.False(result.Value.EffectiveIsPublic);
        Assert.Equal(4, result.Value.SortOrder);
        Assert.Equal([4, 2], result.Value.ItemTemplateIds);
        await using var context = fixture.CreateContext();
        var links = await context.CategoryItemTemplates.Where(link => link.CategoryId == 2).OrderBy(link => link.SortOrder).ToListAsync();
        Assert.Equal([4, 2], links.Select(link => link.ItemTemplateId));
        Assert.Equal([0, 1], links.Select(link => link.SortOrder));
        Assert.Equal(7, (await context.Categories.FindAsync(2))!.ParentCategoryId);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Update_OmittedAssignmentsArePreserved_AndExplicitEmptyClears(bool clear)
    {
        var result = await Service().UpdateAsync(2, 1, new UpdateCategoryRequest { Name = "Edited", ItemTemplateIds = clear ? [] : null });
        Assert.Null(result.Error);
        Assert.Equal(clear ? [] : new[] { 1, 2 }, result.Value!.ItemTemplateIds);
        await using var context = fixture.CreateContext();
        Assert.Equal(clear ? [] : new[] { 2, 5 }, await context.CategoryItemTemplates.Where(link => link.CategoryId == 2)
            .OrderBy(link => link.SortOrder).Select(link => link.SortOrder).ToListAsync());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(999)]
    public async Task Create_RejectsSystemForeignAndMissingParents_WithoutCreatingCategory(int parentId)
    {
        var result = await Service().CreateAsync(1, new CreateCategoryRequest { CollectionId = 1, Name = "New", ParentCategoryId = parentId });
        Assert.Equal(CategoryWriteFailure.Invalid, result.Error!.Kind);
        await using var context = fixture.CreateContext();
        Assert.Equal(10, await context.Categories.CountAsync());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(999)]
    public async Task Update_RejectsInvalidParentsAndCycles_WithoutChangingFieldsOrTemplates(int parentId)
    {
        var result = await Service().UpdateAsync(2, 1, new UpdateCategoryRequest { Name = "Rejected", ParentCategoryId = parentId, ItemTemplateIds = [] });
        Assert.Equal(CategoryWriteFailure.Invalid, result.Error!.Kind);
        await AssertOriginalRootAsync();
    }

    [Theory]
    [InlineData(3)]
    [InlineData(999)]
    public async Task Create_RejectsMissingOrForeignCollections(int collectionId)
    {
        var result = await Service().CreateAsync(1, new CreateCategoryRequest { CollectionId = collectionId, Name = "Rejected" });
        Assert.Equal(CategoryWriteFailure.Invalid, result.Error!.Kind);
    }

    [Fact]
    public async Task Update_RejectsCategoryWhoseCollectionBelongsToAnotherWorkspace()
    {
        var result = await Service().UpdateAsync(8, 1, new UpdateCategoryRequest { Name = "Rejected" });
        Assert.Equal(CategoryWriteFailure.NotFound, result.Error!.Kind);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(999)]
    public async Task UpdateAndDelete_RejectForeignOrMissingCategories(int categoryId)
    {
        Assert.Equal(CategoryWriteFailure.NotFound, (await Service().UpdateAsync(categoryId, 1, new UpdateCategoryRequest { Name = "Rejected" })).Error!.Kind);
        Assert.Equal(CategoryWriteFailure.NotFound, (await Service().DeleteAsync(categoryId, 1)).Error!.Kind);
    }

    [Fact]
    public async Task SystemCategory_CannotBeChangedDeletedOrReordered()
    {
        Assert.Equal(CategoryWriteFailure.Forbidden, (await Service().UpdateAsync(1, 1, new UpdateCategoryRequest { Name = "Rejected" })).Error!.Kind);
        Assert.Equal(CategoryWriteFailure.Forbidden, (await Service().DeleteAsync(1, 1)).Error!.Kind);
        Assert.Equal(CategoryWriteFailure.Forbidden, (await Service().ReorderAsync(1, Reorder((1, 10)))).Error!.Kind);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(999)]
    public async Task InvalidTemplates_RejectEntireCreateAndUpdate(int templateId)
    {
        var service = Service();
        Assert.Equal(CategoryWriteFailure.Invalid, (await service.CreateAsync(1, new CreateCategoryRequest
        { CollectionId = 1, Name = "Rejected", ItemTemplateIds = [templateId] })).Error!.Kind);
        Assert.Equal(CategoryWriteFailure.Invalid, (await service.UpdateAsync(2, 1, new UpdateCategoryRequest
        { Name = "Rejected", ItemTemplateIds = [templateId] })).Error!.Kind);
        await AssertOriginalRootAsync();
        await using var context = fixture.CreateContext();
        Assert.Equal(10, await context.Categories.CountAsync());
    }

    [Fact]
    public async Task ReservedName_IsCheckedAfterTrimming_ForCreateAndUpdate()
    {
        var service = Service();
        Assert.Equal(CategoryWriteFailure.Invalid, (await service.CreateAsync(1, new CreateCategoryRequest
        { CollectionId = 1, Name = " unASSIGNED Items " })).Error!.Kind);
        Assert.Equal(CategoryWriteFailure.Invalid, (await service.UpdateAsync(2, 1, new UpdateCategoryRequest
        { Name = " unASSIGNED Items " })).Error!.Kind);
        await AssertOriginalRootAsync();
    }

    [Fact]
    public async Task ExistingCyclicParent_IsRejected_ButMovingToRootRepairsIt()
    {
        await using (var context = fixture.CreateContext())
        {
            (await context.Categories.FindAsync(2))!.ParentCategoryId = 3;
            await context.SaveChangesAsync();
        }
        var service = Service();
        Assert.Equal(CategoryWriteFailure.Invalid, (await service.CreateAsync(1, new CreateCategoryRequest
        { CollectionId = 1, Name = "Rejected", ParentCategoryId = 3 })).Error!.Kind);
        var repaired = await service.UpdateAsync(2, 1, new UpdateCategoryRequest { Name = "Root" });
        Assert.Null(repaired.Error);
        Assert.Null(repaired.Value!.ParentCategoryId);
        Assert.True(repaired.Value.EffectiveIsPublic);
    }

    private async Task AssertOriginalRootAsync()
    {
        await using var context = fixture.CreateContext();
        var root = (await context.Categories.FindAsync(2))!;
        Assert.Equal("Root", root.Name);
        Assert.Null(root.ParentCategoryId);
        Assert.Equal([1, 2], await context.CategoryItemTemplates.Where(link => link.CategoryId == 2)
            .OrderBy(link => link.SortOrder).Select(link => link.ItemTemplateId).ToListAsync());
    }

    [Fact]
    public async Task Reorder_UpdatesOnlyRequestedCategories_AndReturnsTheirCollection()
    {
        var result = await Service().ReorderAsync(1, Reorder((2, 8), (3, 1)));
        Assert.Null(result.Error);
        Assert.Equal(1, result.Value);
        await using var context = fixture.CreateContext();
        Assert.Equal(8, (await context.Categories.FindAsync(2))!.SortOrder);
        Assert.Equal(1, (await context.Categories.FindAsync(3))!.SortOrder);
        Assert.Equal(0, (await context.Categories.FindAsync(1))!.SortOrder);
        Assert.Equal(0, (await context.Categories.FindAsync(5))!.SortOrder);
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("duplicate")]
    [InlineData("negative")]
    [InlineData("missing")]
    [InlineData("foreign")]
    [InlineData("mixed")]
    [InlineData("mismatched")]
    public async Task Reorder_InvalidBatchMakesNoPartialChanges(string reason)
    {
        var request = reason switch
        {
            "empty" => Reorder(), "duplicate" => Reorder((2, 0), (2, 1)), "negative" => Reorder((2, -1)),
            "missing" => Reorder((2, 0), (999, 1)), "foreign" => Reorder((2, 0), (6, 1)),
            "mixed" => Reorder((2, 0), (5, 1)), _ => Reorder((2, 0), (8, 1))
        };
        Assert.Equal(CategoryWriteFailure.Invalid, (await Service().ReorderAsync(1, request)).Error!.Kind);
        await using var context = fixture.CreateContext();
        Assert.Equal(4, (await context.Categories.FindAsync(2))!.SortOrder);
    }

    [Theory]
    [InlineData(2, 3, null)]
    [InlineData(3, 4, 2)]
    public async Task Delete_PromotesChildrenAndMovesItemsWithoutAffectingOtherCollections(int categoryId, int childId, int? expectedParent)
    {
        var result = await Service().DeleteAsync(categoryId, 1);
        Assert.Null(result.Error);
        Assert.True(result.Value);
        await using var context = fixture.CreateContext();
        Assert.Null(await context.Categories.FindAsync(categoryId));
        Assert.Equal(expectedParent, (await context.Categories.FindAsync(childId))!.ParentCategoryId);
        Assert.All(await context.Items.ToListAsync(), item => Assert.Equal(categoryId == 2 ? 1 : 2, item.CategoryId));
        Assert.False(await context.CategoryItemTemplates.AnyAsync(link => link.CategoryId == categoryId));
        Assert.NotNull(await context.Categories.FindAsync(5));
        Assert.NotNull(await context.Categories.FindAsync(6));
    }

    [Fact]
    public async Task Delete_WithoutUnassignedCategory_LeavesItemsUncategorized()
    {
        await using (var context = fixture.CreateContext())
        {
            context.Categories.Remove((await context.Categories.FindAsync(1))!);
            await context.SaveChangesAsync();
        }
        Assert.Null((await Service().DeleteAsync(2, 1)).Error);
        await using var check = fixture.CreateContext();
        Assert.All(await check.Items.ToListAsync(), item => Assert.Null(item.CategoryId));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Delete_RepairsCyclesByPromotingChildrenToRoot(int parentId)
    {
        await using (var context = fixture.CreateContext())
        {
            (await context.Categories.FindAsync(2))!.ParentCategoryId = parentId;
            await context.SaveChangesAsync();
        }
        Assert.Null((await Service().DeleteAsync(2, 1)).Error);
        await using var check = fixture.CreateContext();
        Assert.Null((await check.Categories.FindAsync(3))!.ParentCategoryId);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Delete_RejectsForeignReferencesWithoutMovingOrNullingThem(bool itemReference, bool otherWorkspace)
    {
        await using (var context = fixture.CreateContext())
        {
            if (itemReference)
                context.Items.Add(new Item { Id = 40, Name = "Inconsistent reference", CategoryId = 2,
                    WorkspaceId = otherWorkspace ? 2 : 1, CollectionId = otherWorkspace ? 3 : 2 });
            else (await context.Categories.FindAsync(otherWorkspace ? 6 : 5))!.ParentCategoryId = 2;
            await context.SaveChangesAsync();
        }
        Assert.Equal(CategoryWriteFailure.Conflict, (await Service().DeleteAsync(2, 1)).Error!.Kind);
        await AssertOriginalRootAsync();
        await using var check = fixture.CreateContext();
        if (itemReference) Assert.Equal(2, (await check.Items.FindAsync(40))!.CategoryId);
        else Assert.Equal(2, (await check.Categories.FindAsync(otherWorkspace ? 6 : 5))!.ParentCategoryId);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AssignmentFailure_RollsBackCategoryAndAllAssignments(bool create)
    {
        await using var context = fixture.CreateContext();
        await context.Database.ExecuteSqlRawAsync("""
            ALTER TABLE "CategoryItemTemplates" ADD CONSTRAINT "CategoryAssignmentRollbackTest" CHECK ("ItemTemplateId" <> 4)
            """);
        try
        {
            var commands = new SuccessfulCommands();
            var service = ServiceWith(commands);
            await Assert.ThrowsAsync<DbUpdateException>(() => create
                ? service.CreateAsync(1, new CreateCategoryRequest { CollectionId = 1, Name = "Rejected", ItemTemplateIds = [4] })
                : service.UpdateAsync(2, 1, new UpdateCategoryRequest { Name = "Rejected", ItemTemplateIds = [4] }));
            Assert.Contains(commands.Sql, sql => sql.Contains(create ? "INSERT INTO \"Categories\"" : "UPDATE \"Categories\""));
            Assert.Equal(10, await context.Categories.CountAsync());
            await AssertOriginalRootAsync();
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("ALTER TABLE \"CategoryItemTemplates\" DROP CONSTRAINT \"CategoryAssignmentRollbackTest\"");
        }
    }

    [Fact]
    public async Task DeleteFailure_RollsBackChildPromotionAndItemMoves()
    {
        await using var context = fixture.CreateContext();
        await context.Database.ExecuteSqlRawAsync("""
            ALTER TABLE "Items" ADD CONSTRAINT "CategoryDeletionRollbackTest" CHECK ("Id" <> 2 OR "CategoryId" = 2)
            """);
        try
        {
            var commands = new SuccessfulCommands();
            await Assert.ThrowsAsync<DbUpdateException>(() => ServiceWith(commands).DeleteAsync(2, 1));
            Assert.Contains(commands.Sql, sql => sql.Contains("UPDATE \"Categories\""));
            Assert.Contains(commands.Sql, sql => sql.Contains("UPDATE \"Items\""));
            await AssertOriginalRootAsync();
            Assert.Equal(2, (await context.Categories.FindAsync(3))!.ParentCategoryId);
            Assert.All(await context.Items.ToListAsync(), item => Assert.Equal(2, item.CategoryId));
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("ALTER TABLE \"Items\" DROP CONSTRAINT \"CategoryDeletionRollbackTest\"");
        }
    }

    [Fact]
    public async Task ConcurrentMoves_CannotCommitACycle_AndRejectedMoveCanBeRevalidated()
    {
        var service = ServiceWith(new BothEditsLoaded());
        var firstRequest = new UpdateCategoryRequest { Name = "Root", ParentCategoryId = 10 };
        var secondRequest = new UpdateCategoryRequest { Name = "Other root", ParentCategoryId = 2 };
        var results = await Task.WhenAll(service.UpdateAsync(2, 1, firstRequest), service.UpdateAsync(10, 1, secondRequest))
            .WaitAsync(TimeSpan.FromSeconds(20));

        Assert.Single(results, result => result.Error is null);
        Assert.Equal(CategoryWriteFailure.Conflict, Assert.Single(results, result => result.Error != null).Error!.Kind);
        await using var context = fixture.CreateContext();
        var root = (await context.Categories.FindAsync(2))!;
        var other = (await context.Categories.FindAsync(10))!;
        Assert.True((root.ParentCategoryId == 10) ^ (other.ParentCategoryId == 2));
        var retry = results[0].Error != null ? await Service().UpdateAsync(2, 1, firstRequest) : await Service().UpdateAsync(10, 1, secondRequest);
        Assert.Equal(CategoryWriteFailure.Invalid, retry.Error!.Kind);
    }

    [Theory]
    [InlineData("serialization")]
    [InlineData("wrapped")]
    [InlineData("deadlock")]
    [InlineData("concurrency")]
    public async Task DatabaseConflicts_AreReturnedAsRetryableRejections(string kind)
    {
        var serialization = new PostgresException("Injected", "ERROR", "ERROR", PostgresErrorCodes.SerializationFailure);
        Exception failure = kind switch
        {
            "serialization" => serialization,
            "wrapped" => new DbUpdateException("Injected", serialization),
            "deadlock" => new PostgresException("Injected", "ERROR", "ERROR", PostgresErrorCodes.DeadlockDetected),
            _ => new DbUpdateConcurrencyException("Injected")
        };
        var result = await ServiceWith(new FailingSave(failure)).UpdateAsync(2, 1, new UpdateCategoryRequest { Name = "Rejected" });
        Assert.Equal(CategoryWriteFailure.Conflict, result.Error!.Kind);
        await AssertOriginalRootAsync();
    }

    [Fact]
    public async Task UnexpectedFailures_AreNotMisreportedAsConflicts()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() => ServiceWith(new FailingSave(new InvalidOperationException("Injected")))
            .UpdateAsync(2, 1, new UpdateCategoryRequest { Name = "Rejected" }));
        await AssertOriginalRootAsync();
    }

    private CategoryWriteService ServiceWith(IInterceptor interceptor) => new(new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString, options => options.MaxBatchSize(1))
            .AddInterceptors(interceptor).Options));

    [Fact]
    public async Task CancelledRequest_DoesNotCreateCategory()
    {
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Service().CreateAsync(1,
            new CreateCategoryRequest { CollectionId = 1, Name = "Cancelled" }, new CancellationToken(true)));
        await using var context = fixture.CreateContext();
        Assert.Equal(10, await context.Categories.CountAsync());
    }

    [Fact]
    public async Task InvalidLegacyAssignments_MustBeReplacedBeforeSaving()
    {
        await using (var context = fixture.CreateContext())
        {
            context.CategoryItemTemplates.Add(new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 3 });
            await context.SaveChangesAsync();
        }
        var service = Service();
        Assert.Equal(CategoryWriteFailure.Invalid, (await service.UpdateAsync(2, 1, new UpdateCategoryRequest { Name = "Rejected" })).Error!.Kind);
        var repaired = await service.UpdateAsync(2, 1, new UpdateCategoryRequest { Name = "Repaired", ItemTemplateIds = [1, 2] });
        Assert.Null(repaired.Error);
        Assert.Equal([1, 2], repaired.Value!.ItemTemplateIds);
    }

    private sealed class SuccessfulCommands : DbCommandInterceptor
    {
        public List<string> Sql { get; } = [];
        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
            DbDataReader result, CancellationToken cancellationToken = default)
        { Sql.Add(command.CommandText); return ValueTask.FromResult(result); }
    }

    private sealed class BothEditsLoaded : SaveChangesInterceptor
    {
        private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _arrived;
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _arrived) == 2) _ready.SetResult();
            await _ready.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            return result;
        }
    }

    private sealed class FailingSave(Exception failure) : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default) => ValueTask.FromException<InterceptionResult<int>>(failure);
    }

    private static ReorderCategoriesRequest Reorder(params (int Id, int Order)[] entries) => new()
    { Categories = entries.Select(entry => new CategorySortOrderEntry { CategoryId = entry.Id, SortOrder = entry.Order }).ToList() };
}

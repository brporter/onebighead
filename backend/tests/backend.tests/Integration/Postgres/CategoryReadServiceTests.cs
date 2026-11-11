using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Categories;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class CategoryReadServiceTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private CategoryReadService CreateService() => new(fixture.CreateContextFactory());

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.AddRange(new Workspace { Id = 1, Name = "Own" }, new Workspace { Id = 2, Name = "Other" });
        context.Collections.AddRange(
            new Collection { Id = 1, WorkspaceId = 1, Name = "Private", Slug = "private" },
            new Collection { Id = 2, WorkspaceId = 1, Name = "Public", Slug = "public", Visibility = Visibility.Public },
            new Collection { Id = 3, WorkspaceId = 2, Name = "Foreign", Slug = "foreign", Visibility = Visibility.Public },
            new Collection { Id = 4, WorkspaceId = 1, Name = "Empty", Slug = "empty" });
        context.Categories.AddRange(
            Category(1, 1, "First collection", 1),
            Category(10, 2, "Root", 3),
            Category(11, 2, "Child", 0, 10),
            Category(12, 2, "Grandchild", 2, 11),
            Category(13, 2, "Private root", 1, visibility: Visibility.Private),
            Category(14, 2, "Private descendant", 1, 13),
            Category(15, 2, "Same name", 4),
            Category(16, 2, "Same name", 4),
            Category(30, 3, "Foreign", 0, workspaceId: 2),
            Category(31, 3, "Mismatched collection workspace", 0),
            Category(32, 2, "Mismatched category workspace", 0, workspaceId: 2));
        context.ItemTemplates.AddRange(
            Template(1, null), Template(2, 1), Template(3, 2), Template(4, null), Template(5, 1));
        context.CategoryItemTemplates.AddRange(
            Link(1, 5, 0), Link(10, 4, 0), Link(10, 2, 1), Link(10, 1, 1), Link(10, 3, -1),
            Link(11, 2, 0), Link(11, 1, 1), Link(30, 3, 0));
        await context.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static Category Category(int id, int collectionId, string name, int sortOrder,
        int? parentId = null, int workspaceId = 1, Visibility visibility = Visibility.Public) => new()
    {
        Id = id, WorkspaceId = workspaceId, CollectionId = collectionId, Name = name,
        Description = $"Description {id}", SortOrder = sortOrder, ParentCategoryId = parentId,
        Visibility = visibility, IsSystem = id == 1
    };

    private static ItemTemplate Template(int id, int? workspaceId) => new()
    {
        Id = id, WorkspaceId = workspaceId, Name = $"Template {id}", TemplateKey = Guid.NewGuid()
    };

    private static CategoryItemTemplate Link(int categoryId, int templateId, int sortOrder) => new()
    {
        CategoryId = categoryId, ItemTemplateId = templateId, SortOrder = sortOrder
    };

    [Fact]
    public async Task AllCollections_UseTheirOwnVisibilityAndAssignments_AndStableOrdering()
    {
        var rows = Assert.IsAssignableFrom<IReadOnlyList<OneBigHead.Server.DTOs.CategoryResponse>>(
            await CreateService().GetAllAsync(1));

        Assert.Equal([11, 1, 14, 13, 12, 10, 15, 16], rows.Select(row => row.CategoryId));
        var firstCollection = rows.Single(row => row.CategoryId == 1);
        Assert.False(firstCollection.EffectiveIsPublic);
        Assert.True(firstCollection.IsSystem);
        Assert.Equal("Description 1", firstCollection.Description);
        Assert.Equal([5], firstCollection.ItemTemplateIds);
        var otherCollection = rows.Single(row => row.CategoryId == 10);
        Assert.True(otherCollection.EffectiveIsPublic);
        Assert.Equal([4, 1, 2], otherCollection.ItemTemplateIds);
        Assert.All(rows, row => Assert.Equal(1, row.WorkspaceId));
        Assert.False(rows.Single(row => row.CategoryId == 14).EffectiveIsPublic);
        Assert.True(rows.Single(row => row.CategoryId == 12).EffectiveIsPublic);
    }

    [Fact]
    public async Task CollectionFilter_PreservesHierarchy_WithoutOtherCollections()
    {
        var rows = (await CreateService().GetAllAsync(1, 2))!;

        Assert.Equal([11, 14, 13, 12, 10, 15, 16], rows.Select(row => row.CategoryId));
        Assert.All(rows, row => Assert.Equal(2, row.CollectionId));
        Assert.Equal(10, rows[0].ParentCategoryId);
        Assert.Equal(Visibility.Public, rows[0].Visibility);
        Assert.Equal(0, rows[0].SortOrder);
        Assert.True(rows[0].EffectiveIsPublic);
    }

    [Theory]
    [InlineData(1, 3)]
    [InlineData(1, 999)]
    [InlineData(2, 2)]
    public async Task CollectionFilter_ReturnsMissingForUnknownOrForeignCollection(int workspaceId, int collectionId)
    {
        Assert.Null(await CreateService().GetAllAsync(workspaceId, collectionId));
    }

    [Fact]
    public async Task EmptyResults_AreDifferentFromMissingCollections()
    {
        Assert.Empty((await CreateService().GetAllAsync(1, 4))!);
        Assert.Empty((await CreateService().GetAllAsync(999))!);
    }

    [Theory]
    [InlineData(10, true, null)]
    [InlineData(11, true, 10)]
    [InlineData(12, true, 11)]
    [InlineData(14, false, 13)]
    [InlineData(1, false, null)]
    public async Task Detail_UsesActualCollectionAndAncestors(int categoryId, bool visible, int? parentId)
    {
        var category = await CreateService().GetByIdAsync(categoryId, 1);

        Assert.NotNull(category);
        Assert.Equal(categoryId, category.CategoryId);
        Assert.Equal(visible, category.EffectiveIsPublic);
        Assert.Equal(parentId, category.ParentCategoryId);
        Assert.Equal(categoryId == 1 ? 1 : 2, category.CollectionId);
        if (categoryId == 10) Assert.Equal([4, 1, 2], category.ItemTemplateIds);
    }

    [Theory]
    [InlineData(30)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(999)]
    public async Task DetailAndTemplates_RejectMissingOrForeignResources(int categoryId)
    {
        var service = CreateService();
        Assert.Null(await service.GetByIdAsync(categoryId, 1));
        Assert.Null(await service.GetInheritedTemplateIdsAsync(categoryId, 1));
    }

    [Fact]
    public async Task Templates_PreserveChildFirstOrder_DeduplicateAndInheritMultipleLevels()
    {
        var service = CreateService();
        Assert.Equal([4, 1, 2], await service.GetInheritedTemplateIdsAsync(10, 1));
        Assert.Equal([2, 1, 4], await service.GetInheritedTemplateIdsAsync(11, 1));
        Assert.Equal([2, 1, 4], await service.GetInheritedTemplateIdsAsync(12, 1));
        Assert.Empty((await service.GetInheritedTemplateIdsAsync(13, 1))!);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(30)]
    [InlineData(32)]
    public async Task CrossCollectionOrWorkspaceParent_CannotSupplyVisibilityOrTemplates(int parentId)
    {
        await using var context = fixture.CreateContext();
        var category = await context.Categories.SingleAsync(category => category.Id == 10);
        category.ParentCategoryId = parentId;
        await context.SaveChangesAsync();

        Assert.False((await CreateService().GetByIdAsync(10, 1))!.EffectiveIsPublic);
        Assert.Equal([4, 1, 2], await CreateService().GetInheritedTemplateIdsAsync(10, 1));
    }

    [Theory]
    [InlineData(10)]
    [InlineData(12)]
    public async Task ExistingCycles_ArePrivate_AndTemplateInheritanceTerminates(int parentId)
    {
        await using var context = fixture.CreateContext();
        var root = await context.Categories.SingleAsync(category => category.Id == 10);
        root.ParentCategoryId = parentId;
        await context.SaveChangesAsync();

        var service = CreateService();
        Assert.False((await service.GetByIdAsync(12, 1))!.EffectiveIsPublic);
        Assert.Equal([2, 1, 4], await service.GetInheritedTemplateIdsAsync(12, 1).WaitAsync(TimeSpan.FromSeconds(5)));
        var rows = (await service.GetAllAsync(1, 2))!;
        Assert.All(rows.Where(row => row.CategoryId is 10 or 11 or 12), row => Assert.False(row.EffectiveIsPublic));
        Assert.True(rows.Single(row => row.CategoryId == 15).EffectiveIsPublic);
    }

    [Fact]
    public async Task Reads_DoNotPersistComputedVisibility_OrCacheAcrossRequests()
    {
        var service = CreateService();
        Assert.True((await service.GetByIdAsync(10, 1))!.EffectiveIsPublic);
        await using var context = fixture.CreateContext();
        var collection = await context.Collections.SingleAsync(collection => collection.Id == 2);
        collection.Visibility = Visibility.Private;
        await context.SaveChangesAsync();

        Assert.False((await service.GetByIdAsync(10, 1))!.EffectiveIsPublic);
        Assert.Equal(Visibility.Public, (await context.Categories.SingleAsync(category => category.Id == 10)).Visibility);
    }
}

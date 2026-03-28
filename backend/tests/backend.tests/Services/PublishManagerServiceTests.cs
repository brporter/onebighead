using backend.DTOs;
using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;

namespace backend.tests.Services;

[Trait("Category", "Unit")]
public class PublishManagerServiceTests
{
    private readonly Mock<IItemRepository> _mockItemRepository = new();
    private readonly Mock<ICategoryRepository> _mockCategoryRepository = new();
    private readonly Mock<ICollectionRepository> _mockCollectionRepository = new();
    private readonly Mock<IWorkspaceRepository> _mockWorkspaceRepository = new();
    private readonly PublishManagerService _service;

    public PublishManagerServiceTests()
    {
        _service = new PublishManagerService(
            _mockItemRepository.Object,
            _mockCategoryRepository.Object,
            _mockCollectionRepository.Object,
            _mockWorkspaceRepository.Object);
    }

    #region ComputeEffectiveVisibility — Category

    [Fact]
    public void ComputeEffectiveVisibility_Category_PublicCollectionPublicCategory_IsPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(category, collection, new List<Category> { category });

        Assert.True(category.EffectiveIsPublic);
    }

    [Fact]
    public void ComputeEffectiveVisibility_Category_PrivateCollection_IsNotPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(category, collection, new List<Category> { category });

        Assert.False(category.EffectiveIsPublic);
    }

    [Fact]
    public void ComputeEffectiveVisibility_Category_PrivateParent_IsNotPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var parent = new Category { Id = 1, Name = "Parent", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };
        var child = new Category { Id = 2, Name = "Child", WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Visibility = Visibility.Public };
        var all = new List<Category> { parent, child };

        _service.ComputeEffectiveVisibility(all, collection);

        Assert.False(parent.EffectiveIsPublic);
        Assert.False(child.EffectiveIsPublic);
    }

    [Fact]
    public void ComputeEffectiveVisibility_Category_PublicParent_IsPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var parent = new Category { Id = 1, Name = "Parent", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };
        var child = new Category { Id = 2, Name = "Child", WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Visibility = Visibility.Public };
        var all = new List<Category> { parent, child };

        _service.ComputeEffectiveVisibility(all, collection);

        Assert.True(parent.EffectiveIsPublic);
        Assert.True(child.EffectiveIsPublic);
    }

    #endregion

    #region ComputeEffectiveVisibility — Item

    [Fact]
    public void ComputeEffectiveVisibility_Item_AllPublic_IsPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public, EffectiveIsPublic = true };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(item, collection, category);

        Assert.True(item.EffectiveIsPublic);
    }

    [Fact]
    public void ComputeEffectiveVisibility_Item_PrivateCategory_IsNotPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private, EffectiveIsPublic = false };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(item, collection, category);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void ComputeEffectiveVisibility_Item_NullCategory_UsesCollectionOnly()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(item, collection, null);

        Assert.True(item.EffectiveIsPublic);
    }

    #endregion

    #region Preflight — Publish

    [Fact]
    public async Task Preflight_Publish_AllAncestorsPublicAndSlugSet_ReturnsReady()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(category);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { category });

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        });

        Assert.True(result.Ready);
        Assert.Empty(result.Requirements);
    }

    [Fact]
    public async Task Preflight_Publish_Item_PrivateCategoryAndCollection_ReturnsBothRequirements()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(category);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { category });

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        });

        Assert.False(result.Ready);
        Assert.Equal(2, result.Requirements.Count);
        Assert.Contains(result.Requirements, r => r is CollectionNotPublicRequirement c && c.CollectionId == 1);
        Assert.Contains(result.Requirements, r => r is CategoryNotPublicRequirement c && c.CategoryId == 1);
    }

    [Fact]
    public async Task Preflight_Publish_NoSlug_ReturnsSlugRequirement()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = null };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        });

        Assert.False(result.Ready);
        Assert.Single(result.Requirements);
        Assert.IsType<WorkspaceSlugRequiredRequirement>(result.Requirements[0]);
    }

    [Fact]
    public async Task Preflight_Publish_DeduplicatesAcrossMultipleItems()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };
        var item1 = new Item { Id = 1, Name = "Item1", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Private };
        var item2 = new Item { Id = 2, Name = "Item2", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item1);
        _mockItemRepository.Setup(r => r.GetByIdAsync(2, 1)).ReturnsAsync(item2);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(category);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { category });

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef>
            {
                new() { Type = "item", Id = 1 },
                new() { Type = "item", Id = 2 },
            }
        });

        Assert.False(result.Ready);
        // Should have exactly 1 collection + 1 category requirement, not 2 of each
        Assert.Equal(2, result.Requirements.Count);
    }

    [Fact]
    public async Task Preflight_Publish_Category_WithPrivateParentCategory_ReturnsParentRequirement()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var parent = new Category { Id = 1, Name = "Parent", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };
        var child = new Category { Id = 2, Name = "Child", WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(2, 1)).ReturnsAsync(child);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { parent, child });

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "category", Id = 2 } }
        });

        Assert.False(result.Ready);
        Assert.Single(result.Requirements);
        Assert.IsType<CategoryNotPublicRequirement>(result.Requirements[0]);
        Assert.Equal(1, ((CategoryNotPublicRequirement)result.Requirements[0]).CategoryId);
    }

    [Fact]
    public async Task Preflight_Publish_Collection_ReturnsOnlySlugIfNeeded()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = null };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "collection", Id = 1 } }
        });

        Assert.False(result.Ready);
        Assert.Single(result.Requirements);
        Assert.IsType<WorkspaceSlugRequiredRequirement>(result.Requirements[0]);
    }

    #endregion

    #region Preflight — Unpublish

    [Fact]
    public async Task Preflight_Unpublish_Category_ReturnsImpactWarning()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Public };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, 1)).ReturnsAsync(new List<Item> { item });

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Unpublish,
            Entities = new List<EntityRef> { new() { Type = "category", Id = 1 } }
        });

        Assert.False(result.Ready);
        Assert.Single(result.Requirements);
        var req = Assert.IsType<UnpublishWillHideChildrenRequirement>(result.Requirements[0]);
        Assert.Equal("category", req.EntityType);
        Assert.Equal(1, req.AffectedPublicItems);
    }

    [Fact]
    public async Task Preflight_Unpublish_Item_AlwaysReady()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Unpublish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        });

        Assert.True(result.Ready);
        Assert.Empty(result.Requirements);
    }

    #endregion
}

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
}

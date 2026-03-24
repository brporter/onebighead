using OneBigHead.Server.Models;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class VisibilityServiceTests
{
    private readonly VisibilityService _service;

    public VisibilityServiceTests()
    {
        _service = new VisibilityService();
    }

    #region Category Visibility Tests

    [Fact]
    public void Category_Private_With_Private_Collection_Is_Not_EffectivelyPublic()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Private };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Private };
        var categories = new List<Category> { category };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(category.EffectiveIsPublic);
    }

    [Fact]
    public void Category_Public_With_Private_Collection_Is_Not_EffectivelyPublic()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Private };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Public };
        var categories = new List<Category> { category };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(category.EffectiveIsPublic);
    }

    [Fact]
    public void Category_Private_With_Public_Collection_Is_Not_EffectivelyPublic()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Private };
        var categories = new List<Category> { category };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(category.EffectiveIsPublic);
    }

    [Fact]
    public void Category_Public_With_Public_Collection_Is_EffectivelyPublic()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Public };
        var categories = new List<Category> { category };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.True(category.EffectiveIsPublic);
    }

    [Fact]
    public void Category_WithPrivateParent_IsPrivate()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var parentCategory = new Category { Id = 1, CollectionId = 1, Name = "Parent", Visibility = Visibility.Private };
        var childCategory = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, Visibility = Visibility.Public };
        var categories = new List<Category> { parentCategory, childCategory };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(childCategory.EffectiveIsPublic);
    }

    [Fact]
    public void Category_WithPublicParent_CanBePublic()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var parentCategory = new Category { Id = 1, CollectionId = 1, Name = "Parent", Visibility = Visibility.Public };
        var childCategory = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, Visibility = Visibility.Public };
        var categories = new List<Category> { parentCategory, childCategory };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.True(childCategory.EffectiveIsPublic);
    }

    [Fact]
    public void Category_WithPublicParent_CanOverrideToPrivate()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var parentCategory = new Category { Id = 1, CollectionId = 1, Name = "Parent", Visibility = Visibility.Public };
        var childCategory = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, Visibility = Visibility.Private };
        var categories = new List<Category> { parentCategory, childCategory };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(childCategory.EffectiveIsPublic);
    }

    [Fact]
    public void Category_DeepHierarchy_AllPublic_PropagatesVisibility()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var root = new Category { Id = 1, CollectionId = 1, Name = "Root", Visibility = Visibility.Public };
        var child = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, Visibility = Visibility.Public };
        var grandChild = new Category { Id = 3, CollectionId = 1, Name = "GrandChild", ParentCategoryId = 2, Visibility = Visibility.Public };
        var categories = new List<Category> { root, child, grandChild };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.True(root.EffectiveIsPublic);
        Assert.True(child.EffectiveIsPublic);
        Assert.True(grandChild.EffectiveIsPublic);
    }

    [Fact]
    public void Category_DeepHierarchy_PrivateBreaksChain()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var root = new Category { Id = 1, CollectionId = 1, Name = "Root", Visibility = Visibility.Public };
        var child = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, Visibility = Visibility.Private };
        var grandChild = new Category { Id = 3, CollectionId = 1, Name = "GrandChild", ParentCategoryId = 2, Visibility = Visibility.Public };
        var categories = new List<Category> { root, child, grandChild };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.True(root.EffectiveIsPublic);
        Assert.False(child.EffectiveIsPublic);
        Assert.False(grandChild.EffectiveIsPublic);
    }

    [Fact]
    public void Category_SingleCategory_ComputeOverload_Works()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(category, collection, new List<Category>());

        Assert.True(category.EffectiveIsPublic);
    }

    [Fact]
    public void Category_SingleCategory_ComputeOverload_Private()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Private };

        _service.ComputeEffectiveVisibility(category, collection, new List<Category>());

        Assert.False(category.EffectiveIsPublic);
    }

    [Fact]
    public void Category_SingleCategory_WithParent_UsesLookup()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var parent = new Category { Id = 1, CollectionId = 1, Name = "Parent", Visibility = Visibility.Private, EffectiveIsPublic = false };
        var child = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(child, collection, new List<Category> { parent });

        Assert.False(child.EffectiveIsPublic);
    }

    #endregion

    #region Item Visibility Tests

    [Fact]
    public void Item_Private_With_Private_Collection_IsPrivate()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Private };
        var item = new Item { Id = 1, CollectionId = 1, Name = "Item", Visibility = Visibility.Private };
        var items = new List<Item> { item };
        var categories = new List<Category>();

        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_Public_With_Private_Collection_IsPrivate()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Private };
        var item = new Item { Id = 1, CollectionId = 1, Name = "Item", Visibility = Visibility.Public };
        var items = new List<Item> { item };
        var categories = new List<Category>();

        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_Public_With_Public_Collection_IsPublic()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var item = new Item { Id = 1, CollectionId = 1, Name = "Item", Visibility = Visibility.Public };
        var items = new List<Item> { item };
        var categories = new List<Category>();

        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.True(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_Private_With_Public_Collection_IsPrivate()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var item = new Item { Id = 1, CollectionId = 1, Name = "Item", Visibility = Visibility.Private };
        var items = new List<Item> { item };
        var categories = new List<Category>();

        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithPrivateCategory_IsPrivate()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Private };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 1, Name = "Item", Visibility = Visibility.Public };
        var categories = new List<Category> { category };
        var items = new List<Item> { item };

        _service.ComputeEffectiveVisibility(categories, collection);
        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithPublicCategory_CanBePublic()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Public };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 1, Name = "Item", Visibility = Visibility.Public };
        var categories = new List<Category> { category };
        var items = new List<Item> { item };

        _service.ComputeEffectiveVisibility(categories, collection);
        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.True(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithPublicCategory_CanOverrideToPrivate()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Public };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 1, Name = "Item", Visibility = Visibility.Private };
        var categories = new List<Category> { category };
        var items = new List<Item> { item };

        _service.ComputeEffectiveVisibility(categories, collection);
        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithNestedPrivateCategory_IsPrivate()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var parentCategory = new Category { Id = 1, CollectionId = 1, Name = "Parent", Visibility = Visibility.Public };
        var childCategory = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, Visibility = Visibility.Private };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 2, Name = "Item", Visibility = Visibility.Public };
        var categories = new List<Category> { parentCategory, childCategory };
        var items = new List<Item> { item };

        _service.ComputeEffectiveVisibility(categories, collection);
        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_SingleItem_ComputeOverload_Public()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var item = new Item { Id = 1, CollectionId = 1, Name = "Item", Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(item, collection, null);

        Assert.True(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_SingleItem_ComputeOverload_Private()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var item = new Item { Id = 1, CollectionId = 1, Name = "Item", Visibility = Visibility.Private };

        _service.ComputeEffectiveVisibility(item, collection, null);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_SingleItem_WithPrivateCategory_IsPrivate()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Private, EffectiveIsPublic = false };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 1, Name = "Item", Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(item, collection, category);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_SingleItem_WithPublicCategory_IsPublic()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Name = "Test", Visibility = Visibility.Public };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", Visibility = Visibility.Public, EffectiveIsPublic = true };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 1, Name = "Item", Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(item, collection, category);

        Assert.True(item.EffectiveIsPublic);
    }

    #endregion
}

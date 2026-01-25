using backend.Models;
using backend.Services;

namespace backend.Tests.Services;

public class VisibilityServiceTests
{
    private readonly VisibilityService _service;

    public VisibilityServiceTests()
    {
        _service = new VisibilityService();
    }

    #region Category Visibility Tests

    [Fact]
    public void Category_WithPrivateCollection_IsPrivate()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = false };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", IsPublicOverride = null };
        var categories = new List<Category> { category };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(category.EffectiveIsPublic);
    }

    [Fact]
    public void Category_WithPrivateCollection_CannotOverrideToPublic()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = false };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", IsPublicOverride = true };
        var categories = new List<Category> { category };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(category.EffectiveIsPublic);
    }

    [Fact]
    public void Category_WithPublicCollection_InheritsPublic()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", IsPublicOverride = null };
        var categories = new List<Category> { category };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.True(category.EffectiveIsPublic);
    }

    [Fact]
    public void Category_WithPublicCollection_CanOverrideToPrivate()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", IsPublicOverride = false };
        var categories = new List<Category> { category };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(category.EffectiveIsPublic);
    }

    [Fact]
    public void Category_WithPrivateParent_IsPrivate()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var parentCategory = new Category { Id = 1, CollectionId = 1, Name = "Parent", IsPublicOverride = false };
        var childCategory = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, IsPublicOverride = null };
        var categories = new List<Category> { parentCategory, childCategory };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(childCategory.EffectiveIsPublic);
    }

    [Fact]
    public void Category_WithPrivateParent_CannotOverrideToPublic()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var parentCategory = new Category { Id = 1, CollectionId = 1, Name = "Parent", IsPublicOverride = false };
        var childCategory = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, IsPublicOverride = true };
        var categories = new List<Category> { parentCategory, childCategory };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(childCategory.EffectiveIsPublic);
    }

    [Fact]
    public void Category_WithPublicParent_InheritsPublic()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var parentCategory = new Category { Id = 1, CollectionId = 1, Name = "Parent", IsPublicOverride = true };
        var childCategory = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, IsPublicOverride = null };
        var categories = new List<Category> { parentCategory, childCategory };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.True(childCategory.EffectiveIsPublic);
    }

    [Fact]
    public void Category_WithPublicParent_CanOverrideToPrivate()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var parentCategory = new Category { Id = 1, CollectionId = 1, Name = "Parent", IsPublicOverride = true };
        var childCategory = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, IsPublicOverride = false };
        var categories = new List<Category> { parentCategory, childCategory };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.False(childCategory.EffectiveIsPublic);
    }

    [Fact]
    public void Category_DeepHierarchy_PropagatesVisibility()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var root = new Category { Id = 1, CollectionId = 1, Name = "Root", IsPublicOverride = true };
        var child = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, IsPublicOverride = null };
        var grandChild = new Category { Id = 3, CollectionId = 1, Name = "GrandChild", ParentCategoryId = 2, IsPublicOverride = null };
        var categories = new List<Category> { root, child, grandChild };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.True(root.EffectiveIsPublic);
        Assert.True(child.EffectiveIsPublic);
        Assert.True(grandChild.EffectiveIsPublic);
    }

    [Fact]
    public void Category_DeepHierarchy_PrivateBreaksChain()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var root = new Category { Id = 1, CollectionId = 1, Name = "Root", IsPublicOverride = true };
        var child = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, IsPublicOverride = false };
        var grandChild = new Category { Id = 3, CollectionId = 1, Name = "GrandChild", ParentCategoryId = 2, IsPublicOverride = null };
        var categories = new List<Category> { root, child, grandChild };

        _service.ComputeEffectiveVisibility(categories, collection);

        Assert.True(root.EffectiveIsPublic);
        Assert.False(child.EffectiveIsPublic);
        Assert.False(grandChild.EffectiveIsPublic);
    }

    #endregion

    #region Item Visibility Tests

    [Fact]
    public void Item_WithPrivateCollection_IsPrivate()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = false };
        var item = new Item { Id = 1, CollectionId = 1, Name = "Item", IsPublicOverride = null };
        var items = new List<Item> { item };
        var categories = new List<Category>();

        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithPrivateCollection_CannotOverrideToPublic()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = false };
        var item = new Item { Id = 1, CollectionId = 1, Name = "Item", IsPublicOverride = true };
        var items = new List<Item> { item };
        var categories = new List<Category>();

        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithPublicCollection_InheritsPublic()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var item = new Item { Id = 1, CollectionId = 1, Name = "Item", IsPublicOverride = null };
        var items = new List<Item> { item };
        var categories = new List<Category>();

        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.True(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithPublicCollection_CanOverrideToPrivate()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var item = new Item { Id = 1, CollectionId = 1, Name = "Item", IsPublicOverride = false };
        var items = new List<Item> { item };
        var categories = new List<Category>();

        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithPrivateCategory_IsPrivate()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", IsPublicOverride = false };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 1, Name = "Item", IsPublicOverride = null };
        var categories = new List<Category> { category };
        var items = new List<Item> { item };

        _service.ComputeEffectiveVisibility(categories, collection);
        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithPrivateCategory_CannotOverrideToPublic()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", IsPublicOverride = false };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 1, Name = "Item", IsPublicOverride = true };
        var categories = new List<Category> { category };
        var items = new List<Item> { item };

        _service.ComputeEffectiveVisibility(categories, collection);
        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithPublicCategory_InheritsPublic()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", IsPublicOverride = true };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 1, Name = "Item", IsPublicOverride = null };
        var categories = new List<Category> { category };
        var items = new List<Item> { item };

        _service.ComputeEffectiveVisibility(categories, collection);
        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.True(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithPublicCategory_CanOverrideToPrivate()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var category = new Category { Id = 1, CollectionId = 1, Name = "Category", IsPublicOverride = true };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 1, Name = "Item", IsPublicOverride = false };
        var categories = new List<Category> { category };
        var items = new List<Item> { item };

        _service.ComputeEffectiveVisibility(categories, collection);
        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void Item_WithNestedPrivateCategory_IsPrivate()
    {
        var collection = new Collection { Id = 1, TenantId = 1, Name = "Test", IsPublic = true };
        var parentCategory = new Category { Id = 1, CollectionId = 1, Name = "Parent", IsPublicOverride = true };
        var childCategory = new Category { Id = 2, CollectionId = 1, Name = "Child", ParentCategoryId = 1, IsPublicOverride = false };
        var item = new Item { Id = 1, CollectionId = 1, CategoryId = 2, Name = "Item", IsPublicOverride = null };
        var categories = new List<Category> { parentCategory, childCategory };
        var items = new List<Item> { item };

        _service.ComputeEffectiveVisibility(categories, collection);
        _service.ComputeEffectiveVisibility(items, collection, categories);

        Assert.False(item.EffectiveIsPublic);
    }

    #endregion
}

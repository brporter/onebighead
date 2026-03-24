using OneBigHead.Server.Models;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Services;

public class PublishVisibilityServiceTests
{
    private readonly VisibilityService _service = new();

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishItem_SetsItemPublic()
    {
        var item = new Item { Visibility = Visibility.Private };
        var result = _service.PublishItem(item, collection: new Collection { Visibility = Visibility.Public }, category: null);
        Assert.Equal(Visibility.Public, item.Visibility);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishItem_PromotesPrivateCategory()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var category = new Category { Id = 5, Name = "Vintage Watches", Visibility = Visibility.Private };
        var item = new Item { Visibility = Visibility.Private, CategoryId = 5 };
        var result = _service.PublishItem(item, collection, category);
        Assert.Equal(Visibility.Public, item.Visibility);
        Assert.Equal(Visibility.Public, category.Visibility);
        Assert.Single(result.Promoted);
        Assert.Equal("category", result.Promoted[0].Type);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishItem_PromotesPrivateCategoryAndCollection()
    {
        var collection = new Collection { Id = 1, Name = "My Collection", Visibility = Visibility.Private };
        var category = new Category { Id = 5, Name = "Vintage Watches", Visibility = Visibility.Private };
        var item = new Item { Visibility = Visibility.Private, CategoryId = 5 };
        var result = _service.PublishItem(item, collection, category);
        Assert.Equal(Visibility.Public, item.Visibility);
        Assert.Equal(Visibility.Public, category.Visibility);
        Assert.Equal(Visibility.Public, collection.Visibility);
        Assert.Equal(2, result.Promoted.Count);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishItem_NoCategory_PromotesCollection()
    {
        var collection = new Collection { Id = 1, Name = "My Collection", Visibility = Visibility.Private };
        var item = new Item { Visibility = Visibility.Private };
        var result = _service.PublishItem(item, collection, category: null);
        Assert.Equal(Visibility.Public, item.Visibility);
        Assert.Equal(Visibility.Public, collection.Visibility);
        Assert.Single(result.Promoted);
        Assert.Equal("collection", result.Promoted[0].Type);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCategory_WithChildren_PublishesAllItems()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var category = new Category { Id = 5, Name = "Watches", Visibility = Visibility.Private };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Private, CategoryId = 5 },
            new() { Id = 2, Visibility = Visibility.Private, CategoryId = 5 },
            new() { Id = 3, Visibility = Visibility.Public, CategoryId = 5 },
        };
        var result = _service.PublishCategory(category, collection, items, allCategories: new List<Category> { category }, includeChildren: true);
        Assert.Equal(Visibility.Public, category.Visibility);
        Assert.All(items, i => Assert.Equal(Visibility.Public, i.Visibility));
        Assert.Equal(2, result.ChildrenPublished);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCategory_WithChildren_PublishesSubcategoriesAndTheirItems()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var parentCategory = new Category { Id = 5, Name = "Watches", Visibility = Visibility.Private };
        var childCategory = new Category { Id = 6, Name = "Dive Watches", Visibility = Visibility.Private, ParentCategoryId = 5 };
        var allCategories = new List<Category> { parentCategory, childCategory };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Private, CategoryId = 5 },
            new() { Id = 2, Visibility = Visibility.Private, CategoryId = 6 },
        };
        var result = _service.PublishCategory(parentCategory, collection, items, allCategories, includeChildren: true);
        Assert.Equal(Visibility.Public, parentCategory.Visibility);
        Assert.Equal(Visibility.Public, childCategory.Visibility);
        Assert.All(items, i => Assert.Equal(Visibility.Public, i.Visibility));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCategory_WithoutChildren_OnlyPublishesCategory()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var category = new Category { Id = 5, Name = "Watches", Visibility = Visibility.Private };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Private, CategoryId = 5 },
        };
        var result = _service.PublishCategory(category, collection, items, allCategories: new List<Category> { category }, includeChildren: false);
        Assert.Equal(Visibility.Public, category.Visibility);
        Assert.Equal(Visibility.Private, items[0].Visibility);
        Assert.Equal(0, result.ChildrenPublished);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void UnpublishCategory_DoesNotCascadeToChildren()
    {
        var category = new Category { Id = 5, Name = "Watches", Visibility = Visibility.Public };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Public, CategoryId = 5 },
            new() { Id = 2, Visibility = Visibility.Public, CategoryId = 5 },
        };
        _service.UnpublishEntity(category);
        Assert.Equal(Visibility.Private, category.Visibility);
        Assert.All(items, i => Assert.Equal(Visibility.Public, i.Visibility));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void UnpublishPreview_ReturnsAffectedCounts()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var category = new Category { Id = 5, Visibility = Visibility.Public };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Public, CategoryId = 5 },
            new() { Id = 2, Visibility = Visibility.Public, CategoryId = 5 },
            new() { Id = 3, Visibility = Visibility.Private, CategoryId = 5 },
        };
        var preview = _service.GetUnpublishPreview(category, items, new List<Category>(), collection);
        Assert.Equal(2, preview.AffectedPublicItems);
        Assert.Equal(0, preview.AffectedPublicCategories);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void RequiresSlugSetup_WhenWorkspaceHasNoSlug()
    {
        var workspace = new Workspace { Slug = null };
        Assert.True(_service.RequiresSlugSetup(workspace));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void RequiresSlugSetup_False_WhenWorkspaceHasSlug()
    {
        var workspace = new Workspace { Slug = "my-gallery" };
        Assert.False(_service.RequiresSlugSetup(workspace));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishItem_ReturnsPublishedEntityInfo()
    {
        var item = new Item { Id = 10, Name = "Test Item", Visibility = Visibility.Private };
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var result = _service.PublishItem(item, collection, category: null);
        Assert.Equal("item", result.Published.Type);
        Assert.Equal(10, result.Published.Id);
        Assert.Equal("Test Item", result.Published.Name);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCategory_ReturnsPublishedEntityInfo()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var category = new Category { Id = 5, Name = "Watches", Visibility = Visibility.Private };
        var result = _service.PublishCategory(category, collection, new List<Item>(), new List<Category> { category }, includeChildren: false);
        Assert.Equal("category", result.Published.Type);
        Assert.Equal(5, result.Published.Id);
        Assert.Equal("Watches", result.Published.Name);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCollection_SetsCollectionPublic()
    {
        var collection = new Collection { Id = 1, Name = "My Collection", Visibility = Visibility.Private };
        var result = _service.PublishCollection(collection, new List<Category>(), new List<Item>(), includeChildren: false);
        Assert.Equal(Visibility.Public, collection.Visibility);
        Assert.Equal("collection", result.Published.Type);
        Assert.Equal(1, result.Published.Id);
        Assert.Equal("My Collection", result.Published.Name);
        Assert.Equal(0, result.ChildrenPublished);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCollection_WithChildren_PublishesAllCategoriesAndItems()
    {
        var collection = new Collection { Id = 1, Name = "My Collection", Visibility = Visibility.Private };
        var categories = new List<Category>
        {
            new() { Id = 5, Name = "Cat1", Visibility = Visibility.Private },
            new() { Id = 6, Name = "Cat2", Visibility = Visibility.Public },
        };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Private },
            new() { Id = 2, Visibility = Visibility.Private },
            new() { Id = 3, Visibility = Visibility.Public },
        };
        var result = _service.PublishCollection(collection, categories, items, includeChildren: true);
        Assert.Equal(Visibility.Public, collection.Visibility);
        Assert.All(categories, c => Assert.Equal(Visibility.Public, c.Visibility));
        Assert.All(items, i => Assert.Equal(Visibility.Public, i.Visibility));
        Assert.Equal(3, result.ChildrenPublished); // 1 category + 2 items changed
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void UnpublishEntity_Collection_SetsPrivate()
    {
        var collection = new Collection { Id = 1, Name = "My Collection", Visibility = Visibility.Public };
        _service.UnpublishEntity(collection);
        Assert.Equal(Visibility.Private, collection.Visibility);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void UnpublishEntity_Item_SetsPrivate()
    {
        var item = new Item { Id = 1, Visibility = Visibility.Public };
        _service.UnpublishEntity(item);
        Assert.Equal(Visibility.Private, item.Visibility);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void GetUnpublishPreview_WithChildCategories_CountsThem()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var category = new Category { Id = 5, Visibility = Visibility.Public };
        var childCategories = new List<Category>
        {
            new() { Id = 6, Visibility = Visibility.Public, ParentCategoryId = 5 },
            new() { Id = 7, Visibility = Visibility.Private, ParentCategoryId = 5 },
        };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Public, CategoryId = 5 },
        };
        var preview = _service.GetUnpublishPreview(category, items, childCategories, collection);
        Assert.Equal(1, preview.AffectedPublicItems);
        Assert.Equal(1, preview.AffectedPublicCategories);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void GetUnpublishPreviewForCollection_ReturnsCorrectCounts()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var categories = new List<Category>
        {
            new() { Id = 5, Visibility = Visibility.Public },
            new() { Id = 6, Visibility = Visibility.Public },
            new() { Id = 7, Visibility = Visibility.Private },
        };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Public },
            new() { Id = 2, Visibility = Visibility.Private },
        };
        var preview = _service.GetUnpublishPreviewForCollection(collection, categories, items);
        Assert.Equal(1, preview.AffectedPublicItems);
        Assert.Equal(2, preview.AffectedPublicCategories);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCategory_PromotesPrivateCollection()
    {
        var collection = new Collection { Id = 1, Name = "My Collection", Visibility = Visibility.Private };
        var category = new Category { Id = 5, Name = "Watches", Visibility = Visibility.Private };
        var result = _service.PublishCategory(category, collection, new List<Item>(), new List<Category> { category }, includeChildren: false);
        Assert.Equal(Visibility.Public, collection.Visibility);
        Assert.Single(result.Promoted);
        Assert.Equal("collection", result.Promoted[0].Type);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCategory_PromotesPrivateParentCategories()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var parentCategory = new Category { Id = 3, Name = "Parent", Visibility = Visibility.Private };
        var childCategory = new Category { Id = 5, Name = "Child", Visibility = Visibility.Private, ParentCategoryId = 3 };
        var allCategories = new List<Category> { parentCategory, childCategory };
        var result = _service.PublishCategory(childCategory, collection, new List<Item>(), allCategories, includeChildren: false);
        Assert.Equal(Visibility.Public, childCategory.Visibility);
        Assert.Equal(Visibility.Public, parentCategory.Visibility);
        Assert.Single(result.Promoted);
        Assert.Equal("category", result.Promoted[0].Type);
        Assert.Equal(3, result.Promoted[0].Id);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishItem_AlreadyPublic_StillReturnsResult()
    {
        var item = new Item { Id = 1, Name = "Already Public", Visibility = Visibility.Public };
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var result = _service.PublishItem(item, collection, category: null);
        Assert.Equal(Visibility.Public, item.Visibility);
        Assert.Equal("item", result.Published.Type);
        Assert.Empty(result.Promoted);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void RequiresSlugSetup_EmptyString_ReturnsFalse()
    {
        var workspace = new Workspace { Slug = "" };
        Assert.False(_service.RequiresSlugSetup(workspace));
    }
}

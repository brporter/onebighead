using OneBigHead.Server.Models;
using OneBigHead.Server.Services;

namespace backend.tests.Unit.Services;

[Trait("Category", "Unit")]
public class VisibilityServiceTests
{
    private readonly VisibilityService service = new();
    [Theory]
    [InlineData("public", true)] [InlineData("item-private", false)] [InlineData("collection-private", false)]
    [InlineData("wrong-workspace", false)] [InlineData("wrong-collection", false)] [InlineData("missing-category", false)]
    [InlineData("wrong-category", false)] [InlineData("category-workspace", false)] [InlineData("category-collection", false)]
    [InlineData("category-private", false)] [InlineData("uncategorized", true)]
    public void Item_RequiresMatchingPublicCollectionAndCategory(string scenario, bool expected)
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Visibility = Visibility.Public };
        var item = new Item { Id = 1, WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Public, EffectiveIsPublic = true };
        Category? category = new() { Id = 1, WorkspaceId = 1, CollectionId = 1, EffectiveIsPublic = true };
        switch (scenario)
        {
            case "item-private": item.Visibility = Visibility.Private; break;
            case "collection-private": collection.Visibility = Visibility.Private; break;
            case "wrong-workspace": item.WorkspaceId = 2; break;
            case "wrong-collection": item.CollectionId = 2; break;
            case "missing-category": category = null; break;
            case "wrong-category": category.Id = 2; break;
            case "category-workspace": category.WorkspaceId = 2; break;
            case "category-collection": category.CollectionId = 2; break;
            case "category-private": category.EffectiveIsPublic = false; break;
            case "uncategorized": item.CategoryId = null; category = null; break;
        }
        service.ComputeEffectiveVisibility(item, collection, category);
        Assert.Equal(expected, item.EffectiveIsPublic);
    }
    [Fact]
    public void CategoryProjection_UsesCurrentEntityAndCompleteAncestors_AndListProjectionFailsClosed()
    {
        var collection = new Collection { Id = 1, WorkspaceId = 1, Visibility = Visibility.Public };
        var parent = new Category { Id = 1, WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };
        var current = new Category { Id = 2, WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Visibility = Visibility.Public };
        service.ComputeEffectiveVisibility(current, collection, [parent, new Category { Id = 2 }]);
        Assert.True(current.EffectiveIsPublic);
        parent.Visibility = Visibility.Private;
        service.ComputeEffectiveVisibility(new[] { parent, current }, collection);
        Assert.False(current.EffectiveIsPublic);
        var items = new[] {
            new Item { WorkspaceId = 1, CollectionId = 1, CategoryId = 2, Visibility = Visibility.Public },
            new Item { WorkspaceId = 1, CollectionId = 1, CategoryId = 999, Visibility = Visibility.Public },
            new Item { WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public }
        };
        service.ComputeEffectiveVisibility(items, collection, [parent, current]);
        Assert.Equal([false, false, true], items.Select(item => item.EffectiveIsPublic));
    }
}

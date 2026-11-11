using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Categories;

namespace OneBigHead.Server.Services;

/// <summary>Read-only visibility projection; this service has no publication or persistence capability.</summary>
public sealed class VisibilityService : IVisibilityService
{
    public void ComputeEffectiveVisibility(Category category, Collection collection, IEnumerable<Category> allCategories)
    {
        var lookup = allCategories.ToDictionary(value => value.Id);
        lookup[category.Id] = category;
        CategoryVisibility.Apply(lookup.Values, collection);
    }

    public void ComputeEffectiveVisibility(IEnumerable<Category> categories, Collection collection) => CategoryVisibility.Apply(categories, collection);

    public void ComputeEffectiveVisibility(Item item, Collection collection, Category? category) =>
        item.EffectiveIsPublic = item.WorkspaceId == collection.WorkspaceId && item.CollectionId == collection.Id &&
            item.Visibility == Visibility.Public && collection.EffectiveIsPublic &&
            (item.CategoryId is null || category is not null && category.Id == item.CategoryId && category.WorkspaceId == item.WorkspaceId &&
                category.CollectionId == item.CollectionId && category.EffectiveIsPublic);

    public void ComputeEffectiveVisibility(IEnumerable<Item> items, Collection collection, IEnumerable<Category> categories)
    {
        var lookup = categories.ToDictionary(category => category.Id);
        foreach (var item in items)
        {
            var category = item.CategoryId is int id ? lookup.GetValueOrDefault(id) : null;
            ComputeEffectiveVisibility(item, collection, category);
        }
    }
}

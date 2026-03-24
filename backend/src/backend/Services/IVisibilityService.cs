using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services;

[GenerateTracingProxy]
public interface IVisibilityService
{
    void ComputeEffectiveVisibility(Category category, Collection collection, IEnumerable<Category> allCategories);
    void ComputeEffectiveVisibility(Item item, Collection collection, Category? category);
    void ComputeEffectiveVisibility(IEnumerable<Category> categories, Collection collection);
    void ComputeEffectiveVisibility(IEnumerable<Item> items, Collection collection, IEnumerable<Category> categories);
    PublishResult PublishItem(Item item, Collection collection, Category? category);
    PublishResult PublishCategory(Category category, Collection collection, IEnumerable<Item> categoryItems, IEnumerable<Category> allCategories, bool includeChildren);
    PublishResult PublishCollection(Collection collection, IEnumerable<Category> categories, IEnumerable<Item> items, bool includeChildren);
    void UnpublishEntity(Category category);
    void UnpublishEntity(Collection collection);
    void UnpublishEntity(Item item);
    UnpublishPreview GetUnpublishPreview(Category category, IEnumerable<Item> items, IEnumerable<Category> childCategories, Collection collection);
    UnpublishPreview GetUnpublishPreviewForCollection(Collection collection, IEnumerable<Category> categories, IEnumerable<Item> items);
    bool RequiresSlugSetup(Workspace workspace);
}
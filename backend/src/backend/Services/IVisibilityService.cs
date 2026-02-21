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
}
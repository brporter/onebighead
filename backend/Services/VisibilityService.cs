using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services;

public interface IVisibilityService
{
    void ComputeEffectiveVisibility(Category category, Collection collection, IEnumerable<Category> allCategories);
    void ComputeEffectiveVisibility(Item item, Collection collection, Category? category, IEnumerable<Category> allCategories);
    void ComputeEffectiveVisibility(IEnumerable<Category> categories, Collection collection);
    void ComputeEffectiveVisibility(IEnumerable<Item> items, Collection collection, IEnumerable<Category> categories);
}

public class VisibilityService : IVisibilityService
{
    public void ComputeEffectiveVisibility(Category category, Collection collection, IEnumerable<Category> allCategories)
    {
        // Build lookup for O(1) parent access
        // Materialize to list first to avoid multiple enumeration if input is a lazy IEnumerable
        var categoryLookup = allCategories as IDictionary<int, Category> 
            ?? (allCategories as IList<Category> ?? allCategories.ToList()).ToDictionary(c => c.Id);
        ComputeEffectiveVisibilityInternal(category, collection, categoryLookup);
    }

    private static void ComputeEffectiveVisibilityInternal(Category category, Collection collection, IDictionary<int, Category> categoryLookup)
    {
        // If collection is not public, category cannot be public
        if (!collection.IsPublic)
        {
            category.EffectiveIsPublic = false;
            return;
        }

        // If has parent category, check parent's effective visibility
        if (category.ParentCategoryId.HasValue)
        {
            if (categoryLookup.TryGetValue(category.ParentCategoryId.Value, out var parentCategory) && !parentCategory.EffectiveIsPublic)
            {
                // Parent is private, so child must be private (cannot override to public)
                category.EffectiveIsPublic = false;
                return;
            }
        }

        // If override is set, use it
        if (category.IsPublicOverride.HasValue)
        {
            category.EffectiveIsPublic = category.IsPublicOverride.Value;
            return;
        }

        // Inherit from parent category or collection
        if (category.ParentCategoryId.HasValue && categoryLookup.TryGetValue(category.ParentCategoryId.Value, out var parent))
        {
            category.EffectiveIsPublic = parent.EffectiveIsPublic;
        }
        else
        {
            category.EffectiveIsPublic = collection.IsPublic;
        }
    }

    public void ComputeEffectiveVisibility(Item item, Collection collection, Category? category, IEnumerable<Category> allCategories)
    {
        // If collection is not public, item cannot be public
        if (!collection.IsPublic)
        {
            item.EffectiveIsPublic = false;
            return;
        }

        // If has category, check category's effective visibility
        if (category != null)
        {
            if (!category.EffectiveIsPublic)
            {
                item.EffectiveIsPublic = false;
                return;
            }
        }

        // If override is set, use it
        if (item.IsPublicOverride.HasValue)
        {
            item.EffectiveIsPublic = item.IsPublicOverride.Value;
            return;
        }

        // Inherit from category or collection
        item.EffectiveIsPublic = category?.EffectiveIsPublic ?? collection.IsPublic;
    }

    public void ComputeEffectiveVisibility(IEnumerable<Category> categories, Collection collection)
    {
        var categoryList = categories.ToList();
        var categoryLookup = categoryList.ToDictionary(c => c.Id);
        
        // Build a dependency order (parents before children)
        var processed = new HashSet<int>();
        var ordered = new List<Category>();
        
        void ProcessCategory(Category cat)
        {
            if (processed.Contains(cat.Id)) return;
            
            if (cat.ParentCategoryId.HasValue && categoryLookup.TryGetValue(cat.ParentCategoryId.Value, out var parent))
            {
                if (!processed.Contains(parent.Id))
                {
                    ProcessCategory(parent);
                }
            }
            
            processed.Add(cat.Id);
            ordered.Add(cat);
        }
        
        foreach (var category in categoryList)
        {
            ProcessCategory(category);
        }
        
        // Now compute in order using the lookup for O(1) access
        foreach (var category in ordered)
        {
            ComputeEffectiveVisibilityInternal(category, collection, categoryLookup);
        }
    }

    public void ComputeEffectiveVisibility(IEnumerable<Item> items, Collection collection, IEnumerable<Category> categories)
    {
        // Build lookup for O(1) category access
        var categoryLookup = categories.ToDictionary(c => c.Id);
        
        foreach (var item in items)
        {
            var category = item.CategoryId.HasValue && categoryLookup.TryGetValue(item.CategoryId.Value, out var cat)
                ? cat 
                : null;
            ComputeEffectiveVisibility(item, collection, category, categories);
        }
    }
}

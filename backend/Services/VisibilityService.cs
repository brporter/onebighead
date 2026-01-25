using backend.Models;

namespace backend.Services;

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
        // If collection is not public, category cannot be public
        if (!collection.IsPublic)
        {
            category.EffectiveIsPublic = false;
            return;
        }

        // If has parent category, check parent's effective visibility
        if (category.ParentCategoryId.HasValue)
        {
            var parentCategory = allCategories.FirstOrDefault(c => c.Id == category.ParentCategoryId.Value);
            if (parentCategory != null && !parentCategory.EffectiveIsPublic)
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
        if (category.ParentCategoryId.HasValue)
        {
            var parentCategory = allCategories.FirstOrDefault(c => c.Id == category.ParentCategoryId.Value);
            category.EffectiveIsPublic = parentCategory?.EffectiveIsPublic ?? collection.IsPublic;
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
        
        // Build a dependency order (parents before children)
        var processed = new HashSet<int>();
        var ordered = new List<Category>();
        
        void ProcessCategory(Category cat)
        {
            if (processed.Contains(cat.Id)) return;
            
            if (cat.ParentCategoryId.HasValue)
            {
                var parent = categoryList.FirstOrDefault(c => c.Id == cat.ParentCategoryId.Value);
                if (parent != null && !processed.Contains(parent.Id))
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
        
        // Now compute in order
        foreach (var category in ordered)
        {
            ComputeEffectiveVisibility(category, collection, categoryList);
        }
    }

    public void ComputeEffectiveVisibility(IEnumerable<Item> items, Collection collection, IEnumerable<Category> categories)
    {
        var categoryList = categories.ToList();
        
        foreach (var item in items)
        {
            var category = item.CategoryId.HasValue 
                ? categoryList.FirstOrDefault(c => c.Id == item.CategoryId.Value) 
                : null;
            ComputeEffectiveVisibility(item, collection, category, categoryList);
        }
    }
}

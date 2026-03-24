using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services;

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
        if (!collection.EffectiveIsPublic)
        {
            category.EffectiveIsPublic = false;
            return;
        }

        // If has parent category, check parent's effective visibility
        if (category.ParentCategoryId.HasValue)
        {
            if (categoryLookup.TryGetValue(category.ParentCategoryId.Value, out var parentCategory) && !parentCategory.EffectiveIsPublic)
            {
                // Parent is private, so child must be private
                category.EffectiveIsPublic = false;
                return;
            }
        }

        // Entity is effectively public only when its own Visibility is Public
        // (and all ancestors are public, which was checked above)
        category.EffectiveIsPublic = category.Visibility == Visibility.Public;
    }

    public void ComputeEffectiveVisibility(Item item, Collection collection, Category? category)
    {
        // If collection is not public, item cannot be public
        if (!collection.EffectiveIsPublic)
        {
            item.EffectiveIsPublic = false;
            return;
        }

        // If has category, check category's effective visibility
        if (category != null && !category.EffectiveIsPublic)
        {
            item.EffectiveIsPublic = false;
            return;
        }

        // Entity is effectively public only when its own Visibility is Public
        // (and all ancestors are public, which was checked above)
        item.EffectiveIsPublic = item.Visibility == Visibility.Public;
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
            ComputeEffectiveVisibility(item, collection, category);
        }
    }

    public PublishResult PublishItem(Item item, Collection collection, Category? category)
    {
        var promoted = new List<PublishedEntityInfo>();

        // Promote collection if private
        if (collection.Visibility == Visibility.Private)
        {
            collection.Visibility = Visibility.Public;
            promoted.Add(new PublishedEntityInfo { Type = "collection", Id = collection.Id, Name = collection.Name });
        }

        // Promote category if private
        if (category != null && category.Visibility == Visibility.Private)
        {
            category.Visibility = Visibility.Public;
            promoted.Add(new PublishedEntityInfo { Type = "category", Id = category.Id, Name = category.Name });
        }

        // Set item to public
        item.Visibility = Visibility.Public;

        return new PublishResult
        {
            Published = new PublishedEntityInfo { Type = "item", Id = item.Id ?? 0, Name = item.Name },
            Promoted = promoted,
        };
    }

    public PublishResult PublishCategory(Category category, Collection collection, IEnumerable<Item> categoryItems, IEnumerable<Category> allCategories, bool includeChildren)
    {
        var promoted = new List<PublishedEntityInfo>();
        var categoryList = allCategories as IList<Category> ?? allCategories.ToList();
        var categoryLookup = categoryList.ToDictionary(c => c.Id);

        // Promote collection if private
        if (collection.Visibility == Visibility.Private)
        {
            collection.Visibility = Visibility.Public;
            promoted.Add(new PublishedEntityInfo { Type = "collection", Id = collection.Id, Name = collection.Name });
        }

        // Promote parent categories up the chain
        PromoteParentCategories(category, categoryLookup, promoted);

        // Set this category to public
        category.Visibility = Visibility.Public;

        int childrenPublished = 0;

        if (includeChildren)
        {
            // Find all descendant category IDs (including this category)
            var descendantCategoryIds = new HashSet<int> { category.Id };
            CollectDescendantCategoryIds(category.Id, categoryList, descendantCategoryIds);

            // Publish all descendant subcategories
            foreach (var cat in categoryList)
            {
                if (cat.Id != category.Id && descendantCategoryIds.Contains(cat.Id) && cat.Visibility == Visibility.Private)
                {
                    cat.Visibility = Visibility.Public;
                    childrenPublished++;
                }
            }

            // Publish all items in descendant categories
            foreach (var item in categoryItems)
            {
                if (item.CategoryId.HasValue && descendantCategoryIds.Contains(item.CategoryId.Value) && item.Visibility == Visibility.Private)
                {
                    item.Visibility = Visibility.Public;
                    childrenPublished++;
                }
            }
        }

        return new PublishResult
        {
            Published = new PublishedEntityInfo { Type = "category", Id = category.Id, Name = category.Name },
            Promoted = promoted,
            ChildrenPublished = childrenPublished,
        };
    }

    public PublishResult PublishCollection(Collection collection, IEnumerable<Category> categories, IEnumerable<Item> items, bool includeChildren)
    {
        collection.Visibility = Visibility.Public;

        int childrenPublished = 0;

        if (includeChildren)
        {
            foreach (var cat in categories)
            {
                if (cat.Visibility == Visibility.Private)
                {
                    cat.Visibility = Visibility.Public;
                    childrenPublished++;
                }
            }

            foreach (var item in items)
            {
                if (item.Visibility == Visibility.Private)
                {
                    item.Visibility = Visibility.Public;
                    childrenPublished++;
                }
            }
        }

        return new PublishResult
        {
            Published = new PublishedEntityInfo { Type = "collection", Id = collection.Id, Name = collection.Name },
            ChildrenPublished = childrenPublished,
        };
    }

    public void UnpublishEntity(Category category)
    {
        category.Visibility = Visibility.Private;
    }

    public void UnpublishEntity(Collection collection)
    {
        collection.Visibility = Visibility.Private;
    }

    public void UnpublishEntity(Item item)
    {
        item.Visibility = Visibility.Private;
    }

    public UnpublishPreview GetUnpublishPreview(Category category, IEnumerable<Item> items, IEnumerable<Category> childCategories, Collection collection)
    {
        return new UnpublishPreview
        {
            AffectedPublicItems = items.Count(i => i.Visibility == Visibility.Public),
            AffectedPublicCategories = childCategories.Count(c => c.Visibility == Visibility.Public),
        };
    }

    public UnpublishPreview GetUnpublishPreviewForCollection(Collection collection, IEnumerable<Category> categories, IEnumerable<Item> items)
    {
        return new UnpublishPreview
        {
            AffectedPublicItems = items.Count(i => i.Visibility == Visibility.Public),
            AffectedPublicCategories = categories.Count(c => c.Visibility == Visibility.Public),
        };
    }

    public bool RequiresSlugSetup(Workspace workspace)
    {
        return workspace.Slug == null;
    }

    private static void PromoteParentCategories(Category category, IDictionary<int, Category> categoryLookup, List<PublishedEntityInfo> promoted)
    {
        if (!category.ParentCategoryId.HasValue)
            return;

        if (!categoryLookup.TryGetValue(category.ParentCategoryId.Value, out var parent))
            return;

        // Recurse first to promote ancestors before this parent
        PromoteParentCategories(parent, categoryLookup, promoted);

        if (parent.Visibility == Visibility.Private)
        {
            parent.Visibility = Visibility.Public;
            promoted.Add(new PublishedEntityInfo { Type = "category", Id = parent.Id, Name = parent.Name });
        }
    }

    private static void CollectDescendantCategoryIds(int parentId, IList<Category> allCategories, HashSet<int> result)
    {
        foreach (var cat in allCategories)
        {
            if (cat.ParentCategoryId == parentId && !result.Contains(cat.Id))
            {
                result.Add(cat.Id);
                CollectDescendantCategoryIds(cat.Id, allCategories, result);
            }
        }
    }
}

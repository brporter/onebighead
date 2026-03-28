using backend.DTOs;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services;

public class PublishManagerService : IPublishManagerService
{
    private readonly IItemRepository _itemRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly ICollectionRepository _collectionRepository;
    private readonly IWorkspaceRepository _workspaceRepository;

    public PublishManagerService(
        IItemRepository itemRepository,
        ICategoryRepository categoryRepository,
        ICollectionRepository collectionRepository,
        IWorkspaceRepository workspaceRepository)
    {
        _itemRepository = itemRepository;
        _categoryRepository = categoryRepository;
        _collectionRepository = collectionRepository;
        _workspaceRepository = workspaceRepository;
    }

    // Preflight and Execute are implemented in subsequent tasks
    public Task<PreflightResponse> PreflightAsync(int workspaceId, PreflightRequest request)
    {
        throw new NotImplementedException();
    }

    public Task<ExecuteResponse> ExecuteAsync(int workspaceId, ExecuteRequest request)
    {
        throw new NotImplementedException();
    }

    #region Effective Visibility Computation

    public void ComputeEffectiveVisibility(Category category, Collection collection, IEnumerable<Category> allCategories)
    {
        var categoryLookup = allCategories as IDictionary<int, Category>
            ?? (allCategories as IList<Category> ?? allCategories.ToList()).ToDictionary(c => c.Id);
        ComputeEffectiveVisibilityInternal(category, collection, categoryLookup);
    }

    public void ComputeEffectiveVisibility(Item item, Collection collection, Category? category)
    {
        if (!collection.EffectiveIsPublic)
        {
            item.EffectiveIsPublic = false;
            return;
        }

        if (category != null && !category.EffectiveIsPublic)
        {
            item.EffectiveIsPublic = false;
            return;
        }

        item.EffectiveIsPublic = item.Visibility == Visibility.Public;
    }

    public void ComputeEffectiveVisibility(IEnumerable<Category> categories, Collection collection)
    {
        var categoryList = categories.ToList();
        var categoryLookup = categoryList.ToDictionary(c => c.Id);

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

        foreach (var category in ordered)
        {
            ComputeEffectiveVisibilityInternal(category, collection, categoryLookup);
        }
    }

    public void ComputeEffectiveVisibility(IEnumerable<Item> items, Collection collection, IEnumerable<Category> categories)
    {
        var categoryLookup = categories.ToDictionary(c => c.Id);

        foreach (var item in items)
        {
            var category = item.CategoryId.HasValue && categoryLookup.TryGetValue(item.CategoryId.Value, out var cat)
                ? cat
                : null;
            ComputeEffectiveVisibility(item, collection, category);
        }
    }

    private static void ComputeEffectiveVisibilityInternal(Category category, Collection collection, IDictionary<int, Category> categoryLookup)
    {
        if (!collection.EffectiveIsPublic)
        {
            category.EffectiveIsPublic = false;
            return;
        }

        if (category.ParentCategoryId.HasValue)
        {
            if (categoryLookup.TryGetValue(category.ParentCategoryId.Value, out var parentCategory) && !parentCategory.EffectiveIsPublic)
            {
                category.EffectiveIsPublic = false;
                return;
            }
        }

        category.EffectiveIsPublic = category.Visibility == Visibility.Public;
    }

    #endregion

    #region Internal Helpers

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

    private static void PromoteParentCategories(Category category, IDictionary<int, Category> categoryLookup, List<ChangedEntityInfo> promoted)
    {
        if (!category.ParentCategoryId.HasValue) return;
        if (!categoryLookup.TryGetValue(category.ParentCategoryId.Value, out var parent)) return;

        PromoteParentCategories(parent, categoryLookup, promoted);

        if (parent.Visibility == Visibility.Private)
        {
            parent.Visibility = Visibility.Public;
            promoted.Add(new ChangedEntityInfo { Type = "category", Id = parent.Id, Name = parent.Name });
        }
    }

    #endregion
}

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

    public async Task<PreflightResponse> PreflightAsync(int workspaceId, PreflightRequest request)
    {
        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        if (workspace == null)
            throw new InvalidOperationException($"Workspace {workspaceId} not found");

        var requirements = new List<PublishRequirement>();

        if (request.Action == PublishAction.Publish)
        {
            await CollectPublishRequirements(workspaceId, workspace, request.Entities, requirements);
        }
        else
        {
            await CollectUnpublishRequirements(workspaceId, request.Entities, requirements);
        }

        return new PreflightResponse
        {
            Ready = requirements.Count == 0,
            Requirements = requirements,
        };
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

    private async Task CollectPublishRequirements(int workspaceId, Workspace workspace, List<EntityRef> entities, List<PublishRequirement> requirements)
    {
        var checkedCollectionIds = new HashSet<int>();
        var checkedCategoryIds = new HashSet<int>();

        if (workspace.Slug == null)
        {
            requirements.Add(new WorkspaceSlugRequiredRequirement
            {
                WorkspaceId = workspace.Id,
                WorkspaceName = workspace.Name,
            });
        }

        foreach (var entity in entities)
        {
            switch (entity.Type)
            {
                case "item":
                {
                    var item = await _itemRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (item == null) continue;

                    if (!checkedCollectionIds.Contains(item.CollectionId))
                    {
                        var collection = await _collectionRepository.GetByIdAsync(item.CollectionId, workspaceId);
                        if (collection != null && collection.Visibility == Visibility.Private)
                        {
                            requirements.Add(new CollectionNotPublicRequirement
                            {
                                CollectionId = collection.Id,
                                CollectionName = collection.Name,
                            });
                        }
                        checkedCollectionIds.Add(item.CollectionId);
                    }

                    if (item.CategoryId.HasValue && !checkedCategoryIds.Contains(item.CategoryId.Value))
                    {
                        var allCategories = (await _categoryRepository.GetByCollectionAsync(item.CollectionId, workspaceId)).ToList();
                        var categoryLookup = allCategories.ToDictionary(c => c.Id);
                        CheckCategoryChain(item.CategoryId.Value, categoryLookup, checkedCategoryIds, requirements);
                    }
                    break;
                }
                case "category":
                {
                    var category = await _categoryRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (category == null) continue;

                    if (!checkedCollectionIds.Contains(category.CollectionId))
                    {
                        var collection = await _collectionRepository.GetByIdAsync(category.CollectionId, workspaceId);
                        if (collection != null && collection.Visibility == Visibility.Private)
                        {
                            requirements.Add(new CollectionNotPublicRequirement
                            {
                                CollectionId = collection.Id,
                                CollectionName = collection.Name,
                            });
                        }
                        checkedCollectionIds.Add(category.CollectionId);
                    }

                    if (category.ParentCategoryId.HasValue && !checkedCategoryIds.Contains(category.ParentCategoryId.Value))
                    {
                        var allCategories = (await _categoryRepository.GetByCollectionAsync(category.CollectionId, workspaceId)).ToList();
                        var categoryLookup = allCategories.ToDictionary(c => c.Id);
                        CheckCategoryChain(category.ParentCategoryId.Value, categoryLookup, checkedCategoryIds, requirements);
                    }
                    break;
                }
                case "collection":
                {
                    break;
                }
            }
        }
    }

    private static void CheckCategoryChain(int categoryId, IDictionary<int, Category> categoryLookup, HashSet<int> checkedCategoryIds, List<PublishRequirement> requirements)
    {
        if (checkedCategoryIds.Contains(categoryId)) return;
        checkedCategoryIds.Add(categoryId);

        if (!categoryLookup.TryGetValue(categoryId, out var category)) return;

        if (category.ParentCategoryId.HasValue)
        {
            CheckCategoryChain(category.ParentCategoryId.Value, categoryLookup, checkedCategoryIds, requirements);
        }

        if (category.Visibility == Visibility.Private)
        {
            requirements.Add(new CategoryNotPublicRequirement
            {
                CategoryId = category.Id,
                CategoryName = category.Name,
            });
        }
    }

    private async Task CollectUnpublishRequirements(int workspaceId, List<EntityRef> entities, List<PublishRequirement> requirements)
    {
        foreach (var entity in entities)
        {
            switch (entity.Type)
            {
                case "item":
                    break;

                case "category":
                {
                    var category = await _categoryRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (category == null) continue;

                    var collection = await _collectionRepository.GetByIdAsync(category.CollectionId, workspaceId);
                    if (collection == null) continue;

                    var allCategories = (await _categoryRepository.GetByCollectionAsync(collection.Id, workspaceId)).ToList();
                    var items = (await _itemRepository.GetByCollectionIdAsync(collection.Id, workspaceId)).ToList();

                    ComputeEffectiveVisibility(allCategories, collection);
                    ComputeEffectiveVisibility(items, collection, allCategories);

                    var childCategories = allCategories.Where(c => c.Id != category.Id).ToList();
                    var affectedItems = items.Count(i => i.EffectiveIsPublic);
                    var affectedCategories = childCategories.Count(c => c.EffectiveIsPublic);

                    if (affectedItems > 0 || affectedCategories > 0)
                    {
                        requirements.Add(new UnpublishWillHideChildrenRequirement
                        {
                            EntityType = "category",
                            EntityId = category.Id,
                            EntityName = category.Name,
                            AffectedPublicItems = affectedItems,
                            AffectedPublicCategories = affectedCategories,
                        });
                    }
                    break;
                }

                case "collection":
                {
                    var collection = await _collectionRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (collection == null) continue;

                    var allCategories = (await _categoryRepository.GetByCollectionAsync(collection.Id, workspaceId)).ToList();
                    var items = (await _itemRepository.GetByCollectionIdAsync(collection.Id, workspaceId)).ToList();

                    ComputeEffectiveVisibility(allCategories, collection);
                    ComputeEffectiveVisibility(items, collection, allCategories);

                    var affectedItems = items.Count(i => i.EffectiveIsPublic);
                    var affectedCategories = allCategories.Count(c => c.EffectiveIsPublic);

                    if (affectedItems > 0 || affectedCategories > 0)
                    {
                        requirements.Add(new UnpublishWillHideChildrenRequirement
                        {
                            EntityType = "collection",
                            EntityId = collection.Id,
                            EntityName = collection.Name,
                            AffectedPublicItems = affectedItems,
                            AffectedPublicCategories = affectedCategories,
                        });
                    }
                    break;
                }
            }
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

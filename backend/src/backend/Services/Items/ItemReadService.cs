using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Items;

public sealed class ItemReadService(
    IItemRepository items,
    ICategoryRepository categories,
    ICollectionRepository collections,
    IVisibilityService visibility) : IItemReadService
{
    public async Task<IReadOnlyList<Item>> GetAllAsync(
        int workspaceId, int? categoryId = null, bool includeDescendants = false)
    {
        var categoryList = (await categories.GetAllAsync(workspaceId)).ToList();
        IEnumerable<Item> selected;
        if (categoryId is int id)
        {
            var root = categoryList.FirstOrDefault(category => category.Id == id);
            if (root is null) return [];

            var categoryIds = includeDescendants ? DescendantIds(root, categoryList) : [id];
            selected = (await items.GetByCategoryIdsAsync(categoryIds, workspaceId))
                .Where(item => item.CollectionId == root.CollectionId);
        }
        else
        {
            selected = await items.GetAllAsync(workspaceId);
        }

        var result = selected.OrderBy(item => item.Id).ToList();
        var collectionLookup = (await collections.GetAllAsync(workspaceId)).ToDictionary(collection => collection.Id);
        var categoryGroups = categoryList.ToLookup(category => category.CollectionId);
        foreach (var group in result.GroupBy(item => item.CollectionId))
        {
            Project(group, collectionLookup.GetValueOrDefault(group.Key), categoryGroups[group.Key]);
        }
        return result;
    }

    public async Task<Item?> GetByIdAsync(int id, int workspaceId)
    {
        var item = await items.GetByIdAsync(id, workspaceId);
        if (item is null) return null;

        var collection = await collections.GetByIdAsync(item.CollectionId, workspaceId);
        var categoryList = await categories.GetByCollectionAsync(item.CollectionId, workspaceId);
        Project([item], collection, categoryList);
        return item;
    }

    private void Project(IEnumerable<Item> selected, Collection? collection, IEnumerable<Category> categoryList)
    {
        if (collection is null)
        {
            foreach (var item in selected) item.EffectiveIsPublic = false;
            return;
        }
        visibility.ComputeEffectiveVisibility(categoryList, collection);
        visibility.ComputeEffectiveVisibility(selected, collection, categoryList);
    }

    private static HashSet<int> DescendantIds(Category root, IEnumerable<Category> categoryList)
    {
        var children = categoryList.Where(category => category.CollectionId == root.CollectionId)
            .ToLookup(category => category.ParentCategoryId);
        var result = new HashSet<int> { root.Id };
        var pending = new Queue<int>();
        pending.Enqueue(root.Id);
        while (pending.TryDequeue(out var current))
        {
            foreach (var child in children[current])
            {
                if (result.Add(child.Id)) pending.Enqueue(child.Id);
            }
        }
        return result;
    }
}

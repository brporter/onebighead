using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.BulkUpdate;

namespace OneBigHead.Server.Services.Items;

public sealed class ItemWriteService(
    IItemRepository items,
    ICategoryRepository categories,
    ICollectionRepository collections,
    IVisibilityService visibility,
    IBulkUpdateJobs jobs) : IItemWriteService
{
    public async Task<ItemWriteResult> CreateAsync(int workspaceId, CreateItemRequest request)
    {
        var (collection, category, error) = await ResolveParentAsync(workspaceId, request.CollectionId, request.CategoryId);
        if (error is not null) return error;

        var item = request.ToItem(workspaceId);
        item.Visibility = (category?.EffectiveIsPublic ?? collection!.EffectiveIsPublic) ? Visibility.Public : Visibility.Private;
        var created = await items.CreateAsync(item);
        visibility.ComputeEffectiveVisibility(created, collection!, category);
        return new(ItemWriteStatus.Success, created);
    }

    public async Task<ItemWriteResult> UpdateAsync(int workspaceId, int id, UpdateItemRequest request)
    {
        var existing = await items.GetByIdAsync(id, workspaceId);
        if (existing is null) return new(ItemWriteStatus.NotFound);
        if (existing.CollectionId != request.CollectionId)
            return new(ItemWriteStatus.Invalid, Error: "An item cannot be moved to a different collection.");

        var (collection, category, error) = await ResolveParentAsync(workspaceId, request.CollectionId, request.CategoryId);
        if (error is not null) return error;

        var item = request.ToItem(id, workspaceId);
        // Publication owns visibility; ordinary editing preserves it.
        item.Visibility = existing.Visibility;
        var updated = await items.UpdateAsync(id, item, workspaceId);
        if (updated is null) return new(ItemWriteStatus.NotFound);
        visibility.ComputeEffectiveVisibility(updated, collection!, category);
        return new(ItemWriteStatus.Success, updated);
    }

    public Task<bool> DeleteAsync(int workspaceId, int id) => items.DeleteAsync(id, workspaceId);

    private async Task<(Collection? Collection, Category? Category, ItemWriteResult? Error)> ResolveParentAsync(
        int workspaceId, int collectionId, int? categoryId)
    {
        if (jobs.GetActiveJobForCollection(collectionId, workspaceId) is not null)
            return (null, null, new(ItemWriteStatus.Conflict,
                Error: "A bulk update is in progress for this collection. Please wait for it to complete."));

        var collection = await collections.GetByIdAsync(collectionId, workspaceId);
        if (collection is null) return (null, null, new(ItemWriteStatus.Invalid, Error: "Invalid collection"));

        var parents = (await categories.GetByCollectionAsync(collectionId, workspaceId)).ToList();
        visibility.ComputeEffectiveVisibility(parents, collection);
        var category = parents.FirstOrDefault(parent => parent.Id == categoryId);
        if (categoryId.HasValue && category is null)
            return (null, null, new(ItemWriteStatus.Invalid, Error: "Invalid category"));
        return (collection, category, null);
    }
}

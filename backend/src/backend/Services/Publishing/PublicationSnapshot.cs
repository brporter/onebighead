using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Publishing;

internal sealed record PublicationKey(string Type, int Id);

/// <summary>A tracked, workspace-scoped view of the selected collections within one transaction.</summary>
internal sealed record PublicationSnapshot(Workspace Workspace, HashSet<PublicationKey> Selection,
    Dictionary<int, Collection> Collections, Dictionary<int, Category> Categories, Dictionary<int, Item> Items)
{
    public static async Task<PublicationResult<PublicationSnapshot>> LoadAsync(AppDbContext context, int workspaceId,
        PublishAction action, List<EntityRef> entities, CancellationToken cancellationToken)
    {
        if (!Enum.IsDefined(action) || entities.Count == 0 || entities.Any(entity => entity.Id <= 0 || entity.Type is not ("item" or "category" or "collection")))
            return Reject(PublicationFailure.Invalid, "Choose at least one valid item, category or collection and a supported action.");
        var selection = entities.Select(entity => new PublicationKey(entity.Type, entity.Id)).ToHashSet();
        var workspace = await context.Workspaces.SingleOrDefaultAsync(w => w.Id == workspaceId && !w.IsDeleted, cancellationToken);
        if (workspace is null) return Reject(PublicationFailure.NotFound, "Workspace not found.");

        var itemIds = selection.Where(key => key.Type == "item").Select(key => key.Id).ToArray();
        var categoryIds = selection.Where(key => key.Type == "category").Select(key => key.Id).ToArray();
        var items = await context.Items.Where(item => item.WorkspaceId == workspaceId && itemIds.Contains(item.Id!.Value))
            .ToDictionaryAsync(item => item.Id!.Value, cancellationToken);
        var selectedCategories = await context.Categories.Where(category => category.WorkspaceId == workspaceId && categoryIds.Contains(category.Id))
            .ToListAsync(cancellationToken);
        if (items.Count != itemIds.Length || selectedCategories.Count != categoryIds.Length)
            return Reject(PublicationFailure.NotFound, "One or more selected entries are unavailable in this workspace.");

        var collectionIds = selection.Where(key => key.Type == "collection").Select(key => key.Id)
            .Concat(items.Values.Select(item => item.CollectionId)).Concat(selectedCategories.Select(category => category.CollectionId)).Distinct().ToArray();
        var collections = await context.Collections.Where(collection => collection.WorkspaceId == workspaceId && collectionIds.Contains(collection.Id))
            .ToDictionaryAsync(collection => collection.Id, cancellationToken);
        if (collections.Count != collectionIds.Length)
            return Reject(PublicationFailure.NotFound, "One or more selected collections are unavailable in this workspace.");
        var categories = await context.Categories.Where(category => category.WorkspaceId == workspaceId && collectionIds.Contains(category.CollectionId))
            .ToDictionaryAsync(category => category.Id, cancellationToken);
        if (action == PublishAction.Unpublish)
        {
            // Impact counts need only scope and visibility, not every item's images and custom properties.
            // Selected items remain tracked so only their visibility fields are written.
            var related = await context.Items.AsNoTracking().Where(item => item.WorkspaceId == workspaceId &&
                collectionIds.Contains(item.CollectionId) && !itemIds.Contains(item.Id!.Value))
                .Select(item => new Item { Id = item.Id, WorkspaceId = item.WorkspaceId, CollectionId = item.CollectionId,
                    CategoryId = item.CategoryId, Visibility = item.Visibility }).ToListAsync(cancellationToken);
            foreach (var item in related) items.Add(item.Id!.Value, item);
        }
        return PublicationResult<PublicationSnapshot>.Success(new(workspace, selection, collections, categories, items));
    }

    public void Apply(ChangedEntityInfo entity, Visibility visibility)
    {
        switch (entity.Type)
        {
            case "collection": Collections[entity.Id].Visibility = visibility; break;
            case "category": Categories[entity.Id].Visibility = visibility; break;
            case "item": Items[entity.Id].Visibility = visibility; break;
            default: throw new ArgumentException("Unsupported publication entity.", nameof(entity));
        }
    }

    private static PublicationResult<PublicationSnapshot> Reject(PublicationFailure kind, string message) =>
        PublicationResult<PublicationSnapshot>.Failure(new(kind, message));
}

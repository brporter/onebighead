using System.Diagnostics.CodeAnalysis;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.BulkUpdate;

public sealed record BulkUpdateTarget(BulkUpdateScope Scope, Guid? TemplateKey = null,
    int? CategoryId = null, int? CollectionId = null, int? ExcludeItemId = null)
{
    public static bool TryCreate(string? scope, Guid? templateKey, int? categoryId, int? collectionId,
        int? excludeItemId, [NotNullWhen(true)] out BulkUpdateTarget? target)
    {
        target = scope?.ToLowerInvariant() switch
        {
            "template" when templateKey.HasValue && templateKey.Value != Guid.Empty =>
                new(BulkUpdateScope.Template, TemplateKey: templateKey, ExcludeItemId: excludeItemId),
            "category" when categoryId > 0 =>
                new(BulkUpdateScope.Category, CategoryId: categoryId, ExcludeItemId: excludeItemId),
            "collection" when collectionId > 0 =>
                new(BulkUpdateScope.Collection, CollectionId: collectionId, ExcludeItemId: excludeItemId),
            _ => null
        };
        if (excludeItemId <= 0) target = null;
        return target is not null;
    }

    internal IQueryable<Item> Select(IQueryable<Item> items, int workspaceId)
    {
        var scoped = items.Where(item => item.WorkspaceId == workspaceId && item.Collection!.WorkspaceId == workspaceId
            && !item.Workspace!.IsDeleted && item.Id != ExcludeItemId);
        return Scope switch
        {
            BulkUpdateScope.Template => scoped.Where(item => item.TemplateKey == TemplateKey),
            BulkUpdateScope.Category => scoped.Where(item => item.CategoryId == CategoryId
                && item.Category!.WorkspaceId == workspaceId && item.Category.CollectionId == item.CollectionId),
            BulkUpdateScope.Collection => scoped.Where(item => item.CollectionId == CollectionId),
            _ => throw new ArgumentOutOfRangeException(nameof(Scope))
        };
    }
}

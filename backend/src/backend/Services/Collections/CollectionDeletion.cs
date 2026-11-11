using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Collections;

public sealed class CollectionDeletion(IDbContextFactory<AppDbContext> contexts, IWorkspaceStatisticsDecrementer statistics) : ICollectionDeletion
{
    public async Task<CollectionWriteResult> DeleteAsync(int userId, int workspaceId, int collectionId, CancellationToken cancellationToken)
    {
        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            if (!await CollectionWriteAccess.ForMember(context, userId, workspaceId).AnyAsync(collection => collection.Id == collectionId, cancellationToken))
                return new(CollectionWriteStatus.NotFound);
            if (!await context.WorkspaceUsers.AnyAsync(member => member.UserId == userId && member.WorkspaceId == workspaceId &&
                member.WorkspaceRole == WorkspaceRole.WorkspaceAdmin, cancellationToken)) return new(CollectionWriteStatus.Forbidden);
            if (await context.Collections.CountAsync(collection => collection.WorkspaceId == workspaceId, cancellationToken) <= 1)
                return new(CollectionWriteStatus.Invalid, Error: "Cannot delete the last collection. Users must have at least one collection.");

            var categories = context.Categories.Where(category => category.CollectionId == collectionId).Select(category => category.Id);
            var items = context.Items.Where(item => item.CollectionId == collectionId).Select(item => item.Id);
            // Malformed legacy references must not delete or alter another collection's content.
            if (await context.Categories.AnyAsync(category => category.CollectionId == collectionId && category.WorkspaceId != workspaceId, cancellationToken) ||
                await context.Categories.AnyAsync(category => category.CollectionId != collectionId && categories.Contains(category.ParentCategoryId!.Value), cancellationToken) ||
                await context.Items.AnyAsync(item => item.CollectionId == collectionId && item.WorkspaceId != workspaceId ||
                    item.CollectionId != collectionId && categories.Contains(item.CategoryId!.Value), cancellationToken) ||
                await context.PropertySuggestions.AnyAsync(suggestion => suggestion.CollectionId == collectionId && suggestion.WorkspaceId != workspaceId, cancellationToken) ||
                await context.CollectionItemHighlights.AnyAsync(highlight => highlight.CollectionId != collectionId && items.Contains(highlight.ItemId), cancellationToken))
                return new(CollectionWriteStatus.Conflict, Error: "This collection has inconsistent links to other content. Repair those links before deleting it.");

            await context.CollectionItemHighlights.Where(highlight => highlight.CollectionId == collectionId).ExecuteDeleteAsync(cancellationToken);
            var itemCount = await context.Items.Where(item => item.CollectionId == collectionId).ExecuteDeleteAsync(cancellationToken);
            await context.Categories.Where(category => category.CollectionId == collectionId)
                .ExecuteUpdateAsync(set => set.SetProperty(category => category.ParentCategoryId, (int?)null), cancellationToken);
            // Cascades remove owned categories, suggestions, template links and collection counters.
            // Stored images and templates belong to the workspace and may still be shared elsewhere.
            await context.Collections.Where(collection => collection.Id == collectionId).ExecuteDeleteAsync(cancellationToken);
            await statistics.DecrementAsync(context, workspaceId, StatisticType.CollectionCount, 1, cancellationToken);
            if (itemCount > 0) await statistics.DecrementAsync(context, workspaceId, StatisticType.ItemCount, itemCount, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(CollectionWriteStatus.Success);
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return CollectionWriteResult.ConcurrentChange();
        }
    }
}

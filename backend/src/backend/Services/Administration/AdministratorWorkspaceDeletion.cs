using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Services.Administration;

/// <summary>Permanently removes a workspace as one transaction while preserving accounts and audit history.</summary>
public sealed class AdministratorWorkspaceDeletion(IDbContextFactory<AppDbContext> contextFactory) : IAdministratorWorkspaceDeletion
{
    public async Task<AdministratorWorkspaceDeletionResult> DeleteAsync(int workspaceId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            if (!await context.Workspaces.AnyAsync(w => w.Id == workspaceId))
                return AdministratorWorkspaceDeletionResult.NotFound;

            var collections = context.Collections.Where(c => c.WorkspaceId == workspaceId).Select(c => c.Id);
            var categories = context.Categories.Where(c => c.WorkspaceId == workspaceId).Select(c => c.Id);
            var items = context.Items.Where(i => i.WorkspaceId == workspaceId).Select(i => i.Id);
            var templates = context.ItemTemplates.Where(t => t.WorkspaceId == workspaceId).Select(t => t.Id);

            // Legacy malformed links must not make a cascade delete another workspace's data.
            if (await context.Categories.AnyAsync(c => c.WorkspaceId != workspaceId &&
                    (collections.Contains(c.CollectionId) || categories.Contains(c.ParentCategoryId!.Value))) ||
                await context.Items.AnyAsync(i => i.WorkspaceId != workspaceId &&
                    (collections.Contains(i.CollectionId) || categories.Contains(i.CategoryId!.Value))) ||
                await context.PropertySuggestions.AnyAsync(p => p.WorkspaceId != workspaceId && collections.Contains(p.CollectionId)) ||
                await context.CollectionItemTemplates.AnyAsync(t => templates.Contains(t.ItemTemplateId) && !collections.Contains(t.CollectionId)) ||
                await context.CategoryItemTemplates.AnyAsync(t => templates.Contains(t.ItemTemplateId) && !categories.Contains(t.CategoryId)) ||
                await context.CollectionThemeTemplates.AnyAsync(t => templates.Contains(t.ItemTemplateId)) ||
                await context.CollectionItemHighlights.AnyAsync(h => items.Contains(h.ItemId) && !collections.Contains(h.CollectionId)))
                return AdministratorWorkspaceDeletionResult.ConflictingReferences;

            await WorkspaceSessionAssignments.ReassignAsync(context, workspaceId);
            await context.SaveChangesAsync();

            await context.CollectionItemHighlights.Where(h => collections.Contains(h.CollectionId)).ExecuteDeleteAsync();
            await context.Items.Where(i => i.WorkspaceId == workspaceId).ExecuteDeleteAsync();
            await context.Categories.Where(c => c.WorkspaceId == workspaceId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(c => c.ParentCategoryId, (int?)null));
            await context.CategoryItemTemplates.Where(t => categories.Contains(t.CategoryId)).ExecuteDeleteAsync();
            await context.CollectionItemTemplates.Where(t => collections.Contains(t.CollectionId)).ExecuteDeleteAsync();
            await context.Categories.Where(c => c.WorkspaceId == workspaceId).ExecuteDeleteAsync();
            await context.PropertySuggestions.Where(p => p.WorkspaceId == workspaceId).ExecuteDeleteAsync();
            await context.WorkspaceStatistics.Where(s => s.WorkspaceId == workspaceId).ExecuteDeleteAsync();
            // PostgreSQL cascades the remaining owned collections, templates/properties,
            // images and memberships. Content scan logs deliberately have no FK.
            await context.Workspaces.Where(w => w.Id == workspaceId).ExecuteDeleteAsync();
            await transaction.CommitAsync();
            return AdministratorWorkspaceDeletionResult.Deleted;
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return AdministratorWorkspaceDeletionResult.ConcurrentChange;
        }
    }
}

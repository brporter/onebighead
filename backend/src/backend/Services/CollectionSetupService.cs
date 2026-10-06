using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Utilities;

namespace OneBigHead.Server.Services;

public class CollectionSetupService(
    IDbContextFactory<AppDbContext> contextFactory,
    IWorkspaceStatisticsRepository statistics,
    ILogger<CollectionSetupService> logger) : ICollectionSetupService
{
    public async Task<Collection> CreateAsync(Collection collection, CollectionTheme? theme)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        collection.Slug = SlugHelper.GenerateSlug(collection.Name);
        if (await context.Collections.AnyAsync(c => c.WorkspaceId == collection.WorkspaceId && c.Slug == collection.Slug))
            collection.Slug = $"{collection.Slug}-{DateTime.UtcNow.Ticks}";

        ApplyTheme(collection, theme, StringComparer.Ordinal);
        context.Collections.Add(collection);
        // EF saves the entire collection graph in one transaction.
        await context.SaveChangesAsync();
        await statistics.IncrementAsync(collection.WorkspaceId, StatisticType.CollectionCount);
        return collection;
    }

    public async Task<Collection> SetupWorkspaceAsync(int userId, Workspace workspace, Collection collection, CollectionTheme? theme)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var user = await context.Users.SingleAsync(u => u.Id == userId);
        collection.Workspace = workspace;
        collection.Slug = SlugHelper.GenerateSlug(collection.Name);
        // Workspace setup historically matches theme parent names without case sensitivity.
        ApplyTheme(collection, theme, StringComparer.OrdinalIgnoreCase);
        foreach (var category in collection.Categories)
            category.Workspace = workspace;
        workspace.WorkspaceUsers.Add(new WorkspaceUser { User = user, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        user.ActiveWorkspace = workspace;
        context.Collections.Add(collection);
        // Workspace, membership, active workspace and collection commit together.
        await context.SaveChangesAsync();
        await statistics.IncrementAsync(workspace.Id, StatisticType.CollectionCount);
        return collection;
    }

    private void ApplyTheme(Collection collection, CollectionTheme? theme, StringComparer comparer)
    {
        collection.Visibility = Visibility.Private;
        collection.Categories.Add(new Category
        {
            WorkspaceId = collection.WorkspaceId,
            Name = Constants.CategoryNames.UnassignedItems,
            Description = Constants.CategoryNames.UnassignedItemsDescription,
            IsSystem = true
        });
        if (theme is null) return;

        foreach (var id in theme.ThemeTemplates.OrderBy(t => t.SortOrder).Select(t => t.ItemTemplateId).Where(id => id > 0).Distinct())
            collection.CollectionItemTemplates.Add(new CollectionItemTemplate { ItemTemplateId = id });

        var categories = new Dictionary<string, Category>(comparer);
        var pending = theme.ThemeCategories.OrderBy(c => c.SortOrder).ToList();
        while (pending.Count > 0)
        {
            var ready = pending.Where(c => c.ParentName is null ||
                (comparer == StringComparer.OrdinalIgnoreCase && c.ParentName.Length == 0) || categories.ContainsKey(c.ParentName)).ToList();
            if (ready.Count == 0) break;
            foreach (var source in ready)
            {
                var category = new Category
                {
                    WorkspaceId = collection.WorkspaceId,
                    Name = source.Name,
                    Description = source.Description,
                    ParentCategory = source.ParentName is not null ? categories.GetValueOrDefault(source.ParentName) : null
                };
                collection.Categories.Add(category);
                categories[source.Name] = category;
                pending.Remove(source);
            }
        }
        foreach (var orphan in pending)
            logger.LogWarning("Theme category '{CategoryName}' could not be created: parent '{ParentName}' is missing or circular",
                orphan.Name, orphan.ParentName);
    }
}

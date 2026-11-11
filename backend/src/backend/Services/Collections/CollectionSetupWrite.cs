using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Collections;

/// <summary>Persists a themed collection and its count within the caller's transaction.</summary>
internal static class CollectionSetupWrite
{
    public static async Task SaveAsync(AppDbContext context, Collection collection, CollectionTheme? theme,
        IWorkspaceStatisticsWriter statistics)
    {
        var categories = CollectionThemeGraph.Build(collection.WorkspaceId, theme);
        collection.Visibility = Visibility.Private;
        collection.Categories = categories.ToList();
        collection.CollectionItemTemplates = theme?.ThemeTemplates.OrderBy(link => link.SortOrder)
            .Select(link => link.ItemTemplateId).Where(id => id > 0).Distinct()
            .Select(id => new CollectionItemTemplate { ItemTemplateId = id }).ToList() ?? [];
        foreach (var category in collection.Categories) category.Workspace = collection.Workspace;

        var workspaceId = collection.Workspace?.Id ?? collection.WorkspaceId;
        collection.Slug = await CollectionSlugs.CreateAsync(context, workspaceId, collection.Name);

        var templateIds = collection.CollectionItemTemplates.Select(link => link.ItemTemplateId).ToList();
        var availableTemplates = await context.ItemTemplates.CountAsync(template => templateIds.Contains(template.Id) &&
            (template.WorkspaceId == null || template.WorkspaceId == workspaceId));
        if (availableTemplates != templateIds.Count)
            throw new InvalidCollectionThemeException("One or more theme templates are unavailable in this workspace.");
        context.Collections.Add(collection);
        await context.SaveChangesAsync();
        await statistics.IncrementAsync(context, collection.WorkspaceId, StatisticType.CollectionCount);
    }
}

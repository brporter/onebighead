using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Categories;

public sealed class CategoryReadService(IDbContextFactory<AppDbContext> contextFactory) : ICategoryReadService
{
    public async Task<IReadOnlyList<CategoryResponse>?> GetAllAsync(int workspaceId, int? collectionId = null)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        if (collectionId.HasValue && !await context.Collections.AnyAsync(
                c => c.Id == collectionId.Value && c.WorkspaceId == workspaceId))
        {
            return null;
        }

        var rows = await ReadCollectionRowsAsync(context, workspaceId, collectionId);
        foreach (var collection in rows.GroupBy(row => row.Collection.Id))
        {
            CategoryVisibility.Apply(collection.Select(row => row.Category), collection.First().Collection);
        }

        return rows.Select(row => CategoryResponse.FromCategory(row.Category, row.TemplateIds)).ToList();
    }

    public async Task<CategoryResponse?> GetByIdAsync(int categoryId, int workspaceId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var rows = await ReadCategoryCollectionAsync(context, categoryId, workspaceId);
        var row = rows.FirstOrDefault(row => row.Category.Id == categoryId);
        if (row is null)
        {
            return null;
        }

        CategoryVisibility.Apply(rows.Select(row => row.Category), row.Collection);
        return CategoryResponse.FromCategory(row.Category, row.TemplateIds);
    }

    public async Task<IReadOnlyList<int>?> GetInheritedTemplateIdsAsync(int categoryId, int workspaceId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var rows = await ReadCategoryCollectionAsync(context, categoryId, workspaceId);
        var lookup = rows.ToDictionary(row => row.Category.Id);
        if (!lookup.TryGetValue(categoryId, out var current))
        {
            return null;
        }

        var result = new List<int>();
        var seenTemplates = new HashSet<int>();
        var seenCategories = new HashSet<int>();
        // Child assignments take precedence. Broken or cyclic ancestry cannot escape this collection.
        while (current != null && seenCategories.Add(current.Category.Id))
        {
            foreach (var templateId in current.TemplateIds)
            {
                if (seenTemplates.Add(templateId))
                {
                    result.Add(templateId);
                }
            }

            current = current.Category.ParentCategoryId is int parentId
                ? lookup.GetValueOrDefault(parentId)
                : null;
        }

        return result;
    }

    private static async Task<List<CategoryRow>> ReadCategoryCollectionAsync(
        AppDbContext context, int categoryId, int workspaceId)
    {
        var collectionId = await ScopedCategories(context, workspaceId)
            .Where(category => category.Id == categoryId)
            .Select(category => (int?)category.CollectionId)
            .SingleOrDefaultAsync();
        return collectionId.HasValue
            ? await ReadCollectionRowsAsync(context, workspaceId, collectionId)
            : [];
    }

    private static IQueryable<Category> ScopedCategories(AppDbContext context, int workspaceId) =>
        context.Categories.AsNoTracking().Where(category =>
            category.WorkspaceId == workspaceId && category.Collection!.WorkspaceId == workspaceId);

    private static Task<List<CategoryRow>> ReadCollectionRowsAsync(
        AppDbContext context, int workspaceId, int? collectionId)
    {
        var query = ScopedCategories(context, workspaceId);
        if (collectionId.HasValue)
        {
            query = query.Where(category => category.CollectionId == collectionId.Value);
        }

        return query.OrderBy(category => category.SortOrder)
            .ThenBy(category => category.Name)
            .ThenBy(category => category.Id)
            .Select(category => new CategoryRow(category, category.Collection!,
                category.CategoryItemTemplates
                    .Where(link => link.ItemTemplate!.WorkspaceId == null || link.ItemTemplate.WorkspaceId == workspaceId)
                    .OrderBy(link => link.SortOrder)
                    .ThenBy(link => link.ItemTemplateId)
                    .Select(link => link.ItemTemplateId).ToList()))
            .ToListAsync();
    }

    private sealed record CategoryRow(Category Category, Collection Collection, List<int> TemplateIds);
}

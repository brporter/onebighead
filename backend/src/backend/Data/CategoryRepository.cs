using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class CategoryRepository : ICategoryRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;

    public CategoryRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task<IEnumerable<Category>> GetAllAsync(int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Categories
            .AsNoTracking()
            .Where(c => c.WorkspaceId == workspaceId)
            .OrderBy(c => c.SortOrder)
            .ThenBy(c => c.Name)
            .ToListAsync();
    }

    public async Task<IEnumerable<Category>> GetByCollectionAsync(int collectionId, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Categories
            .AsNoTracking()
            .Where(c => c.WorkspaceId == workspaceId && c.CollectionId == collectionId)
            .OrderBy(c => c.SortOrder)
            .ThenBy(c => c.Name)
            .ToListAsync();
    }

    public async Task<Category?> GetByIdAsync(int id, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Categories
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id && c.WorkspaceId == workspaceId);
    }

    public async Task<Category?> GetSystemCategoryAsync(int collectionId, int workspaceId, string name)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Categories
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.WorkspaceId == workspaceId && c.CollectionId == collectionId && c.IsSystem && c.Name == name);
    }

    public async Task<Category> CreateAsync(Category category)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        context.Categories.Add(category);
        await context.SaveChangesAsync();
        return category;
    }

    public async Task<IEnumerable<Category>> CreateManyAsync(IEnumerable<Category> categories)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var categoryList = categories.ToList();
        context.Categories.AddRange(categoryList);
        await context.SaveChangesAsync();
        return categoryList;
    }

    public async Task<Category?> UpdateAsync(int id, Category category, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var existingCategory = await context.Categories
            .FirstOrDefaultAsync(c => c.Id == id && c.WorkspaceId == workspaceId);

        if (existingCategory is null)
        {
            return null;
        }

        existingCategory.Name = category.Name;
        existingCategory.Description = category.Description;
        existingCategory.ParentCategoryId = category.ParentCategoryId;
        existingCategory.Visibility = category.Visibility;

        await context.SaveChangesAsync();
        return existingCategory;
    }

    public async Task<bool> DeleteAsync(int id, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var category = await context.Categories
            .FirstOrDefaultAsync(c => c.Id == id && c.WorkspaceId == workspaceId);

        if (category is null)
        {
            return false;
        }

        // Prevent deletion of system categories
        if (category.IsSystem)
        {
            return false;
        }

        // Move subcategories to the deleted category's parent (or root if no parent)
        var subcategories = await context.Categories
            .Where(c => c.ParentCategoryId == id && c.WorkspaceId == workspaceId)
            .ToListAsync();

        foreach (var subcategory in subcategories)
        {
            subcategory.ParentCategoryId = category.ParentCategoryId;
        }

        // Get the "Unassigned Items" system category for this collection
        var unassignedCategory = await GetSystemCategoryAsync(category.CollectionId, workspaceId, "Unassigned Items");

        // Move items in the deleted category to "Unassigned Items"
        var items = await context.Items
            .Where(i => i.CategoryId == id && i.WorkspaceId == workspaceId)
            .ToListAsync();

        foreach (var item in items)
        {
            item.CategoryId = unassignedCategory?.Id;
        }

        context.Categories.Remove(category);
        await context.SaveChangesAsync();
        return true;
    }

    public async Task<List<int>> GetTemplateIdsAsync(int categoryId, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        // Verify category belongs to workspace
        var category = await context.Categories
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == categoryId && c.WorkspaceId == workspaceId);

        if (category is null)
        {
            return new List<int>();
        }

        return await context.CategoryItemTemplates
            .AsNoTracking()
            .Where(ct => ct.CategoryId == categoryId)
            .OrderBy(ct => ct.SortOrder)
            .Select(ct => ct.ItemTemplateId)
            .ToListAsync();
    }

    public async Task<Dictionary<int, List<int>>> GetTemplateIdsByCategoryAsync(int collectionId, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var categoryIds = await context.Categories
            .AsNoTracking()
            .Where(c => c.CollectionId == collectionId && c.WorkspaceId == workspaceId)
            .Select(c => c.Id)
            .ToListAsync();

        var associations = await context.CategoryItemTemplates
            .AsNoTracking()
            .Where(ct => categoryIds.Contains(ct.CategoryId))
            .OrderBy(ct => ct.SortOrder)
            .ToListAsync();

        return associations
            .GroupBy(ct => ct.CategoryId)
            .ToDictionary(
                g => g.Key,
                g => g.Select(ct => ct.ItemTemplateId).ToList()
            );
    }

    public async Task SetTemplateIdsAsync(int categoryId, List<int> templateIds, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        // Verify category belongs to workspace
        var category = await context.Categories
            .FirstOrDefaultAsync(c => c.Id == categoryId && c.WorkspaceId == workspaceId);

        if (category is null)
        {
            return;
        }

        // Remove existing associations
        var existing = await context.CategoryItemTemplates
            .Where(ct => ct.CategoryId == categoryId)
            .ToListAsync();
        context.CategoryItemTemplates.RemoveRange(existing);

        // Add new associations
        var sortOrder = 0;
        foreach (var templateId in templateIds)
        {
            context.CategoryItemTemplates.Add(new CategoryItemTemplate
            {
                CategoryId = categoryId,
                ItemTemplateId = templateId,
                SortOrder = sortOrder++
            });
        }

        await context.SaveChangesAsync();
    }

    public async Task ReorderAsync(Dictionary<int, int> categoryIdToSortOrder, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var categoryIds = categoryIdToSortOrder.Keys.ToList();
        var categories = await context.Categories
            .Where(c => c.WorkspaceId == workspaceId && categoryIds.Contains(c.Id))
            .ToListAsync();

        foreach (var category in categories)
        {
            category.SortOrder = categoryIdToSortOrder[category.Id];
        }

        await context.SaveChangesAsync();
    }

    public async Task<List<int>> GetInheritedTemplateIdsAsync(int categoryId, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        // First get the target category to determine its collection
        var rootCategory = await context.Categories
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == categoryId && c.WorkspaceId == workspaceId);

        if (rootCategory is null)
        {
            return new List<int>();
        }

        // Load only categories for this collection to avoid loading unnecessary data
        var allCategories = await context.Categories
            .AsNoTracking()
            .Where(c => c.WorkspaceId == workspaceId && c.CollectionId == rootCategory.CollectionId)
            .ToDictionaryAsync(c => c.Id);

        // Collect ancestor category IDs
        var ancestorIds = new List<int>();
        var currentId = (int?)categoryId;
        while (currentId.HasValue && allCategories.TryGetValue(currentId.Value, out var category))
        {
            ancestorIds.Add(currentId.Value);
            currentId = category.ParentCategoryId;
        }

        // Load all template associations for ancestors in single query
        var templateAssociations = await context.CategoryItemTemplates
            .AsNoTracking()
            .Where(ct => ancestorIds.Contains(ct.CategoryId))
            .OrderBy(ct => ct.SortOrder)
            .ToListAsync();

        // Group by category for in-memory traversal
        var templatesByCategory = templateAssociations
            .GroupBy(ct => ct.CategoryId)
            .ToDictionary(g => g.Key, g => g.Select(ct => ct.ItemTemplateId).ToList());

        // Walk the hierarchy in order (child first) and collect unique templates
        var result = new List<int>();
        var seen = new HashSet<int>();

        foreach (var catId in ancestorIds)
        {
            if (templatesByCategory.TryGetValue(catId, out var templateIds))
            {
                foreach (var templateId in templateIds)
                {
                    if (seen.Add(templateId))
                    {
                        result.Add(templateId);
                    }
                }
            }
        }

        return result;
    }
}


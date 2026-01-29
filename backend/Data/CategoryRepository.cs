using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Data;

public class CategoryRepository : ICategoryRepository
{
    private readonly AppDbContext _context;

    public CategoryRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<Category>> GetAllAsync(int tenantId)
    {
        return await _context.Categories
            .AsNoTracking()
            .Where(c => c.TenantId == tenantId)
            .ToListAsync();
    }

    public async Task<IEnumerable<Category>> GetByCollectionAsync(int collectionId, int tenantId)
    {
        return await _context.Categories
            .AsNoTracking()
            .Where(c => c.TenantId == tenantId && c.CollectionId == collectionId)
            .ToListAsync();
    }

    public async Task<Category?> GetByIdAsync(int id, int tenantId)
    {
        return await _context.Categories
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId);
    }

    public async Task<Category?> GetSystemCategoryAsync(int collectionId, int tenantId, string name)
    {
        return await _context.Categories
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.TenantId == tenantId && c.CollectionId == collectionId && c.IsSystem && c.Name == name);
    }

    public async Task<Category> CreateAsync(Category category)
    {
        _context.Categories.Add(category);
        await _context.SaveChangesAsync();
        return category;
    }

    public async Task<IEnumerable<Category>> CreateManyAsync(IEnumerable<Category> categories)
    {
        var categoryList = categories.ToList();
        _context.Categories.AddRange(categoryList);
        await _context.SaveChangesAsync();
        return categoryList;
    }

    public async Task<Category?> UpdateAsync(int id, Category category, int tenantId)
    {
        var existingCategory = await _context.Categories
            .FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId);
        
        if (existingCategory is null)
        {
            return null;
        }

        existingCategory.Name = category.Name;
        existingCategory.Description = category.Description;
        existingCategory.ParentCategoryId = category.ParentCategoryId;
        existingCategory.IsPublicOverride = category.IsPublicOverride;

        await _context.SaveChangesAsync();
        return existingCategory;
    }

    public async Task<bool> DeleteAsync(int id, int tenantId)
    {
        var category = await _context.Categories
            .FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId);
        
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
        var subcategories = await _context.Categories
            .Where(c => c.ParentCategoryId == id && c.TenantId == tenantId)
            .ToListAsync();
        
        foreach (var subcategory in subcategories)
        {
            subcategory.ParentCategoryId = category.ParentCategoryId;
        }

        // Get the "Unassigned Items" system category for this collection
        var unassignedCategory = await GetSystemCategoryAsync(category.CollectionId, tenantId, "Unassigned Items");
        
        // Move items in the deleted category to "Unassigned Items"
        var items = await _context.Items
            .Where(i => i.CategoryId == id && i.TenantId == tenantId)
            .ToListAsync();
        
        foreach (var item in items)
        {
            item.CategoryId = unassignedCategory?.Id;
        }

        _context.Categories.Remove(category);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<List<int>> GetTemplateIdsAsync(int categoryId, int tenantId)
    {
        // Verify category belongs to tenant
        var category = await _context.Categories
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == categoryId && c.TenantId == tenantId);
        
        if (category is null)
        {
            return new List<int>();
        }

        return await _context.CategoryItemTemplates
            .AsNoTracking()
            .Where(ct => ct.CategoryId == categoryId)
            .OrderBy(ct => ct.SortOrder)
            .Select(ct => ct.ItemTemplateId)
            .ToListAsync();
    }

    public async Task<Dictionary<int, List<int>>> GetTemplateIdsByCategoryAsync(int collectionId, int tenantId)
    {
        var categoryIds = await _context.Categories
            .AsNoTracking()
            .Where(c => c.CollectionId == collectionId && c.TenantId == tenantId)
            .Select(c => c.Id)
            .ToListAsync();

        var associations = await _context.CategoryItemTemplates
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

    public async Task SetTemplateIdsAsync(int categoryId, List<int> templateIds, int tenantId)
    {
        // Verify category belongs to tenant
        var category = await _context.Categories
            .FirstOrDefaultAsync(c => c.Id == categoryId && c.TenantId == tenantId);
        
        if (category is null)
        {
            return;
        }

        // Remove existing associations
        var existing = await _context.CategoryItemTemplates
            .Where(ct => ct.CategoryId == categoryId)
            .ToListAsync();
        _context.CategoryItemTemplates.RemoveRange(existing);

        // Add new associations
        var sortOrder = 0;
        foreach (var templateId in templateIds)
        {
            _context.CategoryItemTemplates.Add(new CategoryItemTemplate
            {
                CategoryId = categoryId,
                ItemTemplateId = templateId,
                SortOrder = sortOrder++
            });
        }

        await _context.SaveChangesAsync();
    }

    public async Task<List<int>> GetInheritedTemplateIdsAsync(int categoryId, int tenantId)
    {
        // Load all categories for tenant upfront to avoid N+1 queries
        var allCategories = await _context.Categories
            .AsNoTracking()
            .Where(c => c.TenantId == tenantId)
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
        var templateAssociations = await _context.CategoryItemTemplates
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


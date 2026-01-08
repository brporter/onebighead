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
            .Where(c => c.TenantId == tenantId)
            .ToListAsync();
    }

    public async Task<IEnumerable<Category>> GetByCollectionAsync(int collectionId, int tenantId)
    {
        return await _context.Categories
            .Where(c => c.TenantId == tenantId && c.CollectionId == collectionId)
            .ToListAsync();
    }

    public async Task<Category?> GetByIdAsync(int id, int tenantId)
    {
        return await _context.Categories
            .FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId);
    }

    public async Task<Category?> GetSystemCategoryAsync(int collectionId, int tenantId, string name)
    {
        return await _context.Categories
            .FirstOrDefaultAsync(c => c.TenantId == tenantId && c.CollectionId == collectionId && c.IsSystem && c.Name == name);
    }

    public async Task<Category> CreateAsync(Category category)
    {
        _context.Categories.Add(category);
        await _context.SaveChangesAsync();
        return category;
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
}


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

    public async Task<Category?> GetByIdAsync(int id, int tenantId)
    {
        return await _context.Categories
            .FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId);
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

        _context.Categories.Remove(category);
        await _context.SaveChangesAsync();
        return true;
    }
}


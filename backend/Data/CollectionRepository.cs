using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Data;

public class CollectionRepository : ICollectionRepository
{
    private readonly AppDbContext _context;

    public CollectionRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<Collection>> GetAllAsync(int tenantId)
    {
        return await _context.Collections
            .Where(c => c.TenantId == tenantId)
            .OrderBy(c => c.Name)
            .ToListAsync();
    }

    public async Task<Collection?> GetByIdAsync(int id, int tenantId)
    {
        return await _context.Collections
            .FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId);
    }

    public async Task<Collection?> GetBySlugAsync(string slug, int tenantId)
    {
        return await _context.Collections
            .FirstOrDefaultAsync(c => c.Slug == slug && c.TenantId == tenantId);
    }

    public async Task<Collection> CreateAsync(Collection collection)
    {
        _context.Collections.Add(collection);
        await _context.SaveChangesAsync();
        return collection;
    }

    public async Task<Collection?> UpdateAsync(int id, Collection collection, int tenantId)
    {
        var existingCollection = await _context.Collections
            .FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId);

        if (existingCollection is null)
        {
            return null;
        }

        existingCollection.Name = collection.Name;
        existingCollection.Description = collection.Description;
        existingCollection.HeroImageUrl = collection.HeroImageUrl;
        existingCollection.Slug = collection.Slug;

        await _context.SaveChangesAsync();
        return existingCollection;
    }

    public async Task<bool> DeleteAsync(int id, int tenantId)
    {
        var collection = await _context.Collections
            .FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId);

        if (collection is null)
        {
            return false;
        }

        _context.Collections.Remove(collection);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<int> GetCountAsync(int tenantId)
    {
        return await _context.Collections.CountAsync(c => c.TenantId == tenantId);
    }
}

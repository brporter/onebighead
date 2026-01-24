using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Data;

public class ItemTemplateRepository : IItemTemplateRepository
{
    private readonly AppDbContext _context;

    public ItemTemplateRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<ItemTemplate>> GetAllAccessibleAsync(int? tenantId, int? userId)
    {
        return await _context.ItemTemplates
            .Include(t => t.Properties.OrderBy(p => p.SortOrder))
            .Where(t => 
                (t.TenantId == null && t.UserId == null) || // Shared templates
                (t.TenantId == tenantId && t.UserId == userId)) // Personal templates
            .OrderBy(t => t.Name)
            .ToListAsync();
    }

    public async Task<IEnumerable<ItemTemplate>> GetSharedAsync()
    {
        return await _context.ItemTemplates
            .Include(t => t.Properties.OrderBy(p => p.SortOrder))
            .Where(t => t.TenantId == null && t.UserId == null)
            .OrderBy(t => t.Name)
            .ToListAsync();
    }

    public async Task<IEnumerable<ItemTemplate>> GetPersonalAsync(int tenantId, int userId)
    {
        return await _context.ItemTemplates
            .Include(t => t.Properties.OrderBy(p => p.SortOrder))
            .Where(t => t.TenantId == tenantId && t.UserId == userId)
            .OrderBy(t => t.Name)
            .ToListAsync();
    }

    public async Task<ItemTemplate?> GetByIdAsync(int id, int? tenantId, int? userId)
    {
        return await _context.ItemTemplates
            .Include(t => t.Properties.OrderBy(p => p.SortOrder))
            .FirstOrDefaultAsync(t => 
                t.Id == id &&
                ((t.TenantId == null && t.UserId == null) || // Shared templates
                (t.TenantId == tenantId && t.UserId == userId))); // Personal templates
    }

    public async Task<IEnumerable<ItemTemplate>> GetByCollectionAsync(int collectionId)
    {
        return await _context.CollectionItemTemplates
            .Where(ct => ct.CollectionId == collectionId)
            .Include(ct => ct.ItemTemplate)
                .ThenInclude(t => t!.Properties.OrderBy(p => p.SortOrder))
            .Select(ct => ct.ItemTemplate!)
            .OrderBy(t => t.Name)
            .ToListAsync();
    }

    public async Task<ItemTemplate> CreateAsync(ItemTemplate template)
    {
        template.CreatedAt = DateTime.UtcNow;
        template.UpdatedAt = DateTime.UtcNow;
        
        _context.ItemTemplates.Add(template);
        await _context.SaveChangesAsync();
        return template;
    }

    public async Task<ItemTemplate?> UpdateAsync(int id, ItemTemplate template, int? tenantId, int? userId)
    {
        var existing = await _context.ItemTemplates
            .Include(t => t.Properties)
            .FirstOrDefaultAsync(t => 
                t.Id == id &&
                t.TenantId == tenantId && 
                t.UserId == userId);

        if (existing is null)
        {
            return null;
        }

        existing.Name = template.Name;
        existing.Description = template.Description;
        existing.UpdatedAt = DateTime.UtcNow;

        // Replace properties
        _context.ItemTemplateProperties.RemoveRange(existing.Properties);
        
        var sortOrder = 0;
        foreach (var prop in template.Properties)
        {
            existing.Properties.Add(new ItemTemplateProperty
            {
                ItemTemplateId = existing.Id,
                Category = prop.Category,
                Name = prop.Name,
                SortOrder = sortOrder++
            });
        }

        await _context.SaveChangesAsync();
        return existing;
    }

    public async Task<bool> DeleteAsync(int id, int? tenantId, int? userId)
    {
        var template = await _context.ItemTemplates
            .FirstOrDefaultAsync(t => 
                t.Id == id &&
                t.TenantId == tenantId && 
                t.UserId == userId);

        if (template is null)
        {
            return false;
        }

        _context.ItemTemplates.Remove(template);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> AssociateWithCollectionAsync(int templateId, int collectionId)
    {
        var exists = await _context.CollectionItemTemplates
            .AnyAsync(ct => ct.CollectionId == collectionId && ct.ItemTemplateId == templateId);

        if (exists)
        {
            return true; // Already associated
        }

        _context.CollectionItemTemplates.Add(new CollectionItemTemplate
        {
            CollectionId = collectionId,
            ItemTemplateId = templateId
        });

        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DisassociateFromCollectionAsync(int templateId, int collectionId)
    {
        var association = await _context.CollectionItemTemplates
            .FirstOrDefaultAsync(ct => ct.CollectionId == collectionId && ct.ItemTemplateId == templateId);

        if (association is null)
        {
            return false;
        }

        _context.CollectionItemTemplates.Remove(association);
        await _context.SaveChangesAsync();
        return true;
    }
}

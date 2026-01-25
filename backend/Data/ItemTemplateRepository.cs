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

    public async Task<IEnumerable<ItemTemplate>> GetAllAccessibleAsync(int tenantId)
    {
        // Get tenant template names to filter out overridden system templates
        var tenantTemplateNames = await _context.ItemTemplates
            .AsNoTracking()
            .Where(t => t.TenantId == tenantId)
            .Select(t => t.Name)
            .ToListAsync();

        return await _context.ItemTemplates
            .AsNoTracking()
            .Include(t => t.Properties)
            .Where(t => 
                t.TenantId == tenantId || 
                (t.TenantId == null && !tenantTemplateNames.Contains(t.Name)))
            .OrderBy(t => t.Name)
            .ToListAsync();
    }

    public async Task<IEnumerable<ItemTemplate>> GetSystemTemplatesAsync(int tenantId)
    {
        // Get tenant template names to filter out overridden system templates
        var tenantTemplateNames = await _context.ItemTemplates
            .AsNoTracking()
            .Where(t => t.TenantId == tenantId)
            .Select(t => t.Name)
            .ToListAsync();

        return await _context.ItemTemplates
            .AsNoTracking()
            .Include(t => t.Properties)
            .Where(t => t.TenantId == null && !tenantTemplateNames.Contains(t.Name))
            .OrderBy(t => t.Name)
            .ToListAsync();
    }

    public async Task<IEnumerable<ItemTemplate>> GetTenantTemplatesAsync(int tenantId)
    {
        return await _context.ItemTemplates
            .AsNoTracking()
            .Include(t => t.Properties)
            .Where(t => t.TenantId == tenantId)
            .OrderBy(t => t.Name)
            .ToListAsync();
    }

    public async Task<ItemTemplate?> GetByIdAsync(int id, int tenantId)
    {
        return await _context.ItemTemplates
            .AsNoTracking()
            .Include(t => t.Properties)
            .FirstOrDefaultAsync(t => 
                t.Id == id &&
                (t.TenantId == null || t.TenantId == tenantId));
    }

    public async Task<IEnumerable<ItemTemplate>> GetByCollectionAsync(int collectionId)
    {
        return await _context.CollectionItemTemplates
            .AsNoTracking()
            .Where(ct => ct.CollectionId == collectionId)
            .Include(ct => ct.ItemTemplate)
                .ThenInclude(t => t!.Properties)
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

    public async Task<ItemTemplate?> UpdateAsync(int id, ItemTemplate template, int tenantId)
    {
        // Only tenant-owned templates can be updated directly
        var existing = await _context.ItemTemplates
            .Include(t => t.Properties)
            .FirstOrDefaultAsync(t => t.Id == id && t.TenantId == tenantId);

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

    public async Task<ItemTemplate> CopySystemTemplateAsync(int systemTemplateId, int tenantId, ItemTemplate updates)
    {
        var systemTemplate = await _context.ItemTemplates
            .Include(t => t.Properties)
            .FirstOrDefaultAsync(t => t.Id == systemTemplateId && t.TenantId == null);

        if (systemTemplate is null)
        {
            throw new InvalidOperationException("System template not found");
        }

        // Create a new tenant-owned template as a copy
        var newTemplate = new ItemTemplate
        {
            TenantId = tenantId,
            Name = updates.Name,
            Description = updates.Description,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        var sortOrder = 0;
        foreach (var prop in updates.Properties)
        {
            newTemplate.Properties.Add(new ItemTemplateProperty
            {
                Category = prop.Category,
                Name = prop.Name,
                SortOrder = sortOrder++
            });
        }

        _context.ItemTemplates.Add(newTemplate);
        await _context.SaveChangesAsync();
        return newTemplate;
    }

    public async Task<bool> DeleteAsync(int id, int tenantId)
    {
        // Only tenant-owned templates can be deleted
        var template = await _context.ItemTemplates
            .FirstOrDefaultAsync(t => t.Id == id && t.TenantId == tenantId);

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

using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class ItemTemplateRepository : IItemTemplateRepository
{
    private readonly AppDbContext _context;

    public ItemTemplateRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<ItemTemplate>> GetAllAccessibleAsync(int workspaceId)
    {
        // Get workspace template names to filter out overridden system templates
        var workspaceTemplateNames = await _context.ItemTemplates
            .AsNoTracking()
            .Where(t => t.WorkspaceId == workspaceId)
            .Select(t => t.Name)
            .ToListAsync();

        return await _context.ItemTemplates
            .AsNoTracking()
            .Include(t => t.Properties)
            .Where(t =>
                t.WorkspaceId == workspaceId ||
                (t.WorkspaceId == null && !workspaceTemplateNames.Contains(t.Name)))
            .OrderBy(t => t.Name)
            .ToListAsync();
    }

    public async Task<IEnumerable<ItemTemplate>> GetSystemTemplatesAsync(int workspaceId)
    {
        // Get workspace template names to filter out overridden system templates
        var workspaceTemplateNames = await _context.ItemTemplates
            .AsNoTracking()
            .Where(t => t.WorkspaceId == workspaceId)
            .Select(t => t.Name)
            .ToListAsync();

        return await _context.ItemTemplates
            .AsNoTracking()
            .Include(t => t.Properties)
            .Where(t => t.WorkspaceId == null && !workspaceTemplateNames.Contains(t.Name))
            .OrderBy(t => t.Name)
            .ToListAsync();
    }

    public async Task<IEnumerable<ItemTemplate>> GetWorkspaceTemplatesAsync(int workspaceId)
    {
        return await _context.ItemTemplates
            .AsNoTracking()
            .Include(t => t.Properties)
            .Where(t => t.WorkspaceId == workspaceId)
            .OrderBy(t => t.Name)
            .ToListAsync();
    }

    public async Task<ItemTemplate?> GetByIdAsync(int id, int workspaceId)
    {
        return await _context.ItemTemplates
            .AsNoTracking()
            .Include(t => t.Properties)
            .FirstOrDefaultAsync(t =>
                t.Id == id &&
                (t.WorkspaceId == null || t.WorkspaceId == workspaceId));
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

    public async Task<ItemTemplate?> UpdateAsync(int id, ItemTemplate template, int workspaceId)
    {
        // Only workspace-owned templates can be updated directly
        var existing = await _context.ItemTemplates
            .Include(t => t.Properties)
            .FirstOrDefaultAsync(t => t.Id == id && t.WorkspaceId == workspaceId);

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

    public async Task<ItemTemplate> CopySystemTemplateAsync(int systemTemplateId, int workspaceId, ItemTemplate updates)
    {
        var systemTemplate = await _context.ItemTemplates
            .Include(t => t.Properties)
            .FirstOrDefaultAsync(t => t.Id == systemTemplateId && t.WorkspaceId == null);

        if (systemTemplate is null)
        {
            throw new InvalidOperationException("System template not found");
        }

        // Create a new workspace-owned template as a copy
        var newTemplate = new ItemTemplate
        {
            WorkspaceId = workspaceId,
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

    public async Task<bool> DeleteAsync(int id, int workspaceId)
    {
        // Only workspace-owned templates can be deleted
        var template = await _context.ItemTemplates
            .FirstOrDefaultAsync(t => t.Id == id && t.WorkspaceId == workspaceId);

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

    public async Task AssociateMultipleWithCollectionAsync(IEnumerable<int> templateIds, int collectionId)
    {
        var existingTemplateIds = await _context.CollectionItemTemplates
            .Where(ct => ct.CollectionId == collectionId)
            .Select(ct => ct.ItemTemplateId)
            .ToHashSetAsync();

        var newAssociations = templateIds
            .Where(id => !existingTemplateIds.Contains(id))
            .Select(templateId => new CollectionItemTemplate
            {
                CollectionId = collectionId,
                ItemTemplateId = templateId
            })
            .ToList();

        if (newAssociations.Count > 0)
        {
            _context.CollectionItemTemplates.AddRange(newAssociations);
            await _context.SaveChangesAsync();
        }
    }
}

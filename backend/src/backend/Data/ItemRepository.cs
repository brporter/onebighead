using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class ItemRepository : IItemRepository
{
    private readonly AppDbContext _context;

    public ItemRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<Item>> GetAllAsync(int workspaceId)
    {
        return await _context.Items
            .AsNoTracking()
            .Where(i => i.WorkspaceId == workspaceId)
            .ToListAsync();
    }

    public async Task<IEnumerable<Item>> GetByCategoryIdsAsync(IEnumerable<int> categoryIds, int workspaceId)
    {
        var categoryIdSet = categoryIds.ToHashSet();
        return await _context.Items
            .AsNoTracking()
            .Where(i => i.WorkspaceId == workspaceId && i.CategoryId != null && categoryIdSet.Contains(i.CategoryId.Value))
            .ToListAsync();
    }

    public async Task<Item?> GetByIdAsync(int id, int workspaceId)
    {
        return await _context.Items
            .AsNoTracking()
            .FirstOrDefaultAsync(i => i.Id == id && i.WorkspaceId == workspaceId);
    }

    public async Task<Item> CreateAsync(Item item)
    {
        _context.Items.Add(item);
        await _context.SaveChangesAsync();
        return item;
    }

    public async Task<Item?> UpdateAsync(int id, Item item, int workspaceId)
    {
        var existingItem = await _context.Items
            .FirstOrDefaultAsync(i => i.Id == id && i.WorkspaceId == workspaceId);

        if (existingItem is null)
        {
            return null;
        }

        existingItem.Name = item.Name;
        existingItem.Summary = item.Summary;
        existingItem.Description = item.Description;
        existingItem.CategoryId = item.CategoryId;
        existingItem.Properties = item.Properties;
        existingItem.Images = item.Images;
        existingItem.Visibility = item.Visibility;
        existingItem.UserFlag = item.UserFlag;

        await _context.SaveChangesAsync();
        return existingItem;
    }

    public async Task<bool> DeleteAsync(int id, int workspaceId)
    {
        var item = await _context.Items
            .FirstOrDefaultAsync(i => i.Id == id && i.WorkspaceId == workspaceId);

        if (item is null)
        {
            return false;
        }

        _context.Items.Remove(item);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<IEnumerable<Item>> GetByTemplateKeyAsync(Guid templateKey, int workspaceId)
    {
        return await _context.Items
            .Where(i => i.WorkspaceId == workspaceId && i.TemplateKey == templateKey)
            .ToListAsync();
    }

    public async Task<int> CountByTemplateKeyAsync(Guid templateKey, int workspaceId)
    {
        return await _context.Items
            .AsNoTracking()
            .CountAsync(i => i.WorkspaceId == workspaceId && i.TemplateKey == templateKey);
    }

    public async Task<IEnumerable<Item>> GetByCollectionIdAsync(int collectionId, int workspaceId)
    {
        return await _context.Items
            .Where(i => i.WorkspaceId == workspaceId && i.CollectionId == collectionId)
            .ToListAsync();
    }

    public async Task<int> CountByCollectionIdAsync(int collectionId, int workspaceId)
    {
        return await _context.Items
            .AsNoTracking()
            .CountAsync(i => i.WorkspaceId == workspaceId && i.CollectionId == collectionId);
    }

    public async Task<int> CountByCategoryIdAsync(int categoryId, int workspaceId)
    {
        return await _context.Items
            .AsNoTracking()
            .CountAsync(i => i.WorkspaceId == workspaceId && i.CategoryId == categoryId);
    }
}


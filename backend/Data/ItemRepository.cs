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

    public async Task<IEnumerable<Item>> GetAllAsync(int tenantId)
    {
        return await _context.Items
            .AsNoTracking()
            .Where(i => i.TenantId == tenantId)
            .ToListAsync();
    }

    public async Task<IEnumerable<Item>> GetByCategoryIdsAsync(IEnumerable<int> categoryIds, int tenantId)
    {
        var categoryIdSet = categoryIds.ToHashSet();
        return await _context.Items
            .AsNoTracking()
            .Where(i => i.TenantId == tenantId && i.CategoryId != null && categoryIdSet.Contains(i.CategoryId.Value))
            .ToListAsync();
    }

    public async Task<Item?> GetByIdAsync(int id, int tenantId)
    {
        return await _context.Items
            .AsNoTracking()
            .FirstOrDefaultAsync(i => i.Id == id && i.TenantId == tenantId);
    }

    public async Task<Item> CreateAsync(Item item)
    {
        _context.Items.Add(item);
        await _context.SaveChangesAsync();
        return item;
    }

    public async Task<Item?> UpdateAsync(int id, Item item, int tenantId)
    {
        var existingItem = await _context.Items
            .FirstOrDefaultAsync(i => i.Id == id && i.TenantId == tenantId);

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

    public async Task<bool> DeleteAsync(int id, int tenantId)
    {
        var item = await _context.Items
            .FirstOrDefaultAsync(i => i.Id == id && i.TenantId == tenantId);

        if (item is null)
        {
            return false;
        }

        _context.Items.Remove(item);
        await _context.SaveChangesAsync();
        return true;
    }
}


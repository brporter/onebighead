using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class CollectionStatisticsRepository : ICollectionStatisticsRepository
{
    private readonly AppDbContext _context;

    public CollectionStatisticsRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task IncrementAsync(int collectionId, CollectionStatisticType type, long amount = 1)
    {
        var updated = await _context.CollectionStatistics
            .Where(s => s.CollectionId == collectionId && s.StatisticType == type)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.Value, p => p.Value + amount));

        if (updated == 0)
        {
            try
            {
                _context.CollectionStatistics.Add(new CollectionStatistic
                {
                    CollectionId = collectionId,
                    StatisticType = type,
                    Value = amount,
                });
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                _context.ChangeTracker.Clear();
                await _context.CollectionStatistics
                    .Where(s => s.CollectionId == collectionId && s.StatisticType == type)
                    .ExecuteUpdateAsync(s => s.SetProperty(p => p.Value, p => p.Value + amount));
            }
        }
    }

    public async Task DecrementAsync(int collectionId, CollectionStatisticType type, long amount = 1)
    {
        await _context.CollectionStatistics
            .Where(s => s.CollectionId == collectionId && s.StatisticType == type)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.Value, p => p.Value - amount < 0 ? 0 : p.Value - amount));
    }

    public async Task<Dictionary<CollectionStatisticType, long>> GetAggregatesAsync(int collectionId)
    {
        return await _context.CollectionStatistics
            .AsNoTracking()
            .Where(s => s.CollectionId == collectionId)
            .ToDictionaryAsync(s => s.StatisticType, s => s.Value);
    }

    public async Task IncrementItemViewAsync(int collectionId, int itemId)
    {
        var updated = await _context.CollectionItemHighlights
            .Where(h => h.CollectionId == collectionId && h.ItemId == itemId)
            .ExecuteUpdateAsync(h => h.SetProperty(p => p.ViewCount, p => p.ViewCount + 1));

        if (updated == 0)
        {
            try
            {
                _context.CollectionItemHighlights.Add(new CollectionItemHighlight
                {
                    CollectionId = collectionId,
                    ItemId = itemId,
                    ViewCount = 1,
                });
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                _context.ChangeTracker.Clear();
                await _context.CollectionItemHighlights
                    .Where(h => h.CollectionId == collectionId && h.ItemId == itemId)
                    .ExecuteUpdateAsync(h => h.SetProperty(p => p.ViewCount, p => p.ViewCount + 1));
            }
        }
    }

    public async Task<List<CollectionItemHighlight>> GetTopViewedItemsAsync(int collectionId, int count = 10)
    {
        return await _context.CollectionItemHighlights
            .AsNoTracking()
            .Include(h => h.Item)
            .Where(h => h.CollectionId == collectionId)
            .OrderByDescending(h => h.ViewCount)
            .Take(count)
            .ToListAsync();
    }

    public async Task<List<Item>> GetRecentlyAddedItemsAsync(int collectionId, int workspaceId, int count = 10)
    {
        return await _context.Items
            .AsNoTracking()
            .Where(i => i.CollectionId == collectionId && i.WorkspaceId == workspaceId)
            .OrderByDescending(i => i.CreatedAt)
            .Take(count)
            .ToListAsync();
    }

    public async Task RemoveItemHighlightAsync(int collectionId, int itemId)
    {
        await _context.CollectionItemHighlights
            .Where(h => h.CollectionId == collectionId && h.ItemId == itemId)
            .ExecuteDeleteAsync();
    }

    public async Task DeleteCollectionStatsAsync(int collectionId)
    {
        await _context.CollectionStatistics
            .Where(s => s.CollectionId == collectionId)
            .ExecuteDeleteAsync();

        await _context.CollectionItemHighlights
            .Where(h => h.CollectionId == collectionId)
            .ExecuteDeleteAsync();
    }
}

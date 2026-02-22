using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

public class TestCollectionStatisticsRepository : ICollectionStatisticsRepository
{
    private readonly AppDbContext _context;

    public TestCollectionStatisticsRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task IncrementAsync(int collectionId, CollectionStatisticType type, long amount = 1)
    {
        var stat = await _context.CollectionStatistics
            .FirstOrDefaultAsync(s => s.CollectionId == collectionId && s.StatisticType == type);

        if (stat != null)
        {
            stat.Value += amount;
        }
        else
        {
            _context.CollectionStatistics.Add(new CollectionStatistic
            {
                CollectionId = collectionId,
                StatisticType = type,
                Value = amount,
            });
        }

        await _context.SaveChangesAsync();
    }

    public async Task DecrementAsync(int collectionId, CollectionStatisticType type, long amount = 1)
    {
        var stat = await _context.CollectionStatistics
            .FirstOrDefaultAsync(s => s.CollectionId == collectionId && s.StatisticType == type);

        if (stat != null)
        {
            stat.Value = Math.Max(0, stat.Value - amount);
            await _context.SaveChangesAsync();
        }
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
        var highlight = await _context.CollectionItemHighlights
            .FirstOrDefaultAsync(h => h.CollectionId == collectionId && h.ItemId == itemId);

        if (highlight != null)
        {
            highlight.ViewCount += 1;
        }
        else
        {
            _context.CollectionItemHighlights.Add(new CollectionItemHighlight
            {
                CollectionId = collectionId,
                ItemId = itemId,
                ViewCount = 1,
            });
        }

        await _context.SaveChangesAsync();
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
        var highlight = await _context.CollectionItemHighlights
            .FirstOrDefaultAsync(h => h.CollectionId == collectionId && h.ItemId == itemId);

        if (highlight != null)
        {
            _context.CollectionItemHighlights.Remove(highlight);
            await _context.SaveChangesAsync();
        }
    }

    public async Task DeleteCollectionStatsAsync(int collectionId)
    {
        var stats = await _context.CollectionStatistics
            .Where(s => s.CollectionId == collectionId)
            .ToListAsync();
        _context.CollectionStatistics.RemoveRange(stats);

        var highlights = await _context.CollectionItemHighlights
            .Where(h => h.CollectionId == collectionId)
            .ToListAsync();
        _context.CollectionItemHighlights.RemoveRange(highlights);

        await _context.SaveChangesAsync();
    }
}

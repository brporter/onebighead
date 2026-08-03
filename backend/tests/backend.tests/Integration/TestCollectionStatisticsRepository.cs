using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

public class TestCollectionStatisticsRepository : ICollectionStatisticsRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;

    public TestCollectionStatisticsRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task IncrementAsync(int collectionId, CollectionStatisticType type, long amount = 1)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var stat = await context.CollectionStatistics
            .FirstOrDefaultAsync(s => s.CollectionId == collectionId && s.StatisticType == type);

        if (stat != null)
        {
            stat.Value += amount;
        }
        else
        {
            context.CollectionStatistics.Add(new CollectionStatistic
            {
                CollectionId = collectionId,
                StatisticType = type,
                Value = amount,
            });
        }

        await context.SaveChangesAsync();
    }

    public async Task DecrementAsync(int collectionId, CollectionStatisticType type, long amount = 1)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var stat = await context.CollectionStatistics
            .FirstOrDefaultAsync(s => s.CollectionId == collectionId && s.StatisticType == type);

        if (stat != null)
        {
            stat.Value = Math.Max(0, stat.Value - amount);
            await context.SaveChangesAsync();
        }
    }

    public async Task<Dictionary<CollectionStatisticType, long>> GetAggregatesAsync(int collectionId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.CollectionStatistics
            .AsNoTracking()
            .Where(s => s.CollectionId == collectionId)
            .ToDictionaryAsync(s => s.StatisticType, s => s.Value);
    }

    public async Task IncrementItemViewAsync(int collectionId, int itemId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var highlight = await context.CollectionItemHighlights
            .FirstOrDefaultAsync(h => h.CollectionId == collectionId && h.ItemId == itemId);

        if (highlight != null)
        {
            highlight.ViewCount += 1;
        }
        else
        {
            context.CollectionItemHighlights.Add(new CollectionItemHighlight
            {
                CollectionId = collectionId,
                ItemId = itemId,
                ViewCount = 1,
            });
        }

        await context.SaveChangesAsync();
    }

    public async Task<List<CollectionItemHighlight>> GetTopViewedItemsAsync(int collectionId, int count = 10)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.CollectionItemHighlights
            .AsNoTracking()
            .Include(h => h.Item)
            .Where(h => h.CollectionId == collectionId)
            .OrderByDescending(h => h.ViewCount)
            .Take(count)
            .ToListAsync();
    }

    public async Task<List<Item>> GetRecentlyAddedItemsAsync(int collectionId, int workspaceId, int count = 10)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Items
            .AsNoTracking()
            .Where(i => i.CollectionId == collectionId && i.WorkspaceId == workspaceId)
            .OrderByDescending(i => i.CreatedAt)
            .Take(count)
            .ToListAsync();
    }

    public async Task RemoveItemHighlightAsync(int collectionId, int itemId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var highlight = await context.CollectionItemHighlights
            .FirstOrDefaultAsync(h => h.CollectionId == collectionId && h.ItemId == itemId);

        if (highlight != null)
        {
            context.CollectionItemHighlights.Remove(highlight);
            await context.SaveChangesAsync();
        }
    }

    public async Task DeleteCollectionStatsAsync(int collectionId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var stats = await context.CollectionStatistics
            .Where(s => s.CollectionId == collectionId)
            .ToListAsync();
        context.CollectionStatistics.RemoveRange(stats);

        var highlights = await context.CollectionItemHighlights
            .Where(h => h.CollectionId == collectionId)
            .ToListAsync();
        context.CollectionItemHighlights.RemoveRange(highlights);

        await context.SaveChangesAsync();
    }
}

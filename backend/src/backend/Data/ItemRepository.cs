using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace OneBigHead.Server.Data;

public class ItemRepository : IItemRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;
    private readonly IWorkspaceStatisticsRepository _statsRepository;
    private readonly ICollectionStatisticsRepository _collectionStatsRepository;
    private readonly ILogger<ItemRepository> _logger;

    public ItemRepository(IDbContextFactory<AppDbContext> contextFactory, IWorkspaceStatisticsRepository statsRepository, ICollectionStatisticsRepository collectionStatsRepository, ILogger<ItemRepository> logger)
    {
        _contextFactory = contextFactory;
        _statsRepository = statsRepository;
        _collectionStatsRepository = collectionStatsRepository;
        _logger = logger;
    }

    public async Task<IEnumerable<Item>> GetAllAsync(int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Items
            .AsNoTracking()
            .Where(i => i.WorkspaceId == workspaceId)
            .ToListAsync();
    }

    public async Task<IEnumerable<Item>> GetByCategoryIdsAsync(IEnumerable<int> categoryIds, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var categoryIdSet = categoryIds.ToHashSet();
        return await context.Items
            .AsNoTracking()
            .Where(i => i.WorkspaceId == workspaceId && i.CategoryId != null && categoryIdSet.Contains(i.CategoryId.Value))
            .ToListAsync();
    }

    public async Task<Item?> GetByIdAsync(int id, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Items
            .AsNoTracking()
            .FirstOrDefaultAsync(i => i.Id == id && i.WorkspaceId == workspaceId);
    }

    public async Task<Item> CreateAsync(Item item)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        item.CreatedAt = DateTime.UtcNow;
        context.Items.Add(item);
        await context.SaveChangesAsync();
        await _statsRepository.IncrementAsync(item.WorkspaceId, Models.StatisticType.ItemCount);
        await _collectionStatsRepository.IncrementAsync(item.CollectionId, Models.CollectionStatisticType.ItemCount);

        if (item.Images.Count > 0)
        {
            await AdjustCollectionImageStatsAsync(context, item.CollectionId, item.Images, []);
        }

        return item;
    }

    public async Task<Item?> UpdateAsync(int id, Item item, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var existingItem = await context.Items
            .FirstOrDefaultAsync(i => i.Id == id && i.WorkspaceId == workspaceId);

        if (existingItem is null)
        {
            return null;
        }

        var oldImages = existingItem.Images;
        var newImages = item.Images;

        existingItem.Name = item.Name;
        existingItem.Summary = item.Summary;
        existingItem.Description = item.Description;
        existingItem.CategoryId = item.CategoryId;
        existingItem.Properties = item.Properties;
        existingItem.Images = item.Images;
        existingItem.Visibility = item.Visibility;
        existingItem.UserFlag = item.UserFlag;

        await context.SaveChangesAsync();

        await AdjustCollectionImageStatsAsync(context, existingItem.CollectionId, newImages, oldImages);

        return existingItem;
    }

    public async Task<bool> DeleteAsync(int id, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var item = await context.Items
            .FirstOrDefaultAsync(i => i.Id == id && i.WorkspaceId == workspaceId);

        if (item is null)
        {
            return false;
        }

        var collectionId = item.CollectionId;
        var deletedImages = item.Images;

        context.Items.Remove(item);
        await context.SaveChangesAsync();
        await _statsRepository.DecrementAsync(workspaceId, Models.StatisticType.ItemCount);
        await _collectionStatsRepository.DecrementAsync(collectionId, Models.CollectionStatisticType.ItemCount);
        await _collectionStatsRepository.RemoveItemHighlightAsync(collectionId, id);

        if (deletedImages.Count > 0)
        {
            await AdjustCollectionImageStatsAsync(context, collectionId, [], deletedImages);
        }

        return true;
    }

    public async Task<IEnumerable<Item>> GetByTemplateKeyAsync(Guid templateKey, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Items
            .Where(i => i.WorkspaceId == workspaceId && i.TemplateKey == templateKey)
            .ToListAsync();
    }

    public async Task<int> CountByTemplateKeyAsync(Guid templateKey, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Items
            .AsNoTracking()
            .CountAsync(i => i.WorkspaceId == workspaceId && i.TemplateKey == templateKey);
    }

    public async Task<IEnumerable<Item>> GetByCollectionIdAsync(int collectionId, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Items
            .Where(i => i.WorkspaceId == workspaceId && i.CollectionId == collectionId)
            .ToListAsync();
    }

    public async Task<int> CountByCollectionIdAsync(int collectionId, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Items
            .AsNoTracking()
            .CountAsync(i => i.WorkspaceId == workspaceId && i.CollectionId == collectionId);
    }

    public async Task<int> CountByCategoryIdAsync(int categoryId, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Items
            .AsNoTracking()
            .CountAsync(i => i.WorkspaceId == workspaceId && i.CategoryId == categoryId);
    }

    private async Task AdjustCollectionImageStatsAsync(AppDbContext context, int collectionId, List<ItemImage> newImages, List<ItemImage> oldImages)
    {
        var oldUrls = oldImages.Select(i => i.Url).ToHashSet();
        var newUrls = newImages.Select(i => i.Url).ToHashSet();

        var addedGuids = ExtractImageGuids(newUrls.Except(oldUrls));
        var removedGuids = ExtractImageGuids(oldUrls.Except(newUrls));

        if (addedGuids.Count == 0 && removedGuids.Count == 0)
            return;

        var allGuids = addedGuids.Concat(removedGuids).Distinct().ToList();
        var sizes = await context.StoredImages
            .AsNoTracking()
            .Where(s => allGuids.Contains(s.Id))
            .ToDictionaryAsync(s => s.Id, s => (long)s.Data.Length);

        if (addedGuids.Count > 0)
        {
            await _collectionStatsRepository.IncrementAsync(collectionId, Models.CollectionStatisticType.ImageCount, addedGuids.Count);
            var addedSize = SumImageSizes(addedGuids, sizes);
            if (addedSize > 0)
                await _collectionStatsRepository.IncrementAsync(collectionId, Models.CollectionStatisticType.TotalImageSizeBytes, addedSize);
        }

        if (removedGuids.Count > 0)
        {
            await _collectionStatsRepository.DecrementAsync(collectionId, Models.CollectionStatisticType.ImageCount, removedGuids.Count);
            var removedSize = SumImageSizes(removedGuids, sizes);
            if (removedSize > 0)
                await _collectionStatsRepository.DecrementAsync(collectionId, Models.CollectionStatisticType.TotalImageSizeBytes, removedSize);
        }
    }

    private List<Guid> ExtractImageGuids(IEnumerable<string> urls)
    {
        var guids = new List<Guid>();
        foreach (var url in urls)
        {
            // URLs are in the form /api/images/{guid}
            var lastSlash = url.LastIndexOf('/');
            if (lastSlash >= 0 && Guid.TryParse(url[(lastSlash + 1)..], out var guid))
            {
                guids.Add(guid);
            }
            else
            {
                _logger.LogWarning("Failed to extract image GUID from URL: {Url}", url);
            }
        }
        return guids;
    }

    private static long SumImageSizes(List<Guid> guids, Dictionary<Guid, long> sizes)
    {
        long total = 0;
        foreach (var guid in guids)
        {
            if (sizes.TryGetValue(guid, out var size))
            {
                total += size;
            }
        }
        return total;
    }
}


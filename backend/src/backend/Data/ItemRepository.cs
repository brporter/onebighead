using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class ItemRepository : IItemRepository
{
    private readonly AppDbContext _context;
    private readonly IWorkspaceStatisticsRepository _statsRepository;
    private readonly ICollectionStatisticsRepository _collectionStatsRepository;

    public ItemRepository(AppDbContext context, IWorkspaceStatisticsRepository statsRepository, ICollectionStatisticsRepository collectionStatsRepository)
    {
        _context = context;
        _statsRepository = statsRepository;
        _collectionStatsRepository = collectionStatsRepository;
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
        item.CreatedAt = DateTime.UtcNow;
        _context.Items.Add(item);
        await _context.SaveChangesAsync();
        await _statsRepository.IncrementAsync(item.WorkspaceId, Models.StatisticType.ItemCount);
        await _collectionStatsRepository.IncrementAsync(item.CollectionId, Models.CollectionStatisticType.ItemCount);

        if (item.Images.Count > 0)
        {
            await AdjustCollectionImageStatsAsync(item.CollectionId, item.Images, []);
        }

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

        await _context.SaveChangesAsync();

        await AdjustCollectionImageStatsAsync(existingItem.CollectionId, newImages, oldImages);

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

        var collectionId = item.CollectionId;
        var deletedImages = item.Images;

        _context.Items.Remove(item);
        await _context.SaveChangesAsync();
        await _statsRepository.DecrementAsync(workspaceId, Models.StatisticType.ItemCount);
        await _collectionStatsRepository.DecrementAsync(collectionId, Models.CollectionStatisticType.ItemCount);
        await _collectionStatsRepository.RemoveItemHighlightAsync(collectionId, id);

        if (deletedImages.Count > 0)
        {
            await AdjustCollectionImageStatsAsync(collectionId, [], deletedImages);
        }

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

    private async Task AdjustCollectionImageStatsAsync(int collectionId, List<ItemImage> newImages, List<ItemImage> oldImages)
    {
        var oldUrls = oldImages.Select(i => i.Url).ToHashSet();
        var newUrls = newImages.Select(i => i.Url).ToHashSet();

        var addedUrls = newUrls.Except(oldUrls).ToList();
        var removedUrls = oldUrls.Except(newUrls).ToList();

        if (addedUrls.Count == 0 && removedUrls.Count == 0)
            return;

        var allChangedUrls = addedUrls.Concat(removedUrls).ToList();
        var guids = ExtractImageGuids(allChangedUrls);

        var sizes = guids.Count > 0
            ? await _context.StoredImages
                .AsNoTracking()
                .Where(s => guids.Contains(s.Id))
                .ToDictionaryAsync(s => s.Id, s => (long)s.Data.Length)
            : new Dictionary<Guid, long>();

        if (addedUrls.Count > 0)
        {
            await _collectionStatsRepository.IncrementAsync(collectionId, Models.CollectionStatisticType.ImageCount, addedUrls.Count);
            var addedSize = SumImageSizes(addedUrls, sizes);
            if (addedSize > 0)
                await _collectionStatsRepository.IncrementAsync(collectionId, Models.CollectionStatisticType.TotalImageSizeBytes, addedSize);
        }

        if (removedUrls.Count > 0)
        {
            await _collectionStatsRepository.DecrementAsync(collectionId, Models.CollectionStatisticType.ImageCount, removedUrls.Count);
            var removedSize = SumImageSizes(removedUrls, sizes);
            if (removedSize > 0)
                await _collectionStatsRepository.DecrementAsync(collectionId, Models.CollectionStatisticType.TotalImageSizeBytes, removedSize);
        }
    }

    private static List<Guid> ExtractImageGuids(List<string> urls)
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
        }
        return guids;
    }

    private static long SumImageSizes(List<string> urls, Dictionary<Guid, long> sizes)
    {
        long total = 0;
        foreach (var url in urls)
        {
            var lastSlash = url.LastIndexOf('/');
            if (lastSlash >= 0 && Guid.TryParse(url[(lastSlash + 1)..], out var guid) && sizes.TryGetValue(guid, out var size))
            {
                total += size;
            }
        }
        return total;
    }
}


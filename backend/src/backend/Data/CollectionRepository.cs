using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class CollectionRepository : ICollectionRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;
    private readonly IWorkspaceStatisticsRepository _statsRepository;
    private readonly ICollectionStatisticsRepository _collectionStatsRepository;

    public CollectionRepository(IDbContextFactory<AppDbContext> contextFactory, IWorkspaceStatisticsRepository statsRepository, ICollectionStatisticsRepository collectionStatsRepository)
    {
        _contextFactory = contextFactory;
        _statsRepository = statsRepository;
        _collectionStatsRepository = collectionStatsRepository;
    }

    public async Task<IEnumerable<Collection>> GetAllAsync(int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Collections
            .AsNoTracking()
            .Where(c => c.WorkspaceId == workspaceId)
            .OrderBy(c => c.Name)
            .ToListAsync();
    }

    public async Task<Collection?> GetByIdAsync(int id, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Collections
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id && c.WorkspaceId == workspaceId);
    }

    public async Task<Collection?> GetBySlugAsync(string slug, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Collections
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Slug == slug && c.WorkspaceId == workspaceId);
    }

    public async Task<Collection?> GetByWorkspaceIdAsync(int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Collections
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.WorkspaceId == workspaceId);
    }

    public async Task<Collection> CreateAsync(Collection collection)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        context.Collections.Add(collection);
        await context.SaveChangesAsync();
        await _statsRepository.IncrementAsync(collection.WorkspaceId, Models.StatisticType.CollectionCount);
        return collection;
    }

    public async Task<Collection?> UpdateAsync(int id, Collection collection, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var existingCollection = await context.Collections
            .FirstOrDefaultAsync(c => c.Id == id && c.WorkspaceId == workspaceId);

        if (existingCollection is null)
        {
            return null;
        }

        existingCollection.Name = collection.Name;
        existingCollection.Description = collection.Description;
        existingCollection.HeroImageUrl = collection.HeroImageUrl;
        existingCollection.Slug = collection.Slug;
        existingCollection.Visibility = collection.Visibility;

        await context.SaveChangesAsync();
        return existingCollection;
    }

    public async Task<bool> DeleteAsync(int id, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var collection = await context.Collections
            .FirstOrDefaultAsync(c => c.Id == id && c.WorkspaceId == workspaceId);

        if (collection is null)
        {
            return false;
        }

        // Manually delete items since we use Restrict to avoid cascade cycles
        var items = await context.Items
            .Where(i => i.CollectionId == id)
            .ToListAsync();
        var itemCount = items.Count;
        context.Items.RemoveRange(items);

        context.Collections.Remove(collection);
        await context.SaveChangesAsync();

        await _statsRepository.DecrementAsync(workspaceId, Models.StatisticType.CollectionCount);
        if (itemCount > 0)
        {
            await _statsRepository.DecrementAsync(workspaceId, Models.StatisticType.ItemCount, itemCount);
        }

        await _collectionStatsRepository.DeleteCollectionStatsAsync(id);

        return true;
    }

    public async Task<int> GetCountAsync(int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Collections.CountAsync(c => c.WorkspaceId == workspaceId);
    }
}

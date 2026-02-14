using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class CollectionRepository : ICollectionRepository
{
    private readonly AppDbContext _context;
    private readonly IWorkspaceStatisticsRepository _statsRepository;

    public CollectionRepository(AppDbContext context, IWorkspaceStatisticsRepository statsRepository)
    {
        _context = context;
        _statsRepository = statsRepository;
    }

    public async Task<IEnumerable<Collection>> GetAllAsync(int workspaceId)
    {
        return await _context.Collections
            .AsNoTracking()
            .Where(c => c.WorkspaceId == workspaceId)
            .OrderBy(c => c.Name)
            .ToListAsync();
    }

    public async Task<Collection?> GetByIdAsync(int id, int workspaceId)
    {
        return await _context.Collections
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id && c.WorkspaceId == workspaceId);
    }

    public async Task<Collection?> GetBySlugAsync(string slug, int workspaceId)
    {
        return await _context.Collections
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Slug == slug && c.WorkspaceId == workspaceId);
    }

    public async Task<Collection?> GetByWorkspaceIdAsync(int workspaceId)
    {
        return await _context.Collections
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.WorkspaceId == workspaceId);
    }

    public async Task<Collection> CreateAsync(Collection collection)
    {
        _context.Collections.Add(collection);
        await _context.SaveChangesAsync();
        await _statsRepository.IncrementAsync(collection.WorkspaceId, Models.StatisticType.CollectionCount);
        return collection;
    }

    public async Task<Collection?> UpdateAsync(int id, Collection collection, int workspaceId)
    {
        var existingCollection = await _context.Collections
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

        await _context.SaveChangesAsync();
        return existingCollection;
    }

    public async Task<bool> DeleteAsync(int id, int workspaceId)
    {
        var collection = await _context.Collections
            .FirstOrDefaultAsync(c => c.Id == id && c.WorkspaceId == workspaceId);

        if (collection is null)
        {
            return false;
        }

        // Manually delete items since we use Restrict to avoid SQL Server cascade cycles
        var items = await _context.Items
            .Where(i => i.CollectionId == id)
            .ToListAsync();
        var itemCount = items.Count;
        _context.Items.RemoveRange(items);

        _context.Collections.Remove(collection);
        await _context.SaveChangesAsync();

        await _statsRepository.DecrementAsync(workspaceId, Models.StatisticType.CollectionCount);
        if (itemCount > 0)
        {
            await _statsRepository.DecrementAsync(workspaceId, Models.StatisticType.ItemCount, itemCount);
        }

        return true;
    }

    public async Task<int> GetCountAsync(int workspaceId)
    {
        return await _context.Collections.CountAsync(c => c.WorkspaceId == workspaceId);
    }
}

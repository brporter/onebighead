using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class CollectionRepository : ICollectionRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;
    public CollectionRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
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

}

using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class WorkspaceRepository : IWorkspaceRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;

    public WorkspaceRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task<Workspace?> GetByIdAsync(int id)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Workspaces.FirstOrDefaultAsync(t => t.Id == id);
    }

    public async Task UpdateAsync(Workspace workspace)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        context.Workspaces.Update(workspace);
        await context.SaveChangesAsync();
    }

    public async Task CreateAsync(Workspace workspace)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        context.Workspaces.Add(workspace);
        await context.SaveChangesAsync();
    }

    public async Task<WorkspaceStats> GetStatsAsync(int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return new WorkspaceStats
        {
            CollectionCount = await context.Collections.CountAsync(c => c.WorkspaceId == workspaceId),
            ItemCount = await context.Items.CountAsync(i => i.WorkspaceId == workspaceId),
            CategoryCount = await context.Categories.CountAsync(c => c.WorkspaceId == workspaceId),
            ImageCount = await context.StoredImages.CountAsync(i => i.WorkspaceId == workspaceId)
        };
    }

    public async Task<Workspace?> GetBySlugAsync(string slug)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Workspaces
            .AsNoTracking()
            .FirstOrDefaultAsync(w => w.Slug == slug && !w.IsDeleted);
    }

    public async Task<bool> IsSlugTakenAsync(string slug, int? excludeWorkspaceId = null)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Workspaces
            .AnyAsync(w => w.Slug == slug && !w.IsDeleted && (!excludeWorkspaceId.HasValue || w.Id != excludeWorkspaceId.Value));
    }
}

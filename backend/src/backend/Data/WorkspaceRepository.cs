using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class WorkspaceRepository : IWorkspaceRepository
{
    private readonly AppDbContext _context;

    public WorkspaceRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<Workspace?> GetByIdAsync(int id)
    {
        return await _context.Workspaces.FirstOrDefaultAsync(t => t.Id == id);
    }

    public async Task UpdateAsync(Workspace workspace)
    {
        _context.Workspaces.Update(workspace);
        await _context.SaveChangesAsync();
    }

    public async Task CreateAsync(Workspace workspace)
    {
        _context.Workspaces.Add(workspace);
        await _context.SaveChangesAsync();
    }

    public async Task<WorkspaceStats> GetStatsAsync(int workspaceId)
    {
        return new WorkspaceStats
        {
            CollectionCount = await _context.Collections.CountAsync(c => c.WorkspaceId == workspaceId),
            ItemCount = await _context.Items.CountAsync(i => i.WorkspaceId == workspaceId),
            CategoryCount = await _context.Categories.CountAsync(c => c.WorkspaceId == workspaceId),
            ImageCount = await _context.StoredImages.CountAsync(i => i.WorkspaceId == workspaceId)
        };
    }

    public async Task<Workspace?> GetBySlugAsync(string slug)
    {
        return await _context.Workspaces
            .AsNoTracking()
            .FirstOrDefaultAsync(w => w.Slug == slug && w.IsPublicAccessEnabled && !w.IsDeleted);
    }
}

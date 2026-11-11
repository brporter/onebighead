using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class WorkspaceUserRepository : IWorkspaceUserRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;

    public WorkspaceUserRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task<WorkspaceUser?> GetMembershipAsync(int userId, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.WorkspaceUsers
            .Include(tu => tu.Workspace)
            .Include(tu => tu.User)
            .FirstOrDefaultAsync(tu => tu.UserId == userId && tu.WorkspaceId == workspaceId);
    }

    public async Task<IEnumerable<WorkspaceUser>> GetByUserIdAsync(int userId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.WorkspaceUsers
            .Include(tu => tu.Workspace)
            .Where(tu => tu.UserId == userId)
            .OrderBy(tu => tu.CreatedAt)
            .ToListAsync();
    }

    public async Task<IEnumerable<WorkspaceUser>> GetByWorkspaceIdAsync(int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.WorkspaceUsers
            .Include(tu => tu.User)
            .Where(tu => tu.WorkspaceId == workspaceId)
            .OrderBy(tu => tu.CreatedAt)
            .ToListAsync();
    }

    public async Task<IEnumerable<WorkspaceUser>> GetAdminMembershipsIncludingDeletedAsync(int userId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.WorkspaceUsers
            .Include(wu => wu.Workspace)
            .Where(wu => wu.UserId == userId && wu.WorkspaceRole == WorkspaceRole.WorkspaceAdmin)
            .ToListAsync();
    }
}

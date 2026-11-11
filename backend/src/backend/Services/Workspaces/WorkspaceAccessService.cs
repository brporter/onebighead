using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Services.Workspaces;

/// <summary>Read-only checks used by the active-workspace middleware.</summary>
public sealed class WorkspaceAccessService(IDbContextFactory<AppDbContext> contextFactory) : IWorkspaceAccessService
{
    public async Task<bool> IsWorkspaceDeletedAsync(int workspaceId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        return !await context.Workspaces.AnyAsync(w => w.Id == workspaceId && !w.IsDeleted);
    }

    public async Task<bool> IsUserDeletedAsync(int userId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        return !await context.Users.AnyAsync(u => u.Id == userId && !u.IsDeleted);
    }

    public async Task<bool> HasUserAnyActiveWorkspaceAsync(int userId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        return await context.WorkspaceUsers.AnyAsync(m => m.UserId == userId && !m.Workspace.IsDeleted);
    }
}

using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Workspaces;

/// <summary>Counts workspace-owned resources for deletion review.</summary>
public sealed class WorkspaceSummaryService(IDbContextFactory<AppDbContext> contextFactory) : IWorkspaceSummaryService
{
    public async Task<WorkspaceStatsResponse?> GetWorkspaceStatsAsync(int workspaceId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var workspace = await context.Workspaces.AsNoTracking().SingleOrDefaultAsync(w => w.Id == workspaceId && !w.IsDeleted);
        if (workspace is null) return null;

        return new WorkspaceStatsResponse
        {
            WorkspaceId = workspace.Id,
            WorkspaceName = workspace.Name,
            CollectionCount = await context.Collections.CountAsync(c => c.WorkspaceId == workspaceId),
            CategoryCount = await context.Categories.CountAsync(c => c.WorkspaceId == workspaceId),
            ItemCount = await context.Items.CountAsync(i => i.WorkspaceId == workspaceId),
            ImageCount = await context.StoredImages.CountAsync(i => i.WorkspaceId == workspaceId),
            UserCount = await context.WorkspaceUsers.CountAsync(m => m.WorkspaceId == workspaceId),
            AdminCount = await context.WorkspaceUsers.CountAsync(m => m.WorkspaceId == workspaceId && m.WorkspaceRole == WorkspaceRole.WorkspaceAdmin)
        };
    }
}

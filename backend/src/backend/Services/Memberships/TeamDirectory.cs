using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Memberships;

public sealed class TeamDirectory(IDbContextFactory<AppDbContext> contextFactory) : ITeamDirectory
{
    public async Task<IReadOnlyList<WorkspaceUserResponse>?> ReadAsync(int actorId, int workspaceId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        // Authorization and the roster share one database snapshot. A separate
        // permission lookup could be stale before the roster is read.
        var administrators = TeamAdministrator.Membership(context, actorId, workspaceId);
        var workspace = await context.Workspaces.AsNoTracking().Where(w => w.Id == workspaceId && administrators.Any())
            .Include(w => w.WorkspaceUsers).ThenInclude(m => m.User)
            .AsSingleQuery().SingleOrDefaultAsync();
        return workspace?.WorkspaceUsers.OrderBy(m => m.CreatedAt).ThenBy(m => m.UserId)
            .Select(WorkspaceUserResponse.FromWorkspaceUser).ToArray();
    }
}

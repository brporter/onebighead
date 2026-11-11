using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Memberships;

internal static class TeamAdministrator
{
    public static IQueryable<WorkspaceUser> Membership(AppDbContext context, int actorId, int workspaceId) =>
        context.WorkspaceUsers.Where(m => m.WorkspaceId == workspaceId && m.UserId == actorId &&
            m.WorkspaceRole == WorkspaceRole.WorkspaceAdmin && !m.Workspace.IsDeleted && !m.User.IsDeleted);
}

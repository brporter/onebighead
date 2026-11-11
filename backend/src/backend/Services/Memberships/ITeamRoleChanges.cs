using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Memberships;

public interface ITeamRoleChanges
{
    Task<TeamMembershipResult> ChangeRoleAsync(int actorId, int workspaceId, int userId, WorkspaceRole role);
}

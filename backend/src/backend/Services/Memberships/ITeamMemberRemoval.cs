namespace OneBigHead.Server.Services.Memberships;

public interface ITeamMemberRemoval
{
    Task<TeamMembershipResult> RemoveAsync(int actorId, int workspaceId, int userId);
}

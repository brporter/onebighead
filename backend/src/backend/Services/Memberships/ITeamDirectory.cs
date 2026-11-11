using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Memberships;

public interface ITeamDirectory
{
    /// <summary>Returns the current team, or null when the actor cannot administer it.</summary>
    Task<IReadOnlyList<WorkspaceUserResponse>?> ReadAsync(int actorId, int workspaceId);
}

using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface IWorkspaceUserRepository
{
    Task<WorkspaceUser?> GetMembershipAsync(int userId, int workspaceId);
    Task<IEnumerable<WorkspaceUser>> GetByUserIdAsync(int userId);
    Task<IEnumerable<WorkspaceUser>> GetByWorkspaceIdAsync(int workspaceId);
    /// <summary>
    /// Gets admin memberships for a user including deleted workspaces.
    /// Used for the restorable workspaces feature.
    /// </summary>
    Task<IEnumerable<WorkspaceUser>> GetAdminMembershipsIncludingDeletedAsync(int userId);
}

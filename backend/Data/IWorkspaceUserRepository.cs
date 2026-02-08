using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

/// <summary>
/// Result of an atomic admin check operation.
/// </summary>
public enum AdminCheckResult
{
    Success,
    UserNotFound,
    WouldRemoveLastAdmin
}

[GenerateTracingProxy]
public interface IWorkspaceUserRepository
{
    Task<WorkspaceUser?> GetMembershipAsync(int userId, int workspaceId);
    Task<IEnumerable<WorkspaceUser>> GetByUserIdAsync(int userId);
    Task<IEnumerable<WorkspaceUser>> GetByWorkspaceIdAsync(int workspaceId);
    Task<WorkspaceUser> CreateAsync(int userId, int workspaceId, WorkspaceRole role);
    Task<bool> UpdateRoleAsync(int userId, int workspaceId, WorkspaceRole role);
    Task<bool> DeleteAsync(int userId, int workspaceId);
    Task<int> CountAdminsInWorkspaceAsync(int workspaceId);
    Task<int> CountMembersInWorkspaceAsync(int workspaceId);
    Task<int> CountUserMembershipsAsync(int userId);

    /// <summary>
    /// Atomically updates a user's role with admin count check.
    /// Prevents demoting the last admin in a workspace.
    /// </summary>
    Task<AdminCheckResult> UpdateRoleWithAdminCheckAsync(int userId, int workspaceId, WorkspaceRole newRole);

    /// <summary>
    /// Atomically deletes a workspace user with admin count check.
    /// Prevents removing the last admin in a workspace.
    /// </summary>
    Task<AdminCheckResult> DeleteWithAdminCheckAsync(int userId, int workspaceId);

    /// <summary>
    /// Gets admin memberships for a user including deleted workspaces.
    /// Used for the restorable workspaces feature.
    /// </summary>
    Task<IEnumerable<WorkspaceUser>> GetAdminMembershipsIncludingDeletedAsync(int userId);
}

using OneBigHead.Server.Models;

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

public interface ITenantUserRepository
{
    Task<TenantUser?> GetMembershipAsync(int userId, int tenantId);
    Task<IEnumerable<TenantUser>> GetByUserIdAsync(int userId);
    Task<IEnumerable<TenantUser>> GetByTenantIdAsync(int tenantId);
    Task<TenantUser> CreateAsync(int userId, int tenantId, TenantRole role);
    Task<bool> UpdateRoleAsync(int userId, int tenantId, TenantRole role);
    Task<bool> DeleteAsync(int userId, int tenantId);
    Task<int> CountAdminsInTenantAsync(int tenantId);
    Task<int> CountMembersInTenantAsync(int tenantId);
    Task<int> CountUserMembershipsAsync(int userId);

    /// <summary>
    /// Atomically updates a user's role with admin count check.
    /// Prevents demoting the last admin in a tenant.
    /// </summary>
    Task<AdminCheckResult> UpdateRoleWithAdminCheckAsync(int userId, int tenantId, TenantRole newRole);

    /// <summary>
    /// Atomically deletes a tenant user with admin count check.
    /// Prevents removing the last admin in a tenant.
    /// </summary>
    Task<AdminCheckResult> DeleteWithAdminCheckAsync(int userId, int tenantId);
}

using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

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
}

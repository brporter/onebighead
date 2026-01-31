using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface IUserRepository
{
    Task<User?> GetByEmailAsync(string email);
    Task<User?> GetByProviderIdAsync(IdentityProvider provider, string providerSubjectId);
    Task<User> CreateWithNewTenantAsync(string email, IdentityProvider provider, string providerSubjectId);
    Task<User?> GetByIdAsync(int id);
    Task<IEnumerable<User>> GetByTenantIdAsync(int tenantId);
    Task<User> CreatePendingUserAsync(int tenantId, string email, TenantRole role);
    Task<User?> LinkUserAsync(int userId, IdentityProvider provider, string providerSubjectId);
    Task<bool> UpdateRoleAsync(int userId, int tenantId, TenantRole role);
    Task<bool> DeleteByIdAndTenantAsync(int userId, int tenantId);
    Task<int> CountAdminsInTenantAsync(int tenantId);
    Task UpdateAsync(User user);
}



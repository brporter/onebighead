using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface IUserRepository
{
    Task<User?> GetByEmailAsync(string email);
    Task<User?> GetByProviderIdAsync(IdentityProvider provider, string providerSubjectId);
    Task<User> CreateWithNewTenantAsync(string email, IdentityProvider provider, string providerSubjectId);
    Task<User?> GetByIdAsync(int id);
}



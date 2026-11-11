using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface IUserRepository
{
    Task<User?> GetByEmailAsync(string email);
    Task<User> CreateWithNewWorkspaceAsync(string email, IdentityProvider provider, string providerSubjectId);
    Task<User?> GetByIdAsync(int id);
    Task UpdateAsync(User user);
}



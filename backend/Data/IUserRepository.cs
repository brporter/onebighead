using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface IUserRepository
{
    Task<User?> GetByEmailAsync(string email);
    Task<User?> GetByProviderIdAsync(IdentityProvider provider, string providerSubjectId);
    Task<User> CreateWithNewWorkspaceAsync(string email, IdentityProvider provider, string providerSubjectId);
    Task<User?> GetByIdAsync(int id);
    Task<User?> GetByIdWithMembershipsAsync(int id);
    Task<IEnumerable<User>> GetByWorkspaceIdAsync(int workspaceId);
    Task<User> CreatePendingUserAsync(int workspaceId, string email, WorkspaceRole role);
    Task<User?> LinkUserAsync(int userId, IdentityProvider provider, string providerSubjectId);
    Task<bool> DeleteByIdAndWorkspaceAsync(int userId, int workspaceId);
    Task<bool> DeleteAsync(int userId);
    Task UpdateAsync(User user);
    Task UpdateActiveWorkspaceAsync(int userId, int workspaceId);
}



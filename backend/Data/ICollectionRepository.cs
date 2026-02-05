using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface ICollectionRepository
{
    Task<IEnumerable<Collection>> GetAllAsync(int workspaceId);
    Task<Collection?> GetByIdAsync(int id, int workspaceId);
    Task<Collection?> GetBySlugAsync(string slug, int workspaceId);
    Task<Collection?> GetByWorkspaceIdAsync(int workspaceId);
    Task<Collection> CreateAsync(Collection collection);
    Task<Collection?> UpdateAsync(int id, Collection collection, int workspaceId);
    Task<bool> DeleteAsync(int id, int workspaceId);
    Task<int> GetCountAsync(int workspaceId);
}

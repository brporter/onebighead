using backend.Models;

namespace backend.Data;

public interface ICollectionRepository
{
    Task<IEnumerable<Collection>> GetAllAsync(int tenantId);
    Task<Collection?> GetByIdAsync(int id, int tenantId);
    Task<Collection?> GetBySlugAsync(string slug, int tenantId);
    Task<Collection> CreateAsync(Collection collection);
    Task<Collection?> UpdateAsync(int id, Collection collection, int tenantId);
    Task<bool> DeleteAsync(int id, int tenantId);
    Task<int> GetCountAsync(int tenantId);
}

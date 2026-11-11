using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface ICategoryRepository
{
    Task<IEnumerable<Category>> GetAllAsync(int workspaceId);
    Task<IEnumerable<Category>> GetByCollectionAsync(int collectionId, int workspaceId);
    Task<Category?> GetByIdAsync(int id, int workspaceId);

}


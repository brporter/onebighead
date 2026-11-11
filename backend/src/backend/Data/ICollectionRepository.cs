using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface ICollectionRepository
{
    Task<IEnumerable<Collection>> GetAllAsync(int workspaceId);
    Task<Collection?> GetByIdAsync(int id, int workspaceId);
    Task<Collection?> GetBySlugAsync(string slug, int workspaceId);
}

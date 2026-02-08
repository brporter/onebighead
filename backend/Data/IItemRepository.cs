using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface IItemRepository
{
    Task<IEnumerable<Item>> GetAllAsync(int workspaceId);
    Task<IEnumerable<Item>> GetByCategoryIdsAsync(IEnumerable<int> categoryIds, int workspaceId);
    Task<Item?> GetByIdAsync(int id, int workspaceId);
    Task<Item> CreateAsync(Item item);
    Task<Item?> UpdateAsync(int id, Item item, int workspaceId);
    Task<bool> DeleteAsync(int id, int workspaceId);
}


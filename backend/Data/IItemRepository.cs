using backend.Models;

namespace backend.Data;

public interface IItemRepository
{
    Task<IEnumerable<Item>> GetAllAsync(int tenantId);
    Task<IEnumerable<Item>> GetByCategoryIdsAsync(IEnumerable<int> categoryIds, int tenantId);
    Task<Item?> GetByIdAsync(int id, int tenantId);
    Task<Item> CreateAsync(Item item);
    Task<Item?> UpdateAsync(int id, Item item, int tenantId);
    Task<bool> DeleteAsync(int id, int tenantId);
}


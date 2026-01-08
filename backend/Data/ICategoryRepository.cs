using backend.Models;

namespace backend.Data;

public interface ICategoryRepository
{
    Task<IEnumerable<Category>> GetAllAsync(int tenantId);
    Task<IEnumerable<Category>> GetByCollectionAsync(int collectionId, int tenantId);
    Task<Category?> GetByIdAsync(int id, int tenantId);
    Task<Category?> GetSystemCategoryAsync(int collectionId, int tenantId, string name);
    Task<Category> CreateAsync(Category category);
    Task<Category?> UpdateAsync(int id, Category category, int tenantId);
    Task<bool> DeleteAsync(int id, int tenantId);
}


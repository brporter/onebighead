using backend.Models;

namespace backend.Data;

public interface ICategoryRepository
{
    Task<IEnumerable<Category>> GetAllAsync(int tenantId);
    Task<IEnumerable<Category>> GetByCollectionAsync(int collectionId, int tenantId);
    Task<Category?> GetByIdAsync(int id, int tenantId);
    Task<Category?> GetSystemCategoryAsync(int collectionId, int tenantId, string name);
    Task<Category> CreateAsync(Category category);
    Task<IEnumerable<Category>> CreateManyAsync(IEnumerable<Category> categories);
    Task<Category?> UpdateAsync(int id, Category category, int tenantId);
    Task<bool> DeleteAsync(int id, int tenantId);
    
    // Template association methods
    Task<List<int>> GetTemplateIdsAsync(int categoryId, int tenantId);
    Task<Dictionary<int, List<int>>> GetTemplateIdsByCategoryAsync(int collectionId, int tenantId);
    Task SetTemplateIdsAsync(int categoryId, List<int> templateIds, int tenantId);
    Task<List<int>> GetInheritedTemplateIdsAsync(int categoryId, int tenantId);
}


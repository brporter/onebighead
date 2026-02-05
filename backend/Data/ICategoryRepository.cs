using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface ICategoryRepository
{
    Task<IEnumerable<Category>> GetAllAsync(int workspaceId);
    Task<IEnumerable<Category>> GetByCollectionAsync(int collectionId, int workspaceId);
    Task<Category?> GetByIdAsync(int id, int workspaceId);
    Task<Category?> GetSystemCategoryAsync(int collectionId, int workspaceId, string name);
    Task<Category> CreateAsync(Category category);
    Task<IEnumerable<Category>> CreateManyAsync(IEnumerable<Category> categories);
    Task<Category?> UpdateAsync(int id, Category category, int workspaceId);
    Task<bool> DeleteAsync(int id, int workspaceId);

    // Template association methods
    Task<List<int>> GetTemplateIdsAsync(int categoryId, int workspaceId);
    Task<Dictionary<int, List<int>>> GetTemplateIdsByCategoryAsync(int collectionId, int workspaceId);
    Task SetTemplateIdsAsync(int categoryId, List<int> templateIds, int workspaceId);
    Task<List<int>> GetInheritedTemplateIdsAsync(int categoryId, int workspaceId);
}


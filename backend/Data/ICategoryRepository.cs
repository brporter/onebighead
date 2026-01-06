using backend.Models;

namespace backend.Data;

public interface ICategoryRepository
{
    Task<IEnumerable<Category>> GetAllAsync(int tenantId);
    Task<Category?> GetByIdAsync(int id, int tenantId);
    Task<Category> CreateAsync(Category category);
    Task<Category?> UpdateAsync(int id, Category category, int tenantId);
    Task<bool> DeleteAsync(int id, int tenantId);
}


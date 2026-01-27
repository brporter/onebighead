using backend.Models;

namespace backend.Data;

public interface IThemeRepository
{
    Task<IEnumerable<CollectionTheme>> GetAllAsync();
    Task<CollectionTheme?> GetByIdAsync(int id);
}

using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface IThemeRepository
{
    Task<IEnumerable<CollectionTheme>> GetAllAsync();
    Task<CollectionTheme?> GetByIdAsync(int id);
}

using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface IThemeRepository
{
    Task<IEnumerable<CollectionTheme>> GetAllAsync();
    Task<CollectionTheme?> GetByIdAsync(int id);
}

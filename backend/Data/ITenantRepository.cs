using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface ITenantRepository
{
    Task<Tenant?> GetByIdAsync(int id);
    Task UpdateAsync(Tenant tenant);
}

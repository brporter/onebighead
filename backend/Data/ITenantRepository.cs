using backend.Models;

namespace backend.Data;

public interface ITenantRepository
{
    Task<Tenant?> GetByIdAsync(int id);
    Task UpdateAsync(Tenant tenant);
}

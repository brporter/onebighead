using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Administration;

public interface IAdministratorUsers
{
    Task<bool> DeleteAsync(int id);
    Task<UserSummaryResponse?> SetAdministratorAsync(int id, bool enabled);
}

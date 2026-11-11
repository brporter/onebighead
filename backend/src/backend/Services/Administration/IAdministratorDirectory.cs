using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Administration;

public interface IAdministratorDirectory
{
    Task<IReadOnlyList<WorkspaceSummaryResponse>> GetWorkspacesAsync();
    Task<IReadOnlyList<UserSummaryResponse>> GetUsersAsync(string? email);
}

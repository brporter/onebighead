using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.Workspaces;

[GenerateTracingProxy]
public interface IWorkspaceAccessService
{
    Task<bool> IsWorkspaceDeletedAsync(int workspaceId);
    Task<bool> IsUserDeletedAsync(int userId);
    Task<bool> HasUserAnyActiveWorkspaceAsync(int userId);
}

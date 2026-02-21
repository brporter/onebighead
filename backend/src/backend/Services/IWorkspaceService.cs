using OneBigHead.Server.DTOs;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services;

[GenerateTracingProxy]
public interface IWorkspaceService
{
    Task<WorkspaceStatsResponse?> GetWorkspaceStatsAsync(int workspaceId);
    Task<WorkspaceDeletionResponse> SoftDeleteWorkspaceAsync(int workspaceId, int deletedByUserId);
    Task<bool> IsWorkspaceDeletedAsync(int workspaceId);
    Task<bool> IsUserDeletedAsync(int userId);
    Task<bool> HasUserAnyActiveWorkspaceAsync(int userId);
}
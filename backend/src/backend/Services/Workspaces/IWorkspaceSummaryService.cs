using OneBigHead.Server.DTOs;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.Workspaces;

[GenerateTracingProxy]
public interface IWorkspaceSummaryService
{
    Task<WorkspaceStatsResponse?> GetWorkspaceStatsAsync(int workspaceId);
}

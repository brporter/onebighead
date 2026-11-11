using OneBigHead.Server.DTOs;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.Workspaces;

[GenerateTracingProxy]
public interface IWorkspaceDeletionService
{
    /// <summary>
    /// Deletes a workspace after verifying current administrator membership.
    /// </summary>
    Task<WorkspaceDeletionResult> SoftDeleteWorkspaceAsync(int workspaceId, int deletedByUserId);
}

public enum WorkspaceDeletionStatus { Deleted, NotFound, Forbidden, Conflict }

public sealed record WorkspaceDeletionResult(WorkspaceDeletionStatus Status,
    WorkspaceDeletionResponse? Response = null, CurrentUserSession? Session = null, string? Error = null);

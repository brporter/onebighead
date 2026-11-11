using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Workspaces;

public interface IWorkspaceDetails
{
    Task<WorkspaceDetailsResult> UpdateAsync(int userId, int workspaceId, UpdateWorkspaceRequest request);
}

public enum WorkspaceDetailsStatus { Updated, NotFound, Forbidden, Invalid, Conflict }

public sealed record WorkspaceDetailsResult(WorkspaceDetailsStatus Status, UpdateWorkspaceResponse? Workspace = null, string? Error = null);

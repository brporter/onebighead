using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Workspaces;

public interface IWorkspaceCreation
{
    Task<WorkspaceCreationResult> CreateAsync(int userId, CreateWorkspaceRequest request);
}

public enum WorkspaceCreationStatus { Created, Forbidden, Invalid, Conflict }

public sealed record WorkspaceCreationResult(WorkspaceCreationStatus Status, CreateWorkspaceResponse? Workspace = null, string? Error = null);

using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Workspaces;

public interface IWorkspaceWelcome
{
    Task<WorkspaceWelcomeResult> CompleteAsync(int userId, int workspaceId, CompleteWelcomeRequest request);
}

public enum WorkspaceWelcomeStatus { Completed, NotFound, Forbidden, Invalid, Conflict }

public sealed record WorkspaceWelcomeResult(WorkspaceWelcomeStatus Status, CompleteWelcomeResponse? Workspace = null, string? Error = null);

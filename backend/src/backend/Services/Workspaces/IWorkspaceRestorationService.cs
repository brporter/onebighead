using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Workspaces;

/// <summary>Restores only workspaces administered by the requesting user.</summary>
public interface IWorkspaceRestorationService
{
    Task<WorkspaceRestorationResult> RestoreAsync(int userId, int workspaceId, CancellationToken cancellationToken = default);
    Task<WorkspaceRestorationResult> RestoreAndActivateAsync(int userId, IReadOnlyCollection<int> workspaceIds, CancellationToken cancellationToken = default);
}

/// <summary>Committed entities for the HTTP adapter; ActiveUser is present only when the session must change.</summary>
public sealed record WorkspaceRestorationResult(bool IsAuthorized, IReadOnlyList<Workspace> RestoredWorkspaces, User? ActiveUser);

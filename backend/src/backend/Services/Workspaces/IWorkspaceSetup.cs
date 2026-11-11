using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Workspaces;

public interface IWorkspaceSetup
{
    Task<WorkspaceSetupResult> CreateAsync(int userId, SetupWorkspaceRequest request);
}

public enum WorkspaceSetupStatus { Created, Forbidden, Invalid, Conflict, Unavailable }

public sealed record WorkspaceSetupResult(WorkspaceSetupStatus Status, SetupWorkspaceResponse? Workspace = null,
    CurrentUserSession? Session = null, string? Error = null);

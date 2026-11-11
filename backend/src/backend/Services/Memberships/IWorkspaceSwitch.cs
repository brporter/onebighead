using OneBigHead.Server.Authentication;

namespace OneBigHead.Server.Services.Memberships;

public interface IWorkspaceSwitch
{
    Task<WorkspaceSwitchResult> SwitchAsync(int userId, int workspaceId);
}

public enum WorkspaceSwitchStatus { Switched, Forbidden, Conflict }

public sealed record WorkspaceSwitchResult(WorkspaceSwitchStatus Status, string? Error = null, CurrentUserSession? Session = null);

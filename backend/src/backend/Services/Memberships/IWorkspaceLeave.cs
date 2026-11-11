using OneBigHead.Server.Authentication;

namespace OneBigHead.Server.Services.Memberships;

public enum WorkspaceLeaveStatus { Left, NotFound, Invalid, Conflict }

public sealed record WorkspaceLeaveResult(
    WorkspaceLeaveStatus Status, string? Error = null, CurrentUserSession? Session = null);

/// <summary>Removes the caller's membership, selects an active workspace and revokes old tokens as one unit.</summary>
public interface IWorkspaceLeave
{
    Task<WorkspaceLeaveResult> LeaveAsync(int userId, int workspaceId);
}

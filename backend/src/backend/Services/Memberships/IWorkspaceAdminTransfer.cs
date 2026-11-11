using OneBigHead.Server.Authentication;

namespace OneBigHead.Server.Services.Memberships;

public enum WorkspaceAdminTransferStatus { Transferred, NotFound, Forbidden, Invalid, Conflict }

public sealed record WorkspaceAdminTransferResult(
    WorkspaceAdminTransferStatus Status, string? Error = null, CurrentUserSession? Session = null);

/// <summary>Transfers a current administrator's role and revokes stale tokens atomically.</summary>
public interface IWorkspaceAdminTransfer
{
    Task<WorkspaceAdminTransferResult> TransferAsync(int userId, int workspaceId, int newAdminUserId);
}

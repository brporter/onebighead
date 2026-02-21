using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

/// <summary>
/// Information about a specific workspace membership for deletion purposes.
/// </summary>
public class WorkspaceMembershipDeletionInfo
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public WorkspaceRole Role { get; set; }
    public bool IsOnlyUser { get; set; }
    public bool IsOnlyAdmin { get; set; }
    public int UserCount { get; set; }
    public bool CanLeave { get; set; }
    public DeletionBlockerReason BlockerReason { get; set; }
    /// <summary>
    /// Other users in the workspace, for admin transfer selection.
    /// </summary>
    public List<UserBasicInfo> OtherUsers { get; set; } = new();
}
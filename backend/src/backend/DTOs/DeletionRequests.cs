using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

/// <summary>
/// Statistics about a workspace's data, used for deletion confirmation.
/// </summary>
public class WorkspaceStatsResponse
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public int CollectionCount { get; set; }
    public int CategoryCount { get; set; }
    public int ItemCount { get; set; }
    public int ImageCount { get; set; }
    public int UserCount { get; set; }
    public int AdminCount { get; set; }
}

/// <summary>
/// Result of a workspace deletion operation.
/// </summary>
public class WorkspaceDeletionResponse
{
    public bool Success { get; set; }
    /// <summary>
    /// The new active workspace ID for the user, if they were switched to another workspace.
    /// </summary>
    public int? NewActiveWorkspaceId { get; set; }
    /// <summary>
    /// True if the user account was also soft-deleted (single-workspace admin scenario).
    /// Frontend should log out and redirect to homepage.
    /// </summary>
    public bool UserSoftDeleted { get; set; }
}

/// <summary>
/// Information about a user's deletion blockers and requirements.
/// </summary>
public class UserDeletionInfoResponse
{
    public int UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public List<WorkspaceMembershipDeletionInfo> WorkspaceMemberships { get; set; } = new();
    public int WorkspacesRequiringAction { get; set; }
    public bool CanDeleteImmediately { get; set; }
}

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

/// <summary>
/// Basic user information for admin transfer selection.
/// </summary>
public class UserBasicInfo
{
    public int UserId { get; set; }
    public string Email { get; set; } = string.Empty;
}

/// <summary>
/// Reasons why a user cannot immediately delete their account.
/// </summary>
public enum DeletionBlockerReason
{
    /// <summary>No blocker - user can leave this workspace freely.</summary>
    None,
    /// <summary>User is the only member of this workspace.</summary>
    SoleUser,
    /// <summary>User is the only admin in a workspace with other users.</summary>
    SoleAdmin
}

/// <summary>
/// Types of actions a user can take on a workspace during account deletion.
/// </summary>
public enum WorkspaceActionType
{
    /// <summary>Delete the workspace (when user is sole member).</summary>
    Delete,
    /// <summary>Transfer admin role to another user.</summary>
    Transfer
}

/// <summary>
/// Request to delete a user account.
/// </summary>
public class DeleteUserRequest
{
    /// <summary>
    /// User must confirm their email address to delete their account.
    /// </summary>
    [Required]
    public string ConfirmEmail { get; set; } = string.Empty;

    /// <summary>
    /// Actions to take on each workspace that requires resolution.
    /// </summary>
    public List<WorkspaceActionRequest> WorkspaceActions { get; set; } = new();
}

/// <summary>
/// Action to take on a specific workspace during account deletion.
/// </summary>
public class WorkspaceActionRequest
{
    public int WorkspaceId { get; set; }
    public WorkspaceActionType Action { get; set; }
    /// <summary>
    /// User ID to transfer admin role to (required when Action is Transfer).
    /// </summary>
    public int? TransferToUserId { get; set; }
}

/// <summary>
/// Result of a user account deletion operation.
/// </summary>
public class DeleteUserResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// Request to transfer admin role to another user.
/// </summary>
public class TransferAdminRequest
{
    [Required]
    public int NewAdminUserId { get; set; }
}

/// <summary>
/// Result of an admin transfer operation.
/// </summary>
public class TransferAdminResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
}

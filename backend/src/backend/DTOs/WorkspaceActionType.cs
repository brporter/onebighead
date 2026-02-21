namespace OneBigHead.Server.DTOs;

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
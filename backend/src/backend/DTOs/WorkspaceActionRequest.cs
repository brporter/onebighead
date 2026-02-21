namespace OneBigHead.Server.DTOs;

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
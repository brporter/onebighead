namespace OneBigHead.Server.DTOs;

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
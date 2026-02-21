namespace OneBigHead.Server.DTOs;

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
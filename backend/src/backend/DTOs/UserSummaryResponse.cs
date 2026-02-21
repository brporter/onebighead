namespace OneBigHead.Server.DTOs;

public class UserSummaryResponse
{
    public int UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public string IdentityProvider { get; set; } = string.Empty;
    public bool IsSystemAdministrator { get; set; }
    public DateTime CreatedAt { get; set; }
}
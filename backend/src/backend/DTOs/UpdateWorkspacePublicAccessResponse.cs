namespace OneBigHead.Server.DTOs;

/// <summary>
/// Response containing workspace public access settings
/// </summary>
public class UpdateWorkspacePublicAccessResponse
{
    public int WorkspaceId { get; set; }
    public string? Slug { get; set; }
    public bool IsPublicAccessEnabled { get; set; }
    public string? PublicUrl { get; set; }
}

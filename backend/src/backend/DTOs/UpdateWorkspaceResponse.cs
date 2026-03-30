namespace OneBigHead.Server.DTOs;

public class UpdateWorkspaceResponse
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public string? Slug { get; set; }
    public string? PublicUrl { get; set; }
}
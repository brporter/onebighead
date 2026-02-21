namespace OneBigHead.Server.DTOs;

public class AuthCallbackResponse
{
    public bool Success { get; set; }
    public string Email { get; set; } = string.Empty;
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
}
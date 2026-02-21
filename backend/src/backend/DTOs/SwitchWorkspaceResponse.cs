namespace OneBigHead.Server.DTOs;

public class SwitchWorkspaceResponse
{
    public bool Success { get; set; }
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
}
namespace OneBigHead.Server.DTOs;

/// <summary>
/// Response from restoring a single workspace
/// </summary>
public class RestoreWorkspaceResponse
{
    public int WorkspaceId { get; set; }
    public string Name { get; set; } = string.Empty;
}
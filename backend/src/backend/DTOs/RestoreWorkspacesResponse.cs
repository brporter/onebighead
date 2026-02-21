namespace OneBigHead.Server.DTOs;

/// <summary>
/// Response from restoring workspaces
/// </summary>
public class RestoreWorkspacesResponse
{
    public List<int> RestoredWorkspaceIds { get; set; } = new();
    public int ActiveWorkspaceId { get; set; }
}
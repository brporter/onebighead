namespace OneBigHead.Server.DTOs;

/// <summary>
/// Request to restore multiple soft-deleted workspaces
/// </summary>
public class RestoreWorkspacesRequest
{
    public List<int> WorkspaceIds { get; set; } = new();
}
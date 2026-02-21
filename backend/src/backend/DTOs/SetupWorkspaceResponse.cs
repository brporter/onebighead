using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

/// <summary>
/// Response from setting up a new workspace
/// </summary>
public class SetupWorkspaceResponse
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public WorkspaceRole WorkspaceRole { get; set; }
    public int CollectionId { get; set; }
    public string CollectionName { get; set; } = string.Empty;
}
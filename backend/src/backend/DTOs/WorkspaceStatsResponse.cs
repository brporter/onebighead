namespace OneBigHead.Server.DTOs;

/// <summary>
/// Statistics about a workspace's data, used for deletion confirmation.
/// </summary>
public class WorkspaceStatsResponse
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public int CollectionCount { get; set; }
    public int CategoryCount { get; set; }
    public int ItemCount { get; set; }
    public int ImageCount { get; set; }
    public int UserCount { get; set; }
    public int AdminCount { get; set; }
}
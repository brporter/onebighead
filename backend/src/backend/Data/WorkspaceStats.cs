namespace OneBigHead.Server.Data;

/// <summary>
/// Statistics for a workspace.
/// </summary>
public class WorkspaceStats
{
    public int CollectionCount { get; set; }
    public int ItemCount { get; set; }
    public int CategoryCount { get; set; }
    public int ImageCount { get; set; }
}
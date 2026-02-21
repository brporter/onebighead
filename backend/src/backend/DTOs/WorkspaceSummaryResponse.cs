namespace OneBigHead.Server.DTOs;

public class WorkspaceSummaryResponse
{
    public int WorkspaceId { get; set; }
    public string Name { get; set; } = string.Empty;
    public int UserCount { get; set; }
    public int CollectionCount { get; set; }
    public int ItemCount { get; set; }
    public int ImageCount { get; set; }
    public DateTime CreatedAt { get; set; }
}
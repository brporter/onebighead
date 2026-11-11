namespace OneBigHead.Server.DTOs;

public sealed class CompleteWelcomeResponse
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public bool HasCompletedWelcome { get; set; }
    public int? CollectionId { get; set; }
    public string? CollectionName { get; set; }
}

namespace OneBigHead.Server.DTOs;

/// <summary>
/// A soft-deleted workspace that the user can restore
/// </summary>
public class RestorableWorkspaceResponse
{
    public int WorkspaceId { get; set; }
    public string Name { get; set; } = string.Empty;
    public DateTime DeletedAt { get; set; }
    public int DaysRemaining { get; set; }
    public RestorableWorkspaceStats Stats { get; set; } = new();
}
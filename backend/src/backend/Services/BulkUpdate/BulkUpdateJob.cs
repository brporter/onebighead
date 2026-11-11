namespace OneBigHead.Server.Services.BulkUpdate;

public class BulkUpdateJob
{
    public Guid JobId { get; set; } = Guid.NewGuid();
    public int WorkspaceId { get; set; }
    public int RequestedByUserId { get; init; }
    public BulkUpdateTarget Target { get; init; } = null!;
    public PropertyDiff Diff { get; set; } = null!;
    public List<PropertyIdentifier> NewPropertyOrder { get; set; } = new();
    public BulkUpdateJobStatus Status { get; set; } = BulkUpdateJobStatus.Queued;
    public int TotalItems { get; set; }
    public int ProcessedItems { get; set; }
    public int FailedItems { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; set; }
}

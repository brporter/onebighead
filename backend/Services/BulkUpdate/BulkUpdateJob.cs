namespace OneBigHead.Server.Services.BulkUpdate;

public enum BulkUpdateScope
{
    Template,
    Category,
    Collection
}

public enum BulkUpdateJobStatus
{
    Queued,
    Running,
    Completed,
    Failed
}

public class BulkUpdateJob
{
    public Guid JobId { get; set; } = Guid.NewGuid();
    public int WorkspaceId { get; set; }
    public BulkUpdateScope Scope { get; set; }
    public Guid? TemplateKey { get; set; }
    public int? CategoryId { get; set; }
    public int? CollectionId { get; set; }
    public PropertyDiff Diff { get; set; } = null!;
    public List<PropertyIdentifier> NewPropertyOrder { get; set; } = new();
    public int? ExcludeItemId { get; set; }
    public BulkUpdateJobStatus Status { get; set; } = BulkUpdateJobStatus.Queued;
    public int TotalItems { get; set; }
    public int ProcessedItems { get; set; }
    public int FailedItems { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; set; }
}

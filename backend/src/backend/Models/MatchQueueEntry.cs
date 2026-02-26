using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.Models;

public class MatchQueueEntry
{
    [Key]
    public int Id { get; set; }
    public int ItemId { get; set; }
    public int WorkspaceId { get; set; }
    public MatchQueueReason Reason { get; set; }
    public MatchQueueStatus Status { get; set; } = MatchQueueStatus.Pending;
    public DateTime EnqueuedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ProcessedAt { get; set; }
    [MaxLength(500)]
    public string? ErrorMessage { get; set; }
    public int RetryCount { get; set; } = 0;
}

public enum MatchQueueReason
{
    ItemCreated = 0,
    ItemEdited = 1,
    UserFlagChanged = 2
}

public enum MatchQueueStatus
{
    Pending = 0,
    Processing = 1,
    Completed = 2,
    Failed = 3
}

namespace OneBigHead.Server.DTOs;

public class BulkUpdateJobResponse
{
    public Guid JobId { get; set; }
    public string Status { get; set; } = string.Empty;
    public int TotalItems { get; set; }
    public int ProcessedItems { get; set; }
    public int FailedItems { get; set; }
    public string? ErrorMessage { get; set; }
}
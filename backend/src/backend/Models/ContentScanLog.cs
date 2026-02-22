namespace OneBigHead.Server.Models;

public class ContentScanLog
{
    public Guid Id { get; set; }
    public int WorkspaceId { get; set; }
    public int? UserId { get; set; }
    public string ScannerName { get; set; } = string.Empty;
    public bool IsMatch { get; set; }
    public double MatchScore { get; set; }
    public string? Details { get; set; }
    public string? OriginalFileName { get; set; }
    public string ContentType { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public string? ImageHash { get; set; }
    public DateTime ScannedAt { get; set; }
    public bool ReportSubmitted { get; set; }
    public DateTime? ReportedAt { get; set; }
}

using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.Models;

public class ItemMatch
{
    [Key]
    public int Id { get; set; }
    public int WantItemId { get; set; }
    public int WantWorkspaceId { get; set; }
    public int TradeItemId { get; set; }
    public int TradeWorkspaceId { get; set; }
    public double ConfidenceScore { get; set; }
    [MaxLength(1000)]
    public string MatchReason { get; set; } = string.Empty;
    public MatchStatus WantUserStatus { get; set; } = MatchStatus.New;
    public MatchStatus TradeUserStatus { get; set; } = MatchStatus.New;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public enum MatchStatus
{
    New = 0,
    Saved = 1,
    Dismissed = 2
}

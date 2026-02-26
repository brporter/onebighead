using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class MatchItemSummary
{
    public int ItemId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string? PrimaryImageUrl { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public int WorkspaceId { get; set; }
}

public class MatchResponse
{
    public int Id { get; set; }
    public MatchItemSummary WantItem { get; set; } = new();
    public MatchItemSummary TradeItem { get; set; } = new();
    public double ConfidenceScore { get; set; }
    public string MatchReason { get; set; } = string.Empty;
    public MatchStatus MyStatus { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool HasUnreadMessages { get; set; }
}

public class MatchListResponse
{
    public List<MatchResponse> Matches { get; set; } = [];
    public int TotalCount { get; set; }
}

public class UpdateMatchStatusRequest
{
    [Required]
    public MatchStatus Status { get; set; }
}

public class CreateMatchMessageRequest
{
    [Required]
    [MaxLength(2000)]
    public string Message { get; set; } = string.Empty;
}

public class MatchMessageResponse
{
    public int Id { get; set; }
    public string Message { get; set; } = string.Empty;
    public bool IsMine { get; set; }
    public bool IsRead { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class MatchCountResponse
{
    public int NewMatchCount { get; set; }
    public int UnreadMessageCount { get; set; }
}

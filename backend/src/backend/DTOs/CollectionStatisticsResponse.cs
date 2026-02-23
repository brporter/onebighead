using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class CollectionStatisticsResponse
{
    public long ItemCount { get; set; }
    public long ImageCount { get; set; }
    public long TotalImageSizeBytes { get; set; }
    public List<CollectionItemHighlightResponse> TopViewedItems { get; set; } = new();
    public List<RecentItemResponse> RecentlyAddedItems { get; set; } = new();
}

public class CollectionItemHighlightResponse
{
    public int ItemId { get; set; }
    public string ItemName { get; set; } = string.Empty;
    public long ViewCount { get; set; }
}

public class RecentItemResponse
{
    public int ItemId { get; set; }
    public string ItemName { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

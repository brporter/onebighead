namespace OneBigHead.Server.DTOs;

public class DashboardResponse
{
    public long CollectionCount { get; set; }
    public long ItemCount { get; set; }
    public long ImageCount { get; set; }
    public long ImageTotalSizeBytes { get; set; }
    public List<DailyViewResponse> DailyViews { get; set; } = new();
}
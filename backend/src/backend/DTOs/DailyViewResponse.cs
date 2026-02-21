namespace OneBigHead.Server.DTOs;

public class DailyViewResponse
{
    public string Date { get; set; } = string.Empty;
    public long ViewCount { get; set; }
}
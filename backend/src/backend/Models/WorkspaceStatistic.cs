namespace OneBigHead.Server.Models;

public class WorkspaceStatistic
{
    public int Id { get; set; }
    public int WorkspaceId { get; set; }
    public StatisticType StatisticType { get; set; }
    public DateOnly Date { get; set; }
    public long Value { get; set; }
}

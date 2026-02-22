namespace OneBigHead.Server.Models;

public class CollectionStatistic
{
    public int Id { get; set; }
    public int CollectionId { get; set; }
    public CollectionStatisticType StatisticType { get; set; }
    public long Value { get; set; }
}

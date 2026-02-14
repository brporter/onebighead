using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

public record DailyStatistic(DateOnly Date, long Value);

[GenerateTracingProxy]
public interface IWorkspaceStatisticsRepository
{
    Task IncrementAsync(int workspaceId, StatisticType type, long amount = 1, DateOnly? date = null);
    Task DecrementAsync(int workspaceId, StatisticType type, long amount = 1);
    Task<Dictionary<StatisticType, long>> GetAggregatesAsync(int workspaceId);
    Task<List<DailyStatistic>> GetDailyAsync(int workspaceId, StatisticType type, DateOnly from, DateOnly to);
}

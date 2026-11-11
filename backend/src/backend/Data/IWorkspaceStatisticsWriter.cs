using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

/// <summary>Updates counters using the caller's context and transaction.</summary>
public interface IWorkspaceStatisticsWriter
{
    Task IncrementAsync(AppDbContext context, int workspaceId, StatisticType type, long amount = 1, DateOnly? date = null);
}

using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

/// <summary>Decrements aggregate counters in the caller's transaction without changing daily history.</summary>
public interface IWorkspaceStatisticsDecrementer
{
    Task DecrementAsync(AppDbContext context, int workspaceId, StatisticType type, long amount = 1, CancellationToken cancellationToken = default);
}

using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public sealed class WorkspaceStatisticsWriter : IWorkspaceStatisticsWriter, IWorkspaceStatisticsDecrementer
{
    public Task DecrementAsync(AppDbContext context, int workspaceId, StatisticType type, long amount = 1, CancellationToken cancellationToken = default) =>
        context.WorkspaceStatistics
            .Where(statistic => statistic.WorkspaceId == workspaceId && statistic.StatisticType == type && statistic.Date == DateOnly.MinValue)
            .ExecuteUpdateAsync(set => set.SetProperty(statistic => statistic.Value,
                statistic => statistic.Value - amount < 0 ? 0 : statistic.Value - amount), cancellationToken);

    public Task IncrementAsync(AppDbContext context, int workspaceId, StatisticType type, long amount = 1, DateOnly? date = null)
    {
        var effectiveDate = date ?? DateOnly.MinValue;
        return context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO "WorkspaceStatistics" ("WorkspaceId", "StatisticType", "Date", "Value")
            VALUES ({workspaceId}, {(int)type}, {effectiveDate}, {amount})
            ON CONFLICT ("WorkspaceId", "StatisticType", "Date")
            DO UPDATE SET "Value" = "WorkspaceStatistics"."Value" + EXCLUDED."Value"
            """);
    }
}

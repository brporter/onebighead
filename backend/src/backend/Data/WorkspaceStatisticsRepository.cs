using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class WorkspaceStatisticsRepository : IWorkspaceStatisticsRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;

    public WorkspaceStatisticsRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task IncrementAsync(int workspaceId, StatisticType type, long amount = 1, DateOnly? date = null)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var effectiveDate = date ?? DateOnly.MinValue;

        var updated = await context.WorkspaceStatistics
            .Where(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date == effectiveDate)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.Value, p => p.Value + amount));

        if (updated == 0)
        {
            try
            {
                context.WorkspaceStatistics.Add(new WorkspaceStatistic
                {
                    WorkspaceId = workspaceId,
                    StatisticType = type,
                    Date = effectiveDate,
                    Value = amount,
                });
                await context.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                // Concurrent insert — retry the update
                context.ChangeTracker.Clear();
                await context.WorkspaceStatistics
                    .Where(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date == effectiveDate)
                    .ExecuteUpdateAsync(s => s.SetProperty(p => p.Value, p => p.Value + amount));
            }
        }
    }

    public async Task DecrementAsync(int workspaceId, StatisticType type, long amount = 1)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        // Decrement aggregate stats only (sentinel date), floor at 0
        await context.WorkspaceStatistics
            .Where(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date == DateOnly.MinValue)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.Value, p => p.Value - amount < 0 ? 0 : p.Value - amount));
    }

    public async Task<Dictionary<StatisticType, long>> GetAggregatesAsync(int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.WorkspaceStatistics
            .AsNoTracking()
            .Where(s => s.WorkspaceId == workspaceId && s.Date == DateOnly.MinValue)
            .ToDictionaryAsync(s => s.StatisticType, s => s.Value);
    }

    public async Task<List<DailyStatistic>> GetDailyAsync(int workspaceId, StatisticType type, DateOnly from, DateOnly to)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.WorkspaceStatistics
            .AsNoTracking()
            .Where(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date >= from && s.Date <= to)
            .OrderBy(s => s.Date)
            .Select(s => new DailyStatistic(s.Date, s.Value))
            .ToListAsync();
    }
}

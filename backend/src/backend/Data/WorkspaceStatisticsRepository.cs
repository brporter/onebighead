using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class WorkspaceStatisticsRepository : IWorkspaceStatisticsRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;
    private readonly IWorkspaceStatisticsWriter _writer;
    private readonly IWorkspaceStatisticsDecrementer _decrementer;

    public WorkspaceStatisticsRepository(IDbContextFactory<AppDbContext> contextFactory, IWorkspaceStatisticsWriter writer, IWorkspaceStatisticsDecrementer decrementer)
    {
        _contextFactory = contextFactory;
        _writer = writer;
        _decrementer = decrementer;
    }

    public async Task IncrementAsync(int workspaceId, StatisticType type, long amount = 1, DateOnly? date = null)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        await _writer.IncrementAsync(context, workspaceId, type, amount, date);
    }

    public async Task DecrementAsync(int workspaceId, StatisticType type, long amount = 1)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        await _decrementer.DecrementAsync(context, workspaceId, type, amount);
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

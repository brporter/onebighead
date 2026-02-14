using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class WorkspaceStatisticsRepository : IWorkspaceStatisticsRepository
{
    private readonly AppDbContext _context;

    public WorkspaceStatisticsRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task IncrementAsync(int workspaceId, StatisticType type, long amount = 1, DateOnly? date = null)
    {
        var effectiveDate = date ?? DateOnly.MinValue;

        var updated = await _context.WorkspaceStatistics
            .Where(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date == effectiveDate)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.Value, p => p.Value + amount));

        if (updated == 0)
        {
            try
            {
                _context.WorkspaceStatistics.Add(new WorkspaceStatistic
                {
                    WorkspaceId = workspaceId,
                    StatisticType = type,
                    Date = effectiveDate,
                    Value = amount,
                });
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                // Concurrent insert — retry the update
                _context.ChangeTracker.Clear();
                await _context.WorkspaceStatistics
                    .Where(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date == effectiveDate)
                    .ExecuteUpdateAsync(s => s.SetProperty(p => p.Value, p => p.Value + amount));
            }
        }
    }

    public async Task DecrementAsync(int workspaceId, StatisticType type, long amount = 1)
    {
        // Decrement aggregate stats only (sentinel date), floor at 0
        await _context.WorkspaceStatistics
            .Where(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date == DateOnly.MinValue)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.Value, p => p.Value - amount < 0 ? 0 : p.Value - amount));
    }

    public async Task<Dictionary<StatisticType, long>> GetAggregatesAsync(int workspaceId)
    {
        return await _context.WorkspaceStatistics
            .AsNoTracking()
            .Where(s => s.WorkspaceId == workspaceId && s.Date == DateOnly.MinValue)
            .ToDictionaryAsync(s => s.StatisticType, s => s.Value);
    }

    public async Task<List<DailyStatistic>> GetDailyAsync(int workspaceId, StatisticType type, DateOnly from, DateOnly to)
    {
        return await _context.WorkspaceStatistics
            .AsNoTracking()
            .Where(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date >= from && s.Date <= to)
            .OrderBy(s => s.Date)
            .Select(s => new DailyStatistic(s.Date, s.Value))
            .ToListAsync();
    }
}

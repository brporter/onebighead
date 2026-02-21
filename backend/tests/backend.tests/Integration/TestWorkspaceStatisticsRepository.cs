using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

/// <summary>
/// Test workspace statistics repository that uses simple in-memory operations
/// instead of ExecuteUpdateAsync (which is unsupported by the EF Core in-memory provider).
/// </summary>
public class TestWorkspaceStatisticsRepository : IWorkspaceStatisticsRepository
{
    private readonly AppDbContext _context;

    public TestWorkspaceStatisticsRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task IncrementAsync(int workspaceId, StatisticType type, long amount = 1, DateOnly? date = null)
    {
        var effectiveDate = date ?? DateOnly.MinValue;

        var stat = await _context.WorkspaceStatistics
            .FirstOrDefaultAsync(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date == effectiveDate);

        if (stat != null)
        {
            stat.Value += amount;
        }
        else
        {
            _context.WorkspaceStatistics.Add(new WorkspaceStatistic
            {
                WorkspaceId = workspaceId,
                StatisticType = type,
                Date = effectiveDate,
                Value = amount,
            });
        }

        await _context.SaveChangesAsync();
    }

    public async Task DecrementAsync(int workspaceId, StatisticType type, long amount = 1)
    {
        var stat = await _context.WorkspaceStatistics
            .FirstOrDefaultAsync(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date == DateOnly.MinValue);

        if (stat != null)
        {
            stat.Value = Math.Max(0, stat.Value - amount);
            await _context.SaveChangesAsync();
        }
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
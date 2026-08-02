using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class ContentScanLogRepository : IContentScanLogRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;

    public ContentScanLogRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task<ContentScanLog> CreateAsync(ContentScanLog scanLog)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        context.ContentScanLogs.Add(scanLog);
        await context.SaveChangesAsync();
        return scanLog;
    }

    public async Task<ContentScanLog?> GetByIdAsync(Guid id)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.ContentScanLogs
            .AsNoTracking()
            .FirstOrDefaultAsync(l => l.Id == id);
    }

    public async Task UpdateAsync(ContentScanLog scanLog)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        context.ContentScanLogs.Update(scanLog);
        await context.SaveChangesAsync();
    }
}

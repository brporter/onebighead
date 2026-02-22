using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class ContentScanLogRepository : IContentScanLogRepository
{
    private readonly AppDbContext _context;

    public ContentScanLogRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<ContentScanLog> CreateAsync(ContentScanLog scanLog)
    {
        _context.ContentScanLogs.Add(scanLog);
        await _context.SaveChangesAsync();
        return scanLog;
    }

    public async Task<ContentScanLog?> GetByIdAsync(Guid id)
    {
        return await _context.ContentScanLogs
            .AsNoTracking()
            .FirstOrDefaultAsync(l => l.Id == id);
    }

    public async Task UpdateAsync(ContentScanLog scanLog)
    {
        _context.ContentScanLogs.Update(scanLog);
        await _context.SaveChangesAsync();
    }
}

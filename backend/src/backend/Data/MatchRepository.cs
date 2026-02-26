using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class MatchRepository : IMatchRepository
{
    private readonly AppDbContext _context;

    public MatchRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<ItemMatch?> GetByIdAsync(int matchId)
    {
        return await _context.ItemMatches
            .AsNoTracking()
            .FirstOrDefaultAsync(m => m.Id == matchId);
    }

    public async Task<ItemMatch?> GetByItemPairAsync(int wantItemId, int tradeItemId)
    {
        return await _context.ItemMatches
            .FirstOrDefaultAsync(m => m.WantItemId == wantItemId && m.TradeItemId == tradeItemId);
    }

    public async Task<ItemMatch> CreateAsync(ItemMatch match)
    {
        match.CreatedAt = DateTime.UtcNow;
        _context.ItemMatches.Add(match);
        await _context.SaveChangesAsync();
        return match;
    }

    public async Task UpdateAsync(ItemMatch match)
    {
        var existing = await _context.ItemMatches
            .FirstOrDefaultAsync(m => m.Id == match.Id);

        if (existing != null)
        {
            existing.ConfidenceScore = match.ConfidenceScore;
            existing.MatchReason = match.MatchReason;
            existing.WantUserStatus = match.WantUserStatus;
            existing.TradeUserStatus = match.TradeUserStatus;
            await _context.SaveChangesAsync();
        }
    }

    public async Task DeleteByItemIdAsync(int itemId)
    {
        var matches = await _context.ItemMatches
            .Where(m => m.WantItemId == itemId || m.TradeItemId == itemId)
            .ToListAsync();

        if (matches.Count > 0)
        {
            // Delete associated messages first
            var matchIds = matches.Select(m => m.Id).ToList();
            var messages = await _context.MatchMessages
                .Where(msg => matchIds.Contains(msg.ItemMatchId))
                .ToListAsync();
            _context.MatchMessages.RemoveRange(messages);
            _context.ItemMatches.RemoveRange(matches);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<List<ItemMatch>> GetMatchesForWorkspaceAsync(
        int workspaceId, MatchStatus? status, int skip, int take)
    {
        var query = _context.ItemMatches
            .AsNoTracking()
            .Where(m => m.WantWorkspaceId == workspaceId || m.TradeWorkspaceId == workspaceId);

        if (status.HasValue)
        {
            // Filter by the status on the requesting workspace's side
            query = query.Where(m =>
                (m.WantWorkspaceId == workspaceId && m.WantUserStatus == status.Value) ||
                (m.TradeWorkspaceId == workspaceId && m.TradeUserStatus == status.Value));
        }

        return await query
            .OrderByDescending(m => m.CreatedAt)
            .Skip(skip)
            .Take(take)
            .ToListAsync();
    }

    public async Task<int> GetNewMatchCountAsync(int workspaceId)
    {
        return await _context.ItemMatches
            .AsNoTracking()
            .CountAsync(m =>
                (m.WantWorkspaceId == workspaceId && m.WantUserStatus == MatchStatus.New) ||
                (m.TradeWorkspaceId == workspaceId && m.TradeUserStatus == MatchStatus.New));
    }

    public async Task<List<ItemMatch>> GetMatchesForItemAsync(int itemId)
    {
        return await _context.ItemMatches
            .AsNoTracking()
            .Where(m => m.WantItemId == itemId || m.TradeItemId == itemId)
            .ToListAsync();
    }

    public async Task<MatchQueueEntry> EnqueueAsync(MatchQueueEntry entry)
    {
        entry.EnqueuedAt = DateTime.UtcNow;
        _context.MatchQueueEntries.Add(entry);
        await _context.SaveChangesAsync();
        return entry;
    }

    public async Task<List<MatchQueueEntry>> DequeueAsync(int batchSize)
    {
        var entries = await _context.MatchQueueEntries
            .Where(q => q.Status == MatchQueueStatus.Pending)
            .OrderBy(q => q.EnqueuedAt)
            .Take(batchSize)
            .ToListAsync();

        foreach (var entry in entries)
        {
            entry.Status = MatchQueueStatus.Processing;
        }

        if (entries.Count > 0)
        {
            await _context.SaveChangesAsync();
        }

        return entries;
    }

    public async Task UpdateQueueEntryAsync(MatchQueueEntry entry)
    {
        var existing = await _context.MatchQueueEntries
            .FirstOrDefaultAsync(q => q.Id == entry.Id);

        if (existing != null)
        {
            existing.Status = entry.Status;
            existing.ProcessedAt = entry.ProcessedAt;
            existing.ErrorMessage = entry.ErrorMessage;
            existing.RetryCount = entry.RetryCount;
            await _context.SaveChangesAsync();
        }
    }

    public async Task DeduplicateQueueAsync(int itemId)
    {
        // Remove pending duplicates for the same item, keeping only the latest
        var pendingEntries = await _context.MatchQueueEntries
            .Where(q => q.ItemId == itemId && q.Status == MatchQueueStatus.Pending)
            .OrderByDescending(q => q.EnqueuedAt)
            .ToListAsync();

        if (pendingEntries.Count > 1)
        {
            var toRemove = pendingEntries.Skip(1).ToList();
            _context.MatchQueueEntries.RemoveRange(toRemove);
            await _context.SaveChangesAsync();
        }
    }
}

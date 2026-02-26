using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class MatchMessageRepository : IMatchMessageRepository
{
    private readonly AppDbContext _context;

    public MatchMessageRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<List<MatchMessage>> GetByMatchIdAsync(int matchId, int skip, int take)
    {
        return await _context.MatchMessages
            .AsNoTracking()
            .Where(m => m.ItemMatchId == matchId)
            .OrderBy(m => m.CreatedAt)
            .Skip(skip)
            .Take(take)
            .ToListAsync();
    }

    public async Task<MatchMessage> CreateAsync(MatchMessage message)
    {
        message.CreatedAt = DateTime.UtcNow;
        _context.MatchMessages.Add(message);
        await _context.SaveChangesAsync();
        return message;
    }

    public async Task MarkAsReadAsync(int matchId, int readerWorkspaceId)
    {
        // Mark all messages in this match as read where they were NOT sent by the reader's workspace
        var unreadMessages = await _context.MatchMessages
            .Where(m => m.ItemMatchId == matchId &&
                        m.SenderWorkspaceId != readerWorkspaceId &&
                        !m.IsRead)
            .ToListAsync();

        foreach (var message in unreadMessages)
        {
            message.IsRead = true;
        }

        if (unreadMessages.Count > 0)
        {
            await _context.SaveChangesAsync();
        }
    }

    public async Task<int> GetUnreadCountAsync(int workspaceId)
    {
        // Count unread messages in matches where this workspace participates,
        // that were sent by the OTHER workspace
        return await _context.MatchMessages
            .AsNoTracking()
            .Where(m => !m.IsRead &&
                        m.SenderWorkspaceId != workspaceId &&
                        m.ItemMatch != null &&
                        (m.ItemMatch.WantWorkspaceId == workspaceId ||
                         m.ItemMatch.TradeWorkspaceId == workspaceId))
            .CountAsync();
    }
}

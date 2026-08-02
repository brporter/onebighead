using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class SupportRepository : ISupportRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;

    public SupportRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task<SupportRequest> CreateRequestAsync(SupportRequest request)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        request.CreatedAt = DateTime.UtcNow;
        request.UpdatedAt = DateTime.UtcNow;
        context.SupportRequests.Add(request);
        await context.SaveChangesAsync();
        return request;
    }

    public async Task<SupportRequest?> GetRequestByIdAsync(int id, bool includeReplies = false)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var query = context.SupportRequests.AsQueryable();

        if (includeReplies)
        {
            query = query.Include(sr => sr.Replies.OrderBy(r => r.CreatedAt));
        }

        return await query.FirstOrDefaultAsync(sr => sr.Id == id);
    }

    public async Task<IEnumerable<SupportRequest>> GetRequestsForUserAsync(int userId, bool includeDeleted = false)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var query = context.SupportRequests
            .Include(sr => sr.Replies)
            .Where(sr => sr.UserId == userId);

        if (!includeDeleted)
        {
            query = query.Where(sr => !sr.IsDeleted);
        }

        return await query
            .OrderByDescending(sr => sr.UpdatedAt)
            .ToListAsync();
    }

    public async Task<IEnumerable<SupportRequest>> GetAllRequestsAsync(
        SupportRequestStatus? status = null,
        bool includeDeleted = false,
        int? limit = null,
        int? offset = null)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var query = context.SupportRequests
            .Include(sr => sr.Replies)
            .AsQueryable();

        if (!includeDeleted)
        {
            query = query.Where(sr => !sr.IsDeleted);
        }

        if (status.HasValue)
        {
            query = query.Where(sr => sr.Status == status.Value);
        }

        query = query.OrderByDescending(sr => sr.UpdatedAt);

        if (offset.HasValue)
        {
            query = query.Skip(offset.Value);
        }

        if (limit.HasValue)
        {
            query = query.Take(limit.Value);
        }

        return await query.ToListAsync();
    }

    public async Task<int> GetRequestCountAsync(SupportRequestStatus? status = null, bool includeDeleted = false)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var query = context.SupportRequests.AsQueryable();

        if (!includeDeleted)
        {
            query = query.Where(sr => !sr.IsDeleted);
        }

        if (status.HasValue)
        {
            query = query.Where(sr => sr.Status == status.Value);
        }

        return await query.CountAsync();
    }

    public async Task<SupportReply> AddReplyAsync(SupportReply reply)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        reply.CreatedAt = DateTime.UtcNow;
        context.SupportReplies.Add(reply);

        // Update the parent request's UpdatedAt timestamp
        var request = await context.SupportRequests.FindAsync(reply.SupportRequestId);
        if (request != null)
        {
            request.UpdatedAt = DateTime.UtcNow;
        }

        await context.SaveChangesAsync();
        return reply;
    }

    public async Task<SupportRequest?> UpdateStatusAsync(int requestId, SupportRequestStatus status)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var request = await context.SupportRequests
            .Include(sr => sr.Replies)
            .FirstOrDefaultAsync(sr => sr.Id == requestId);
        if (request == null || request.IsDeleted)
        {
            return null;
        }

        request.Status = status;
        request.UpdatedAt = DateTime.UtcNow;
        await context.SaveChangesAsync();
        return request;
    }

    public async Task<bool> SoftDeleteAsync(int requestId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var request = await context.SupportRequests.FindAsync(requestId);
        if (request == null)
        {
            return false;
        }

        request.IsDeleted = true;
        request.DeletedAt = DateTime.UtcNow;
        await context.SaveChangesAsync();
        return true;
    }

    public async Task MarkRepliesAsReadAsync(int requestId, int userId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        // Only mark admin replies as read for requests belonging to this user
        var request = await context.SupportRequests
            .Include(sr => sr.Replies)
            .FirstOrDefaultAsync(sr => sr.Id == requestId && sr.UserId == userId);

        if (request == null)
        {
            return;
        }

        foreach (var reply in request.Replies.Where(r => r.IsFromAdmin && !r.IsRead))
        {
            reply.IsRead = true;
        }

        await context.SaveChangesAsync();
    }

    public async Task<int> GetUnreadCountForUserAsync(int userId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.SupportReplies
            .Where(r => r.SupportRequest != null &&
                        r.SupportRequest.UserId == userId &&
                        !r.SupportRequest.IsDeleted &&
                        r.IsFromAdmin &&
                        !r.IsRead)
            .CountAsync();
    }
}

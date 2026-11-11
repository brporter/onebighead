using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Support;

public sealed class SupportRequests(ISupportRepository requests) : ISupportRequests
{
    public Task<IEnumerable<SupportRequest>> GetForUserAsync(int userId) => requests.GetRequestsForUserAsync(userId);
    public Task<int> GetUnreadCountAsync(int userId) => requests.GetUnreadCountForUserAsync(userId);
    public Task<SupportRequest?> GetAsync(int id, int userId) => GetOwnedAsync(id, userId, includeReplies: true);

    public async Task<bool> DeleteAsync(int id, int userId)
    {
        if (await GetOwnedAsync(id, userId, includeReplies: false) is null) return false;
        await requests.SoftDeleteAsync(id);
        return true;
    }

    public async Task<bool> MarkReadAsync(int id, int userId)
    {
        if (await GetOwnedAsync(id, userId, includeReplies: false) is null) return false;
        await requests.MarkRepliesAsReadAsync(id, userId);
        return true;
    }

    private async Task<SupportRequest?> GetOwnedAsync(int id, int userId, bool includeReplies)
    {
        var request = await requests.GetRequestByIdAsync(id, includeReplies);
        return request?.UserId == userId ? request : null;
    }
}

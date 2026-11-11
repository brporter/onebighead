using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Support;

/// <summary>User-owned support requests; administrator operations use separate ports.</summary>
public interface ISupportRequests
{
    Task<IEnumerable<SupportRequest>> GetForUserAsync(int userId);
    Task<SupportRequest?> GetAsync(int id, int userId);
    Task<bool> DeleteAsync(int id, int userId);
    Task<int> GetUnreadCountAsync(int userId);
    Task<bool> MarkReadAsync(int id, int userId);
}

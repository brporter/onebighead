using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface ISupportRepository
{
    /// <summary>
    /// Create a new support request.
    /// </summary>
    Task<SupportRequest> CreateRequestAsync(SupportRequest request);

    /// <summary>
    /// Get a support request by ID, optionally including replies.
    /// </summary>
    Task<SupportRequest?> GetRequestByIdAsync(int id, bool includeReplies = false);

    /// <summary>
    /// Get all support requests for a specific user (by UserId).
    /// </summary>
    Task<IEnumerable<SupportRequest>> GetRequestsForUserAsync(int userId, bool includeDeleted = false);

    /// <summary>
    /// Get all support requests (for admin view).
    /// </summary>
    Task<IEnumerable<SupportRequest>> GetAllRequestsAsync(
        SupportRequestStatus? status = null,
        bool includeDeleted = false,
        int? limit = null,
        int? offset = null);

    /// <summary>
    /// Get total count of requests (for pagination).
    /// </summary>
    Task<int> GetRequestCountAsync(SupportRequestStatus? status = null, bool includeDeleted = false);

    /// <summary>
    /// Add a reply to a support request.
    /// </summary>
    Task<SupportReply> AddReplyAsync(SupportReply reply);

    /// <summary>
    /// Update the status of a support request.
    /// </summary>
    Task<SupportRequest?> UpdateStatusAsync(int requestId, SupportRequestStatus status);

    /// <summary>
    /// Soft delete a support request.
    /// </summary>
    Task<bool> SoftDeleteAsync(int requestId);

    /// <summary>
    /// Mark all admin replies as read for a specific request.
    /// </summary>
    Task MarkRepliesAsReadAsync(int requestId, int userId);

    /// <summary>
    /// Get count of unread admin replies for a user.
    /// </summary>
    Task<int> GetUnreadCountForUserAsync(int userId);
}

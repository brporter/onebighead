using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Support;

public interface ISupportReplies
{
    Task<SupportReplyResult> AddUserReplyAsync(int requestId, int userId, string message);
    Task<SupportReplyResult> AddAdminReplyAsync(int requestId, int userId, string message);
}

public enum SupportReplyStatus { Added, NotFound, Forbidden, Invalid, Conflict }

public sealed record SupportReplyResult(SupportReplyStatus Status, SupportReplyDto? Reply = null, string? Error = null);

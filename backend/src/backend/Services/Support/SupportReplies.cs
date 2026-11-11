using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Support;

/// <summary>Authorizes and saves a reply and its ticket transition together.</summary>
public sealed class SupportReplies(IDbContextFactory<AppDbContext> contextFactory,
    IEmailService emailService, TimeProvider timeProvider, ILogger<SupportReplies> logger) : ISupportReplies
{
    public Task<SupportReplyResult> AddUserReplyAsync(int requestId, int userId, string message) =>
        AddAsync(requestId, userId, message, fromAdmin: false);

    public Task<SupportReplyResult> AddAdminReplyAsync(int requestId, int userId, string message) =>
        AddAsync(requestId, userId, message, fromAdmin: true);

    private async Task<SupportReplyResult> AddAsync(int requestId, int userId, string message, bool fromAdmin)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        SupportRequest request;
        SupportReply reply;
        try
        {
            var user = await context.Users.SingleOrDefaultAsync(u => u.Id == userId && !u.IsDeleted);
            if (user is null || (fromAdmin && !user.IsSystemAdministrator))
                return new(SupportReplyStatus.Forbidden);

            var found = await context.SupportRequests.SingleOrDefaultAsync(r => r.Id == requestId);
            if (found is null || (!fromAdmin && found.UserId != userId))
                return new(SupportReplyStatus.NotFound);
            if (found.IsDeleted)
                return new(SupportReplyStatus.Invalid, Error: "Cannot reply to a deleted request.");
            if (string.IsNullOrWhiteSpace(message) || message.Length > 4000)
                return new(SupportReplyStatus.Invalid, Error: "Enter a reply of at most 4000 characters.");

            request = found;
            var now = timeProvider.GetUtcNow().UtcDateTime;
            reply = new SupportReply
            {
                SupportRequestId = request.Id, UserId = userId, Message = message,
                IsFromAdmin = fromAdmin, IsRead = !fromAdmin, CreatedAt = now
            };
            request.UpdatedAt = now;
            if (fromAdmin && request.Status == SupportRequestStatus.Open)
                request.Status = SupportRequestStatus.InProgress;
            else if (!fromAdmin && request.Status is SupportRequestStatus.Resolved or SupportRequestStatus.Closed)
                request.Status = SupportRequestStatus.Open;
            context.SupportReplies.Add(reply);
            await context.SaveChangesAsync();
            await transaction.CommitAsync();
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return new(SupportReplyStatus.Conflict, Error: "This support request changed. Refresh it before sending your reply again.");
        }

        // Delivery happens after commit. A delivery failure must not turn a saved
        // reply into a failed request that encourages the client to post it twice.
        if (fromAdmin)
        {
            try
            {
                await emailService.SendSupportReplyNotificationAsync(request.Email, request.Subject,
                    reply.Message, request.Id, request.UserId.HasValue);
            }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Notification delivery failed for saved support reply {ReplyId}", reply.Id);
            }
        }
        return new(SupportReplyStatus.Added, SupportReplyDto.FromEntity(reply));
    }
}

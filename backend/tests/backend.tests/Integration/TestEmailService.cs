using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Integration;

/// <summary>
/// Test email service that captures sent emails for verification.
/// </summary>
public class TestEmailService : IEmailService
{
    public List<(string To, string Subject, int RequestId)> SupportConfirmations { get; } = new();
    public List<(string To, string Subject, string Reply, int RequestId)> SupportReplies { get; } = new();

    public Task SendSupportRequestConfirmationAsync(string toEmail, string subject, int requestId, bool isLoggedInUser)
    {
        SupportConfirmations.Add((toEmail, subject, requestId));
        return Task.CompletedTask;
    }

    public Task SendSupportReplyNotificationAsync(string toEmail, string subject, string replyMessage, int requestId, bool isLoggedInUser)
    {
        SupportReplies.Add((toEmail, subject, replyMessage, requestId));
        return Task.CompletedTask;
    }
}
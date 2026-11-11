using Microsoft.Extensions.Options;
using OneBigHead.Server.Services.Email;

namespace OneBigHead.Server.Services.Support;

/// <summary>Composes support notifications and keeps delivery failures out of saved support workflows.</summary>
public sealed class SupportEmailService(IEmailDelivery delivery, IOptions<EmailSettings> settings,
    ILogger<SupportEmailService> logger) : IEmailService
{
    public Task SendSupportRequestConfirmationAsync(string toEmail, string subject, int requestId, bool isLoggedInUser) =>
        SendAsync(toEmail, SupportEmailComposer.Confirmation(subject, requestId, isLoggedInUser, settings.Value.AppBaseUrl));

    public Task SendSupportReplyNotificationAsync(string toEmail, string subject, string replyMessage, int requestId, bool isLoggedInUser) =>
        SendAsync(toEmail, SupportEmailComposer.Reply(subject, replyMessage, requestId, isLoggedInUser, settings.Value.AppBaseUrl));

    private async Task SendAsync(string recipient, EmailMessageContent content)
    {
        try
        {
            await delivery.SendAsync(recipient, content);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Support notification delivery failed");
        }
    }
}

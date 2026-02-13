using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services;

[GenerateTracingProxy]
public interface IEmailService
{
    /// <summary>
    /// Send a support request confirmation email.
    /// </summary>
    Task SendSupportRequestConfirmationAsync(string toEmail, string subject, int requestId, bool isLoggedInUser);

    /// <summary>
    /// Send a support reply notification email.
    /// </summary>
    Task SendSupportReplyNotificationAsync(string toEmail, string subject, string replyMessage, int requestId, bool isLoggedInUser);
}

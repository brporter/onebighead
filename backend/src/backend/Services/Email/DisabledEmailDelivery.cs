namespace OneBigHead.Server.Services.Email;

public sealed class DisabledEmailDelivery(ILogger<DisabledEmailDelivery> logger) : IEmailDelivery
{
    public Task SendAsync(string recipient, EmailMessageContent content)
    {
        logger.LogWarning("Email not sent because email delivery is not configured");
        return Task.CompletedTask;
    }
}

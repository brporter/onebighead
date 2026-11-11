using Azure;
using Azure.Communication.Email;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Services.Email;

public sealed class AzureEmailDelivery(EmailClient client, IOptions<EmailSettings> settings,
    ILogger<AzureEmailDelivery> logger) : IEmailDelivery
{
    public async Task SendAsync(string recipient, EmailMessageContent content)
    {
        var message = new EmailMessage(senderAddress: settings.Value.SenderAddress,
            content: new EmailContent(content.Subject) { Html = content.Html, PlainText = content.PlainText },
            recipients: new EmailRecipients(new[] { new EmailAddress(recipient) }));
        var operation = await client.SendAsync(WaitUntil.Completed, message);
        if (operation.Value.Status != EmailSendStatus.Succeeded)
            throw new InvalidOperationException($"Email delivery ended with status {operation.Value.Status}.");
        logger.LogInformation("Email delivery completed. OperationId: {OperationId}", operation.Id);
    }
}

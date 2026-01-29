using Azure;
using Azure.Communication.Email;
using Microsoft.Extensions.Options;

namespace backend.Services;

public class AzureEmailService : IEmailService
{
    private readonly EmailSettings _settings;
    private readonly EmailClient? _client;
    private readonly ILogger<AzureEmailService> _logger;

    public AzureEmailService(IOptions<EmailSettings> settings, ILogger<AzureEmailService> logger)
    {
        _settings = settings.Value;
        _logger = logger;

        if (!string.IsNullOrEmpty(_settings.ConnectionString))
        {
            _client = new EmailClient(_settings.ConnectionString);
        }
        else
        {
            _logger.LogWarning("Email service not configured - ConnectionString is empty");
        }
    }

    public async Task SendSupportRequestConfirmationAsync(string toEmail, string subject, int requestId, bool isLoggedInUser)
    {
        var sanitizedSubject = SanitizeSubject(subject);
        var htmlContent = BuildConfirmationEmail(sanitizedSubject, requestId, isLoggedInUser);
        var plainTextContent = BuildConfirmationEmailPlainText(sanitizedSubject, requestId, isLoggedInUser);

        await SendEmailAsync(toEmail, $"Support Request Received: {sanitizedSubject}", htmlContent, plainTextContent);
    }

    public async Task SendSupportReplyNotificationAsync(string toEmail, string subject, string replyMessage, int requestId, bool isLoggedInUser)
    {
        var sanitizedSubject = SanitizeSubject(subject);
        var htmlContent = BuildReplyNotificationEmail(sanitizedSubject, replyMessage, requestId, isLoggedInUser);
        var plainTextContent = BuildReplyNotificationEmailPlainText(sanitizedSubject, replyMessage, requestId, isLoggedInUser);

        await SendEmailAsync(toEmail, $"Support Update: {sanitizedSubject}", htmlContent, plainTextContent);
    }

    /// <summary>
    /// Sanitize email subject to prevent header injection attacks.
    /// Removes CR/LF characters and enforces max length.
    /// </summary>
    private static string SanitizeSubject(string subject)
    {
        if (string.IsNullOrEmpty(subject))
            return string.Empty;

        // Remove CR/LF to prevent header injection
        var sanitized = subject
            .Replace("\r", "")
            .Replace("\n", "")
            .Trim();

        // Enforce reasonable max length for email subject
        const int maxLength = 200;
        if (sanitized.Length > maxLength)
            sanitized = sanitized[..maxLength];

        return sanitized;
    }

    private async Task SendEmailAsync(string toEmail, string subject, string htmlContent, string plainTextContent)
    {
        if (_client == null)
        {
            _logger.LogWarning("Email not sent - service not configured. To: {Email}, Subject: {Subject}", toEmail, subject);
            return;
        }

        try
        {
            var emailMessage = new EmailMessage(
                senderAddress: _settings.SenderAddress,
                content: new EmailContent(subject)
                {
                    PlainText = plainTextContent,
                    Html = htmlContent
                },
                recipients: new EmailRecipients(new List<EmailAddress>
                {
                    new EmailAddress(toEmail)
                }));

            var operation = await _client.SendAsync(WaitUntil.Completed, emailMessage);
            _logger.LogInformation("Email sent to {Email}, OperationId: {OperationId}", toEmail, operation.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email to {Email}", toEmail);
            // Don't throw - email failures shouldn't break the support flow
        }
    }

    private string BuildConfirmationEmail(string subject, int requestId, bool isLoggedInUser)
    {
        var viewInstructions = isLoggedInUser
            ? $@"<p>You can view your support request and any responses in your <a href=""{_settings.AppBaseUrl}/collections"">Settings</a> under the Support section.</p>"
            : "";

        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #4a90d9; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; background: #f9f9f9; }}
        .footer {{ padding: 20px; font-size: 12px; color: #666; text-align: center; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin: 15px 0; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            <h1>Support Request Received</h1>
        </div>
        <div class=""content"">
            <p>Thank you for contacting OneBigHead Support.</p>
            <p>We have received your support request:</p>
            <p><strong>Subject:</strong> {System.Web.HttpUtility.HtmlEncode(subject)}</p>
            <p><strong>Reference Number:</strong> #{requestId}</p>
            <p>Our team will review your request and respond as soon as possible.</p>
            {viewInstructions}
            <div class=""warning"">
                <strong>⚠️ Do not reply to this email.</strong><br>
                {(isLoggedInUser
                    ? "Please use the Support section in your Settings to respond to this request."
                    : "If you need to provide additional information, please submit a new support request.")}
            </div>
        </div>
        <div class=""footer"">
            <p>This is an automated message from OneBigHead. Please do not reply directly to this email.</p>
        </div>
    </div>
</body>
</html>";
    }

    private string BuildConfirmationEmailPlainText(string subject, int requestId, bool isLoggedInUser)
    {
        var viewInstructions = isLoggedInUser
            ? $"You can view your support request and any responses in your Settings at {_settings.AppBaseUrl}/collections under the Support section.\n\n"
            : "";

        return $@"Support Request Received
========================

Thank you for contacting OneBigHead Support.

We have received your support request:
Subject: {subject}
Reference Number: #{requestId}

Our team will review your request and respond as soon as possible.

{viewInstructions}⚠️ IMPORTANT: Do not reply to this email.
{(isLoggedInUser
    ? "Please use the Support section in your Settings to respond to this request."
    : "If you need to provide additional information, please submit a new support request.")}

--
This is an automated message from OneBigHead. Please do not reply directly to this email.";
    }

    private string BuildReplyNotificationEmail(string subject, string replyMessage, int requestId, bool isLoggedInUser)
    {
        var viewInstructions = isLoggedInUser
            ? $@"<p><a href=""{_settings.AppBaseUrl}/collections"" style=""background: #4a90d9; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;"">View in Settings</a></p>
               <p>Go to Settings → Support to view the full conversation and reply.</p>"
            : "";

        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #4a90d9; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; background: #f9f9f9; }}
        .message {{ background: white; padding: 15px; border-left: 4px solid #4a90d9; margin: 15px 0; }}
        .footer {{ padding: 20px; font-size: 12px; color: #666; text-align: center; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin: 15px 0; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            <h1>Support Update</h1>
        </div>
        <div class=""content"">
            <p>You have received a response to your support request:</p>
            <p><strong>Subject:</strong> {System.Web.HttpUtility.HtmlEncode(subject)}</p>
            <p><strong>Reference Number:</strong> #{requestId}</p>
            
            <div class=""message"">
                {System.Web.HttpUtility.HtmlEncode(replyMessage).Replace("\n", "<br>")}
            </div>

            {viewInstructions}

            <div class=""warning"">
                <strong>⚠️ Do not reply to this email.</strong><br>
                {(isLoggedInUser
                    ? "Please use the Support section in your Settings to respond to this request."
                    : "If you need further assistance, please submit a new support request.")}
            </div>
        </div>
        <div class=""footer"">
            <p>This is an automated message from OneBigHead. Please do not reply directly to this email.</p>
        </div>
    </div>
</body>
</html>";
    }

    private string BuildReplyNotificationEmailPlainText(string subject, string replyMessage, int requestId, bool isLoggedInUser)
    {
        var viewInstructions = isLoggedInUser
            ? $@"View this conversation in your Settings at {_settings.AppBaseUrl}/collections
Go to Settings → Support to view the full conversation and reply.

"
            : "";

        return $@"Support Update
==============

You have received a response to your support request:
Subject: {subject}
Reference Number: #{requestId}

Response:
---------
{replyMessage}
---------

{viewInstructions}⚠️ IMPORTANT: Do not reply to this email.
{(isLoggedInUser
    ? "Please use the Support section in your Settings to respond to this request."
    : "If you need further assistance, please submit a new support request.")}

--
This is an automated message from OneBigHead. Please do not reply directly to this email.";
    }
}

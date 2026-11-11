using System.Net;
using OneBigHead.Server.Services.Email;

namespace OneBigHead.Server.Services.Support;

/// <summary>Pure HTML and plain-text templates shared by support delivery adapters.</summary>
public static class SupportEmailComposer
{
    public static EmailMessageContent Confirmation(string subject, int requestId, bool registered, string appBaseUrl) =>
        Compose("Support Request Received", subject, null, requestId, registered, appBaseUrl);

    public static EmailMessageContent Reply(string subject, string message, int requestId, bool registered, string appBaseUrl) =>
        Compose("Support Update", subject, message, requestId, registered, appBaseUrl);

    private static EmailMessageContent Compose(string title, string subject, string? reply, int requestId, bool registered, string appBaseUrl)
    {
        var cleanSubject = SanitizeSubject(subject);
        var url = appBaseUrl.TrimEnd('/') + "/settings?section=support";
        var introduction = reply is null
            ? "Thank you for contacting OneBigHead Support. We have received your support request:"
            : "You have received a response to your support request:";
        var detailsHtml = reply is null
            ? "<p>Our team will review your request and respond as soon as possible.</p>"
            : $"<div class=\"message\">{WebUtility.HtmlEncode(reply).Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", "<br>")}</div>";
        var detailsText = reply is null
            ? "Our team will review your request and respond as soon as possible."
            : $"Response:\n{reply}";
        var viewHtml = registered ? $"<p><a href=\"{WebUtility.HtmlEncode(url)}\">View this conversation in Support settings</a></p>" : "";
        var viewText = registered ? $"View this conversation in Support settings: {url}\n\n" : "";
        var warning = registered
            ? "Please use the Support section in your Settings to respond to this request."
            : "If you need to provide additional information, please submit a new support request.";
        const string footer = "This is an automated message from OneBigHead. Please do not reply directly to this email.";

        var html = $$"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; margin: 0; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; overflow-wrap: anywhere; }
                    .header { background: #4a90d9; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background: #f9f9f9; }
                    .message { background: white; padding: 15px; border-left: 4px solid #4a90d9; margin: 15px 0; }
                    .footer { padding: 20px; font-size: 12px; color: #666; text-align: center; }
                    .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin: 15px 0; border-radius: 4px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header"><h1>{{title}}</h1></div>
                    <div class="content">
                        <p>{{introduction}}</p>
                        <p><strong>Subject:</strong> {{WebUtility.HtmlEncode(cleanSubject)}}</p>
                        <p><strong>Reference Number:</strong> #{{requestId}}</p>
                        {{detailsHtml}}
                        {{viewHtml}}
                        <div class="warning"><strong>Do not reply to this email.</strong><br>{{warning}}</div>
                    </div>
                    <div class="footer"><p>{{footer}}</p></div>
                </div>
            </body>
            </html>
            """;
        var plainText = $"{title}\n\n{introduction}\nSubject: {cleanSubject}\nReference Number: #{requestId}\n\n{detailsText}\n\n" +
            $"{viewText}IMPORTANT: Do not reply to this email.\n{warning}\n\n--\n{footer}";
        return new($"{title}: {cleanSubject}", html, plainText);
    }

    private static string SanitizeSubject(string subject)
    {
        if (string.IsNullOrEmpty(subject)) return string.Empty;
        var sanitized = subject.Replace("\r", "").Replace("\n", "").Trim();
        if (sanitized.Length <= 200) return sanitized;
        // Keep a supplementary Unicode character intact at the header boundary.
        var length = char.IsHighSurrogate(sanitized[199]) ? 199 : 200;
        return sanitized[..length];
    }
}

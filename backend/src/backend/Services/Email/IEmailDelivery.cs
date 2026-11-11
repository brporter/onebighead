namespace OneBigHead.Server.Services.Email;

/// <summary>Delivers prepared content without knowing the workflow that produced it.</summary>
public interface IEmailDelivery
{
    Task SendAsync(string recipient, EmailMessageContent content);
}

public sealed record EmailMessageContent(string Subject, string Html, string PlainText);

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OneBigHead.Server.Services.Email;
using OneBigHead.Server.Services.Support;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class SupportEmailTests
{
    private const string AppUrl = "https://example.test/app/";
    private const string SupportUrl = "https://example.test/app/settings?section=support";

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Notification_DeliversCompleteContentForTheIntendedRecipient(bool reply, bool registered)
    {
        var delivery = new Mock<IEmailDelivery>(MockBehavior.Strict);
        EmailMessageContent? captured = null;
        delivery.Setup(d => d.SendAsync("recipient@example.test", It.IsAny<EmailMessageContent>()))
            .Callback<string, EmailMessageContent>((_, content) => captured = content).Returns(Task.CompletedTask);
        var service = Service(delivery.Object);
        if (reply) await service.SendSupportReplyNotificationAsync("recipient@example.test", "Import help", "Use the import screen.", 123, registered);
        else await service.SendSupportRequestConfirmationAsync("recipient@example.test", "Import help", 123, registered);

        Assert.NotNull(captured);
        Assert.Equal(reply ? "Support Update: Import help" : "Support Request Received: Import help", captured.Subject);
        Assert.Contains("Import help", captured.Html);
        Assert.Contains("Import help", captured.PlainText);
        Assert.Contains("#123", captured.Html);
        Assert.Contains("#123", captured.PlainText);
        Assert.Contains(reply ? "Use the import screen." : "Our team will review your request", captured.Html);
        Assert.Contains(reply ? "Use the import screen." : "Our team will review your request", captured.PlainText);
        Assert.Contains("Do not reply to this email.", captured.Html);
        Assert.Contains("Do not reply to this email.", captured.PlainText);
        Assert.DoesNotContain("/collections", captured.Html);
        Assert.DoesNotContain("/collections", captured.PlainText);
        if (registered)
        {
            Assert.Contains($"href=\"{SupportUrl}\"", captured.Html);
            Assert.Contains(SupportUrl, captured.PlainText);
            Assert.Contains("Please use the Support section", captured.Html);
        }
        else
        {
            Assert.DoesNotContain("href=", captured.Html);
            Assert.DoesNotContain(SupportUrl, captured.PlainText);
            Assert.Contains("please submit a new support request", captured.Html);
            Assert.Contains("please submit a new support request", captured.PlainText);
        }
        delivery.Verify(d => d.SendAsync("recipient@example.test", It.IsAny<EmailMessageContent>()), Times.Once);
        delivery.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData(" \t\n ", "")]
    [InlineData("  Subject\r\nWith\nNewlines  ", "SubjectWithNewlines")]
    public void Subject_IsSanitizedWithoutHeaderInjection(string? input, string expected)
    {
        var message = SupportEmailComposer.Confirmation(input!, 123, false, AppUrl);
        Assert.Equal($"Support Request Received: {expected}", message.Subject);
        Assert.DoesNotContain('\r', message.Subject);
        Assert.DoesNotContain('\n', message.Subject);
    }

    [Theory]
    [InlineData(199)]
    [InlineData(200)]
    [InlineData(201)]
    [InlineData(10000)]
    public void SubjectLimit_IsAppliedConsistentlyToHeadersAndBodies(int length)
    {
        var expected = new string('X', Math.Min(length, 200));
        var message = SupportEmailComposer.Reply(new string('X', length), "Reply", 123, true, AppUrl);
        Assert.Equal($"Support Update: {expected}", message.Subject);
        Assert.Contains($"Subject:</strong> {expected}</p>", message.Html);
        Assert.Contains($"Subject: {expected}\n", message.PlainText);
    }

    [Fact]
    public void Html_EncodesUserContentAndNormalizesLineBreaksWhilePlainTextPreservesIt()
    {
        const string subject = "<script>alert('subject')</script> & \"quotes\"";
        const string reply = "<script>alert('reply')</script> & \"quotes\"\r\nSecond\rThird\nFourth";
        var message = SupportEmailComposer.Reply(subject, reply, 42, true, "https://example.test/app?x=\"unsafe\"&y=test");
        Assert.DoesNotContain("<script>", message.Html);
        Assert.Contains("&lt;script&gt;", message.Html);
        Assert.Contains("&amp;", message.Html);
        Assert.Contains("&quot;quotes&quot;", message.Html);
        Assert.Contains("<br>Second<br>Third<br>Fourth", message.Html);
        Assert.DoesNotContain('\r', message.Html);
        Assert.Contains("x=&quot;unsafe&quot;&amp;y=test", message.Html);
        Assert.Contains(subject, message.PlainText);
        Assert.Contains(reply, message.PlainText);
    }

    [Theory]
    [InlineData("https://example.test", "https://example.test/settings?section=support")]
    [InlineData("https://example.test/", "https://example.test/settings?section=support")]
    [InlineData("https://example.test/app///", "https://example.test/app/settings?section=support")]
    public void SupportLink_PreservesBasePathWithoutDuplicatingSlashes(string appUrl, string expected)
    {
        var message = SupportEmailComposer.Confirmation("Help", 1, true, appUrl);
        Assert.Contains($"href=\"{expected}\"", message.Html);
        Assert.Contains(expected, message.PlainText);
    }

    [Fact]
    public void SubjectTruncation_DoesNotSplitASupplementaryUnicodeCharacter()
    {
        var prefix = new string('X', 199);
        var message = SupportEmailComposer.Confirmation(prefix + "📚", 1, false, AppUrl);
        Assert.Equal("Support Request Received: " + prefix, message.Subject);
        Assert.DoesNotContain("�", message.Html);
        var intact = SupportEmailComposer.Confirmation(new string('X', 198) + "📚", 1, false, AppUrl);
        Assert.EndsWith("📚", intact.Subject);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DeliveryFailure_IsLoggedWithoutFailingTheSavedSupportWorkflow(bool reply)
    {
        var failure = new InvalidOperationException("Simulated delivery failure");
        var delivery = new Mock<IEmailDelivery>(MockBehavior.Strict);
        delivery.Setup(d => d.SendAsync("recipient@example.test", It.IsAny<EmailMessageContent>())).ThrowsAsync(failure);
        var logger = new Mock<ILogger<SupportEmailService>>();
        var service = Service(delivery.Object, logger.Object);
        if (reply) await service.SendSupportReplyNotificationAsync("recipient@example.test", "Private subject", "Private reply", 1, true);
        else await service.SendSupportRequestConfirmationAsync("recipient@example.test", "Private subject", 1, true);
        var log = Assert.Single(logger.Invocations);
        Assert.Equal(LogLevel.Error, log.Arguments[0]);
        Assert.Same(failure, log.Arguments[3]);
        Assert.DoesNotContain("recipient@example.test", log.Arguments[2].ToString());
        Assert.DoesNotContain("Private", log.Arguments[2].ToString());
        delivery.Verify(d => d.SendAsync("recipient@example.test", It.IsAny<EmailMessageContent>()), Times.Once);
    }

    private static SupportEmailService Service(IEmailDelivery delivery, ILogger<SupportEmailService>? logger = null) =>
        new(delivery, Options.Create(new EmailSettings { AppBaseUrl = AppUrl }), logger ?? Mock.Of<ILogger<SupportEmailService>>());
}

using Azure;
using Azure.Communication.Email;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OneBigHead.Server.Services.Email;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class EmailDeliveryTests
{
    private static readonly EmailMessageContent Content = new("Private subject", "<p>HTML content</p>", "Plain content");

    [Fact]
    public async Task AzureDelivery_MapsTheEnvelopeWaitsForCompletionAndLogsOperationIdentity()
    {
        var client = new Mock<EmailClient>(MockBehavior.Strict);
        var operation = Operation("Succeeded");
        EmailMessage? sent = null;
        client.Setup(c => c.SendAsync(WaitUntil.Completed, It.IsAny<EmailMessage>(), default))
            .Callback<WaitUntil, EmailMessage, CancellationToken>((_, message, _) => sent = message).ReturnsAsync(operation);
        var logger = new Mock<ILogger<AzureEmailDelivery>>();
        var delivery = new AzureEmailDelivery(client.Object, Options.Create(new EmailSettings { SenderAddress = "sender@example.test" }), logger.Object);
        await delivery.SendAsync("recipient@example.test", Content);
        Assert.NotNull(sent);
        Assert.Equal("sender@example.test", sent.SenderAddress);
        Assert.Equal("recipient@example.test", Assert.Single(sent.Recipients.To).Address);
        Assert.Empty(sent.Recipients.CC);
        Assert.Empty(sent.Recipients.BCC);
        Assert.Equal(Content.Subject, sent.Content.Subject);
        Assert.Equal(Content.Html, sent.Content.Html);
        Assert.Equal(Content.PlainText, sent.Content.PlainText);
        var log = Assert.Single(logger.Invocations);
        Assert.Equal(LogLevel.Information, log.Arguments[0]);
        Assert.Contains("operation-123", log.Arguments[2].ToString());
        Assert.DoesNotContain("recipient@example.test", log.Arguments[2].ToString());
        client.Verify(c => c.SendAsync(WaitUntil.Completed, It.IsAny<EmailMessage>(), default), Times.Once);
        client.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("Failed")]
    [InlineData("Canceled")]
    [InlineData("Running")]
    [InlineData("NotStarted")]
    public async Task NonSuccessOperation_IsNotReportedAsSent(string status)
    {
        var client = new Mock<EmailClient>(MockBehavior.Strict);
        client.Setup(c => c.SendAsync(WaitUntil.Completed, It.IsAny<EmailMessage>(), default)).ReturnsAsync(Operation(status));
        var logger = new Mock<ILogger<AzureEmailDelivery>>();
        var delivery = new AzureEmailDelivery(client.Object, Options.Create(new EmailSettings()), logger.Object);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => delivery.SendAsync("recipient@example.test", Content));
        Assert.Contains(status, exception.Message);
        logger.VerifyNoOtherCalls();
        client.Verify(c => c.SendAsync(WaitUntil.Completed, It.IsAny<EmailMessage>(), default), Times.Once);
    }

    [Fact]
    public async Task TransportFailure_IsPreservedForTheCallingWorkflow()
    {
        var failure = new RequestFailedException(503, "Simulated service outage");
        var client = new Mock<EmailClient>(MockBehavior.Strict);
        client.Setup(c => c.SendAsync(WaitUntil.Completed, It.IsAny<EmailMessage>(), default)).ThrowsAsync(failure);
        var logger = new Mock<ILogger<AzureEmailDelivery>>();
        var delivery = new AzureEmailDelivery(client.Object, Options.Create(new EmailSettings()), logger.Object);
        Assert.Same(failure, await Assert.ThrowsAsync<RequestFailedException>(() => delivery.SendAsync("recipient@example.test", Content)));
        logger.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task DisabledDelivery_ReportsConfigurationWithoutLoggingContentOrRecipient()
    {
        var logger = new Mock<ILogger<DisabledEmailDelivery>>();
        await new DisabledEmailDelivery(logger.Object).SendAsync("recipient@example.test", Content);
        var log = Assert.Single(logger.Invocations);
        Assert.Equal(LogLevel.Warning, log.Arguments[0]);
        Assert.Contains("not configured", log.Arguments[2].ToString());
        Assert.DoesNotContain("recipient@example.test", log.Arguments[2].ToString());
        Assert.DoesNotContain("Private subject", log.Arguments[2].ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \t\r\n")]
    public async Task UnconfiguredRegistration_DoesNotConstructAnAzureClient(string? connection)
    {
        var services = Services(connection!);
        services.AddSingleton<EmailClient>(_ => throw new InvalidOperationException("Unconfigured delivery must not resolve a network client"));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });
        var delivery = Assert.IsType<DisabledEmailDelivery>(provider.GetRequiredService<IEmailDelivery>());
        Assert.Same(delivery, provider.GetRequiredService<IEmailDelivery>());
        await delivery.SendAsync("recipient@example.test", Content);
    }

    [Fact]
    public void ConfiguredRegistration_CreatesTheClientAndSharesOneDeliveryAdapter()
    {
        // Fictional endpoint/key; resolving the SDK client does not send a request.
        using var provider = Services("endpoint=https://email.example.test/;accesskey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });
        Assert.IsType<EmailClient>(provider.GetRequiredService<EmailClient>());
        var delivery = Assert.IsType<AzureEmailDelivery>(provider.GetRequiredService<IEmailDelivery>());
        Assert.Same(delivery, provider.GetRequiredService<AzureEmailDelivery>());
        Assert.Same(delivery, provider.GetRequiredService<IEmailDelivery>());
    }

    private static ServiceCollection Services(string connection)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Options.Create(new EmailSettings { ConnectionString = connection }));
        Assert.Same(services, services.AddEmailDelivery());
        return services;
    }

    private static EmailSendOperation Operation(string status)
    {
        var operation = new Mock<EmailSendOperation>();
        operation.SetupGet(o => o.Id).Returns("operation-123");
        operation.SetupGet(o => o.Value).Returns(EmailModelFactory.EmailSendResult("operation-123", new EmailSendStatus(status)));
        return operation.Object;
    }
}

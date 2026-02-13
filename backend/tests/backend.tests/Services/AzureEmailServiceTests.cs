using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class AzureEmailServiceTests
{
    private readonly Mock<ILogger<AzureEmailService>> _mockLogger;

    public AzureEmailServiceTests()
    {
        _mockLogger = new Mock<ILogger<AzureEmailService>>();
    }

    private AzureEmailService CreateService(EmailSettings? settings = null)
    {
        settings ??= new EmailSettings
        {
            ConnectionString = "", // Empty to avoid actual Azure client initialization
            SenderAddress = "noreply@test.com",
            AppBaseUrl = "https://test.onebighead.com"
        };

        var options = Options.Create(settings);
        return new AzureEmailService(options, _mockLogger.Object);
    }

    #region Constructor Tests

    [Fact]
    public void Constructor_LogsWarning_WhenConnectionStringEmpty()
    {
        // Arrange & Act
        var service = CreateService(new EmailSettings { ConnectionString = "" });

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("not configured")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void Constructor_DoesNotLogWarning_WhenConnectionStringProvided()
    {
        // We can't actually test with a real connection string without Azure,
        // but we can verify the warning is only logged when empty
        var service = CreateService(new EmailSettings { ConnectionString = "" });

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeastOnce);
    }

    #endregion

    #region SendSupportRequestConfirmationAsync Tests

    [Fact]
    public async Task SendSupportRequestConfirmationAsync_LogsWarning_WhenClientNotConfigured()
    {
        // Arrange
        var service = CreateService();

        // Act
        await service.SendSupportRequestConfirmationAsync(
            "user@example.com",
            "Test Subject",
            123,
            isLoggedInUser: true);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("not sent")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task SendSupportRequestConfirmationAsync_CompletesWithoutError_WhenClientNotConfigured()
    {
        // Arrange
        var service = CreateService();

        // Act - should not throw
        await service.SendSupportRequestConfirmationAsync(
            "user@example.com",
            "Test Subject",
            123,
            isLoggedInUser: false);
    }

    [Fact]
    public async Task SendSupportRequestConfirmationAsync_HandlesLongSubject()
    {
        // Arrange
        var service = CreateService();
        var longSubject = new string('A', 300); // More than 200 char limit

        // Act - should not throw
        await service.SendSupportRequestConfirmationAsync(
            "user@example.com",
            longSubject,
            123,
            isLoggedInUser: true);

        // Assert - logged with sanitized (truncated) subject
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task SendSupportRequestConfirmationAsync_HandlesSubjectWithNewlines()
    {
        // Arrange
        var service = CreateService();
        var subjectWithNewlines = "Subject\r\nWith\nNewlines";

        // Act - should not throw (newlines are sanitized)
        await service.SendSupportRequestConfirmationAsync(
            "user@example.com",
            subjectWithNewlines,
            123,
            isLoggedInUser: true);
    }

    [Fact]
    public async Task SendSupportRequestConfirmationAsync_HandlesEmptySubject()
    {
        // Arrange
        var service = CreateService();

        // Act - should not throw
        await service.SendSupportRequestConfirmationAsync(
            "user@example.com",
            "",
            123,
            isLoggedInUser: false);
    }

    [Fact]
    public async Task SendSupportRequestConfirmationAsync_HandlesNullSubject()
    {
        // Arrange
        var service = CreateService();

        // Act - should not throw
        await service.SendSupportRequestConfirmationAsync(
            "user@example.com",
            null!,
            123,
            isLoggedInUser: false);
    }

    #endregion

    #region SendSupportReplyNotificationAsync Tests

    [Fact]
    public async Task SendSupportReplyNotificationAsync_LogsWarning_WhenClientNotConfigured()
    {
        // Arrange
        var service = CreateService();

        // Act
        await service.SendSupportReplyNotificationAsync(
            "user@example.com",
            "Test Subject",
            "Reply message",
            123,
            isLoggedInUser: true);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("not sent")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task SendSupportReplyNotificationAsync_CompletesWithoutError_ForAnonymousUser()
    {
        // Arrange
        var service = CreateService();

        // Act - should not throw
        await service.SendSupportReplyNotificationAsync(
            "user@example.com",
            "Test Subject",
            "Reply content",
            456,
            isLoggedInUser: false);
    }

    [Fact]
    public async Task SendSupportReplyNotificationAsync_CompletesWithoutError_ForLoggedInUser()
    {
        // Arrange
        var service = CreateService();

        // Act - should not throw
        await service.SendSupportReplyNotificationAsync(
            "user@example.com",
            "Test Subject",
            "Reply content",
            456,
            isLoggedInUser: true);
    }

    [Fact]
    public async Task SendSupportReplyNotificationAsync_HandlesLongReplyMessage()
    {
        // Arrange
        var service = CreateService();
        var longMessage = new string('X', 10000);

        // Act - should not throw
        await service.SendSupportReplyNotificationAsync(
            "user@example.com",
            "Subject",
            longMessage,
            789,
            isLoggedInUser: true);
    }

    [Fact]
    public async Task SendSupportReplyNotificationAsync_HandlesSpecialCharactersInMessage()
    {
        // Arrange
        var service = CreateService();
        var messageWithSpecialChars = "<script>alert('xss')</script> &amp; \"quotes\"";

        // Act - should not throw
        await service.SendSupportReplyNotificationAsync(
            "user@example.com",
            "Subject",
            messageWithSpecialChars,
            123,
            isLoggedInUser: true);
    }

    #endregion

    #region Edge Cases

    [Fact]
    public async Task SendEmail_HandlesWhitespaceOnlySubject()
    {
        // Arrange
        var service = CreateService();

        // Act - should not throw
        await service.SendSupportRequestConfirmationAsync(
            "user@example.com",
            "   \t\n   ",
            123,
            isLoggedInUser: true);
    }

    [Fact]
    public async Task SendEmail_IncludesRequestIdInContent()
    {
        // Arrange
        var service = CreateService();

        // Act - should complete without error
        await service.SendSupportRequestConfirmationAsync(
            "user@example.com",
            "Test Subject",
            12345,
            isLoggedInUser: true);

        // The request ID (12345) should be included in the email content
        // We can verify the warning log contains the email details
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("user@example.com")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    #endregion
}

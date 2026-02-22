using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class NoOpCsamReportingServiceTests
{
    private readonly Mock<ILogger<NoOpCsamReportingService>> _mockLogger;
    private readonly NoOpCsamReportingService _service;

    public NoOpCsamReportingServiceTests()
    {
        _mockLogger = new Mock<ILogger<NoOpCsamReportingService>>();
        _service = new NoOpCsamReportingService(_mockLogger.Object);
    }

    [Fact]
    public async Task ReportAsync_CompletesWithoutError()
    {
        // Arrange
        var scanLog = new ContentScanLog
        {
            Id = Guid.NewGuid(),
            WorkspaceId = 1,
            ScannerName = "TestScanner",
            IsMatch = true,
            MatchScore = 0.99,
            ContentType = "image/jpeg",
            ScannedAt = DateTime.UtcNow,
        };

        // Act & Assert - should not throw
        await _service.ReportAsync(scanLog);
    }

    [Fact]
    public async Task ReportAsync_LogsWarning()
    {
        // Arrange
        var scanLog = new ContentScanLog
        {
            Id = Guid.NewGuid(),
            WorkspaceId = 1,
            ScannerName = "TestScanner",
            IsMatch = true,
            MatchScore = 0.95,
            ContentType = "image/jpeg",
            ScannedAt = DateTime.UtcNow,
        };

        // Act
        await _service.ReportAsync(scanLog);

        // Assert - verify a warning was logged
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("not configured")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }
}

using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class NoOpContentScannerTests
{
    private readonly NoOpContentScanner _scanner = new();

    [Fact]
    public async Task ScanAsync_ReturnsNoMatch()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        var contentType = "image/jpeg";

        // Act
        var result = await _scanner.ScanAsync(imageData, contentType);

        // Assert
        Assert.False(result.IsMatch);
    }

    [Fact]
    public async Task ScanAsync_ReturnsZeroMatchScore()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };

        // Act
        var result = await _scanner.ScanAsync(imageData, "image/jpeg");

        // Assert
        Assert.Equal(0.0, result.MatchScore);
    }

    [Fact]
    public async Task ScanAsync_ReturnsScannerNameNoOp()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };

        // Act
        var result = await _scanner.ScanAsync(imageData, "image/jpeg");

        // Assert
        Assert.Equal("NoOp", result.ScannerName);
    }

    [Fact]
    public async Task ScanAsync_ReturnsNullDetails()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };

        // Act
        var result = await _scanner.ScanAsync(imageData, "image/jpeg");

        // Assert
        Assert.Null(result.Details);
    }

    [Fact]
    public async Task ScanAsync_RespectsEmptyData()
    {
        // Act
        var result = await _scanner.ScanAsync(Array.Empty<byte>(), "image/png");

        // Assert
        Assert.False(result.IsMatch);
        Assert.Equal("NoOp", result.ScannerName);
    }
}

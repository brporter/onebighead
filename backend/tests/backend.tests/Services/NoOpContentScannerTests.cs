using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class NoOpContentScannerTests
{
    [Theory]
    [InlineData("image/jpeg", 3)]
    [InlineData("image/png", 0)]
    public async Task ScanAsync_ReturnsNoMatch(string contentType, int length)
    {
        var result = await new NoOpContentScanner().ScanAsync(new byte[length], contentType);
        Assert.Equal(new ContentScanResult(IsMatch: false, MatchScore: 0, ScannerName: "NoOp"), result);
    }
}

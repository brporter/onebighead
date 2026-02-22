namespace OneBigHead.Server.Services;

public class NoOpContentScanner : IContentScanner
{
    public Task<ContentScanResult> ScanAsync(byte[] imageData, string contentType, CancellationToken ct = default)
    {
        return Task.FromResult(new ContentScanResult(
            IsMatch: false,
            MatchScore: 0.0,
            ScannerName: "NoOp"));
    }
}

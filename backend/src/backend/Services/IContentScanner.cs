using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services;

[GenerateTracingProxy]
public interface IContentScanner
{
    Task<ContentScanResult> ScanAsync(byte[] imageData, string contentType, CancellationToken ct = default);
}

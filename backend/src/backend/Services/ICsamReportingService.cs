using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services;

[GenerateTracingProxy]
public interface ICsamReportingService
{
    Task ReportAsync(ContentScanLog scanLog, CancellationToken ct = default);
}

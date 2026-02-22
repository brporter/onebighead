using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services;

public class NoOpCsamReportingService : ICsamReportingService
{
    private readonly ILogger<NoOpCsamReportingService> _logger;

    public NoOpCsamReportingService(ILogger<NoOpCsamReportingService> logger)
    {
        _logger = logger;
    }

    public Task ReportAsync(ContentScanLog scanLog, CancellationToken ct = default)
    {
        _logger.LogWarning(
            "CSAM reporting service is not configured. Scan log {ScanLogId} with match score {MatchScore} was not reported to NCMEC.",
            scanLog.Id,
            scanLog.MatchScore);

        return Task.CompletedTask;
    }
}

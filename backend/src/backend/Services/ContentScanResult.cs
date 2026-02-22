namespace OneBigHead.Server.Services;

public record ContentScanResult(
    bool IsMatch,
    double MatchScore,
    string ScannerName,
    string? Details = null);

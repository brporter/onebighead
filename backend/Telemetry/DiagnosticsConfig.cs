using System.Diagnostics;

namespace OneBigHead.Server.Telemetry;

public static class DiagnosticsConfig
{
    public const string ServiceName = "OneBigHead.Server";

    public static readonly ActivitySource AppActivitySource = new(ServiceName);
    public static readonly ActivitySource RepositoryActivitySource = new($"{ServiceName}.Repository");
}

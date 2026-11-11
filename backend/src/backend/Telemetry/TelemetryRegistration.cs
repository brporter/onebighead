using Azure.Monitor.OpenTelemetry.Exporter;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace OneBigHead.Server.Telemetry;

internal static class TelemetryRegistration
{
    public static WebApplicationBuilder AddApplicationTelemetry(this WebApplicationBuilder builder,
        Action<AzureMonitorExporterOptions>? configureAzureExporter = null)
    {
        if (builder.Environment.IsEnvironment("Testing"))
            return builder;

        // Resolve configuration once for all three signals. Configuration already includes environment variables.
        var endpoint = builder.Configuration["OpenTelemetry:OtlpEndpoint"]
            ?? builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
        var connectionString = builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"];
        var useAzure = !string.IsNullOrWhiteSpace(connectionString);
        var useOtlp = !string.IsNullOrWhiteSpace(endpoint);
        var otlpEndpoint = useOtlp ? new Uri(endpoint!, UriKind.Absolute) : null;
        Action<AzureMonitorExporterOptions> configureAzure = options =>
        {
            options.ConnectionString = connectionString;
            configureAzureExporter?.Invoke(options);
        };
        Action<OtlpExporterOptions> configureOtlp = options => options.Endpoint = otlpEndpoint!;

        builder.Services.AddOpenTelemetry()
            .ConfigureResource(resource => resource.AddService(DiagnosticsConfig.ServiceName))
            .WithTracing(tracing =>
            {
                tracing.AddAspNetCoreInstrumentation(options => options.Filter = ShouldTraceRequest)
                    .AddEntityFrameworkCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddSource(DiagnosticsConfig.AppActivitySource.Name)
                    .AddSource(DiagnosticsConfig.RepositoryActivitySource.Name);

                if (useAzure) tracing.AddAzureMonitorTraceExporter(configureAzure);
                if (useOtlp) tracing.AddOtlpExporter(configureOtlp);
            })
            .WithMetrics(metrics =>
            {
                metrics.AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddRuntimeInstrumentation()
                    .AddPrometheusExporter();

                if (useAzure) metrics.AddAzureMonitorMetricExporter(configureAzure);
                if (useOtlp) metrics.AddOtlpExporter(configureOtlp);
            });

        builder.Logging.AddOpenTelemetry(logging =>
        {
            logging.IncludeScopes = true;
            logging.IncludeFormattedMessage = true;
            if (useAzure) logging.AddAzureMonitorLogExporter(configureAzure);
            if (useOtlp) logging.AddOtlpExporter(configureOtlp);
        });
        return builder;
    }

    internal static bool ShouldTraceRequest(HttpContext context)
    {
        // Match path segments, so routes such as /healthcare do not disappear from traces.
        return !context.Request.Path.StartsWithSegments("/health", StringComparison.OrdinalIgnoreCase)
            && !context.Request.Path.StartsWithSegments("/assets", StringComparison.OrdinalIgnoreCase);
    }
}

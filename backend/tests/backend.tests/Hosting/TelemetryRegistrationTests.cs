using System.Collections.Concurrent;
using System.IO.Compression;
using System.Net;
using System.Text;
using Azure.Core.Pipeline;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Telemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace OneBigHead.Server.Tests.Hosting;

[Collection(TelemetryConfigurationCollection.Name)]
public class TelemetryRegistrationTests : IDisposable
{
    private readonly string? _previousStatsbeat = Environment.GetEnvironmentVariable("APPLICATIONINSIGHTS_STATSBEAT_DISABLED");

    public TelemetryRegistrationTests()
        => Environment.SetEnvironmentVariable("APPLICATIONINSIGHTS_STATSBEAT_DISABLED", "true");

    public void Dispose()
        => Environment.SetEnvironmentVariable("APPLICATIONINSIGHTS_STATSBEAT_DISABLED", _previousStatsbeat);

    [Theory]
    [InlineData(null, true)]
    [InlineData("/", true)]
    [InlineData("/health", false)]
    [InlineData("/HEALTH/ready", false)]
    [InlineData("/assets", false)]
    [InlineData("/ASSETS/app.js", false)]
    [InlineData("/healthcare", true)]
    [InlineData("/assets-library", true)]
    [InlineData("/api/collections", true)]
    public void TraceFilter_ExcludesOnlyHealthAndAssetSegments(string? path, bool expected)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        Assert.Equal(expected, TelemetryRegistration.ShouldTraceRequest(context));
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, true, false)]
    [InlineData(false, true, true)]
    public async Task Exporters_UseConfiguredDestinations_ForRealTracesMetricsAndLogs(bool azure, bool otlp, bool fallback)
    {
        var builder = StartupTests.CreateBuilder("Production");
        const string primaryEndpoint = "https://collector.test/primary/";
        const string fallbackEndpoint = "https://collector.test/fallback/";
        builder.Configuration["OpenTelemetry:OtlpEndpoint"] = fallback ? null : otlp ? primaryEndpoint : " ";
        builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"] = fallbackEndpoint;
        builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"] = azure
            ? $"InstrumentationKey={Guid.NewGuid()};IngestionEndpoint=https://azure.test/"
            : " ";
        using var transport = new RecordingHandler();
        builder.AddApplicationTelemetry(options =>
        {
            options.Transport = new HttpClientTransport(new HttpClient(transport, disposeHandler: false));
            options.DisableOfflineStorage = true;
        });
        builder.Services.PostConfigureAll<OtlpExporterOptions>(options =>
        {
            options.Protocol = OtlpExportProtocol.HttpProtobuf;
            options.HttpClientFactory = () => new HttpClient(transport, disposeHandler: false);
        });
        await using (var app = builder.Build())
        {
            var traces = app.Services.GetRequiredService<TracerProvider>();
            var metrics = app.Services.GetRequiredService<MeterProvider>();
            var logging = app.Services.GetRequiredService<IOptions<OpenTelemetryLoggerOptions>>().Value;
            Assert.True(logging.IncludeScopes);
            Assert.True(logging.IncludeFormattedMessage);
            using (var activity = DiagnosticsConfig.AppActivitySource.StartActivity("startup-application-trace"))
                Assert.NotNull(activity);
            using (var activity = DiagnosticsConfig.RepositoryActivitySource.StartActivity("startup-repository-trace"))
                Assert.NotNull(activity);
            app.Logger.LogInformation("startup-telemetry-log");
            Assert.True(traces.ForceFlush());
            // The pull-based Prometheus reader cannot flush; verify push exporter payloads below.
            metrics.ForceFlush();
            // Disposing the logger provider flushes the configured batch log exporters.
        }

        var requests = transport.Requests.ToArray();
        var azureRequests = requests.Where(request => request.Uri.Host == "azure.test").ToArray();
        var otlpRequests = requests.Where(request => request.Uri.Host == "collector.test").ToArray();
        if (azure)
        {
            var payload = string.Join("\n", azureRequests.Select(request => request.Body));
            Assert.Contains("startup-application-trace", payload);
            Assert.Contains("startup-repository-trace", payload);
            Assert.Contains("startup-telemetry-log", payload);
            Assert.Contains("MetricData", payload);
        }
        else Assert.Empty(azureRequests);
        if (otlp)
        {
            Assert.Contains(otlpRequests, request => request.Body.Contains("startup-application-trace"));
            Assert.Contains(otlpRequests, request => request.Body.Contains("startup-repository-trace"));
            Assert.Contains(otlpRequests, request => request.Body.Contains("startup-telemetry-log"));
            Assert.Contains(otlpRequests, request => request.Body.Contains("dotnet.gc.collections"));
            Assert.All(otlpRequests, request => Assert.StartsWith(fallback ? fallbackEndpoint : primaryEndpoint, request.Uri.AbsoluteUri));
            Assert.All(otlpRequests, request => Assert.Contains(DiagnosticsConfig.ServiceName, request.Body));
        }
        else Assert.Empty(otlpRequests);
        Assert.All(requests, request => Assert.Contains(request.Uri.Host, new[] { "azure.test", "collector.test" }));
    }

    [Fact]
    public void InvalidOtlpEndpoint_FailsDuringRegistration()
    {
        var builder = StartupTests.CreateBuilder("Production");
        builder.Configuration["OpenTelemetry:OtlpEndpoint"] = "not-an-absolute-uri";
        Assert.Throws<UriFormatException>(() => builder.AddApplicationTelemetry());
    }

    [Fact]
    public void InvalidAzureConnectionString_FailsBeforeServingRequests()
    {
        var builder = StartupTests.CreateBuilder("Production");
        builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"] = "not-a-connection-string";
        builder.AddApplicationTelemetry();
        var error = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("Connection String Error", error.Message);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public ConcurrentQueue<(Uri Uri, string Body)> Requests { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var bytes = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            if (bytes.Length > 2 && bytes[0] == 0x1f && bytes[1] == 0x8b)
            {
                using var compressed = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress);
                using var output = new MemoryStream();
                await compressed.CopyToAsync(output, cancellationToken);
                bytes = output.ToArray();
            }
            Requests.Enqueue((request.RequestUri!, Encoding.UTF8.GetString(bytes)));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = request.RequestUri!.Host == "azure.test"
                    ? new StringContent("{\"itemsReceived\":1,\"itemsAccepted\":1,\"errors\":[]}", Encoding.UTF8, "application/json")
                    : new ByteArrayContent([])
            };
        }

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
            => SendAsync(request, cancellationToken).GetAwaiter().GetResult();
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public class TelemetryConfigurationCollection
{
    public const string Name = "TelemetryConfiguration";
}

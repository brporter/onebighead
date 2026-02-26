using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.BulkUpdate;
using OneBigHead.Server.Services.Matching;
using OneBigHead.Server.Services.Seeding;
using OneBigHead.Server.Telemetry;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Azure.Monitor.OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using OneBigHead.Server.Utilities;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Add services for both API controllers and Razor Pages
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
        options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });
builder.Services.AddRazorPages();

// Configure lowercase URLs for tag helpers
builder.Services.Configure<RouteOptions>(options =>
{
    options.LowercaseUrls = true;
});

// Configure EF Core with SQL Server (skipped in Testing environment - tests provide their own)
if (!builder.Environment.IsEnvironment("Testing"))
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseSqlServer(connectionString));
}

// Register repositories and services with tracing decorators (skip in Testing environment)
if (!builder.Environment.IsEnvironment("Testing"))
{
    var repoSource = DiagnosticsConfig.RepositoryActivitySource;
    var appSource = DiagnosticsConfig.AppActivitySource;

    builder.Services.AddTracingDecorator<ICategoryRepository, CategoryRepository>(repoSource);
    builder.Services.AddTracingDecorator<ICollectionRepository, CollectionRepository>(repoSource);
    builder.Services.AddTracingDecorator<IItemRepository, ItemRepository>(repoSource);
    builder.Services.AddTracingDecorator<IUserRepository, UserRepository>(repoSource);
    builder.Services.AddTracingDecorator<IWorkspaceRepository, WorkspaceRepository>(repoSource);
    builder.Services.AddTracingDecorator<IWorkspaceUserRepository, WorkspaceUserRepository>(repoSource);
    builder.Services.AddTracingDecorator<IPropertySuggestionRepository, PropertySuggestionRepository>(repoSource);
    builder.Services.AddTracingDecorator<IItemTemplateRepository, ItemTemplateRepository>(repoSource);
    builder.Services.AddTracingDecorator<IThemeRepository, ThemeRepository>(repoSource);
    builder.Services.AddTracingDecorator<ISupportRepository, SupportRepository>(repoSource);
    builder.Services.AddTracingDecorator<IImageProvider, DatabaseImageProvider>(repoSource);
    builder.Services.AddTracingDecorator<IWorkspaceStatisticsRepository, WorkspaceStatisticsRepository>(repoSource);
    builder.Services.AddTracingDecorator<ICollectionStatisticsRepository, CollectionStatisticsRepository>(repoSource);
    builder.Services.AddTracingDecorator<IVisibilityService, VisibilityService>(appSource);
    builder.Services.AddTracingDecorator<IWorkspaceService, WorkspaceService>(appSource);
    builder.Services.AddTracingDecorator<IUserDeletionService, UserDeletionService>(appSource);
    builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("Email"));
    builder.Services.AddTracingDecorator<IEmailService, AzureEmailService>(appSource);
    builder.Services.AddTracingDecorator<IContentScanLogRepository, ContentScanLogRepository>(repoSource);
    builder.Services.AddTracingDecorator<IContentScanner, NoOpContentScanner>(appSource);
    builder.Services.AddTracingDecorator<ICsamReportingService, NoOpCsamReportingService>(appSource);
    builder.Services.AddTracingDecorator<IItemEmbeddingRepository, ItemEmbeddingRepository>(repoSource);
    builder.Services.AddTracingDecorator<IMatchRepository, MatchRepository>(repoSource);
    builder.Services.AddTracingDecorator<IMatchMessageRepository, MatchMessageRepository>(repoSource);
    builder.Services.AddTracingDecorator<IEmbeddingService, EmbeddingService>(appSource);
    builder.Services.AddTracingDecorator<ILlmService, LlmService>(appSource);
    builder.Services.AddTracingDecorator<IMatchingService, MatchingService>(appSource);
}
else
{
    builder.Services.AddScoped<ICategoryRepository, CategoryRepository>();
    builder.Services.AddScoped<ICollectionRepository, CollectionRepository>();
    builder.Services.AddScoped<IItemRepository, ItemRepository>();
    builder.Services.AddScoped<IUserRepository, UserRepository>();
    builder.Services.AddScoped<IWorkspaceRepository, WorkspaceRepository>();
    builder.Services.AddScoped<IWorkspaceUserRepository, WorkspaceUserRepository>();
    builder.Services.AddScoped<IPropertySuggestionRepository, PropertySuggestionRepository>();
    builder.Services.AddScoped<IItemTemplateRepository, ItemTemplateRepository>();
    builder.Services.AddScoped<IThemeRepository, ThemeRepository>();
    builder.Services.AddScoped<ISupportRepository, SupportRepository>();
    builder.Services.AddScoped<IImageProvider, DatabaseImageProvider>();
    builder.Services.AddScoped<IWorkspaceStatisticsRepository, WorkspaceStatisticsRepository>();
    builder.Services.AddScoped<ICollectionStatisticsRepository, CollectionStatisticsRepository>();
    builder.Services.AddScoped<IVisibilityService, VisibilityService>();
    builder.Services.AddScoped<IWorkspaceService, WorkspaceService>();
    builder.Services.AddScoped<IUserDeletionService, UserDeletionService>();
    builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("Email"));
    builder.Services.AddScoped<IEmailService, AzureEmailService>();
    builder.Services.AddScoped<IContentScanLogRepository, ContentScanLogRepository>();
    builder.Services.AddScoped<IContentScanner, NoOpContentScanner>();
    builder.Services.AddScoped<ICsamReportingService, NoOpCsamReportingService>();
    builder.Services.AddScoped<IItemEmbeddingRepository, ItemEmbeddingRepository>();
    builder.Services.AddScoped<IMatchRepository, MatchRepository>();
    builder.Services.AddScoped<IMatchMessageRepository, MatchMessageRepository>();
    builder.Services.AddScoped<IEmbeddingService, EmbeddingService>();
    builder.Services.AddScoped<ILlmService, LlmService>();
    builder.Services.AddScoped<IMatchingService, MatchingService>();
}

// Register image processor (environment-independent, stateless singleton)
builder.Services.AddSingleton<IImageProcessor, ImageProcessor>();

builder.Services.AddSingleton<IRouteHelper, RouteHelper>();

// Register bulk update services (environment-independent)
builder.Services.AddScoped<IPropertyDiffService, PropertyDiffService>();
builder.Services.AddSingleton<IBulkUpdateQueue, BulkUpdateQueue>();
builder.Services.AddHostedService<BulkUpdateWorker>();

// Matching configuration
builder.Services.Configure<LlmSettings>(builder.Configuration.GetSection("Matching"));
builder.Services.AddHttpClient("AzureOpenAI", (sp, client) =>
{
    var settings = sp.GetRequiredService<IOptions<LlmSettings>>().Value;
    if (!string.IsNullOrEmpty(settings.ApiKey))
        client.DefaultRequestHeaders.Add("api-key", settings.ApiKey);
});
builder.Services.AddHttpClient("AzureOpenAIEmbedding", (sp, client) =>
{
    var settings = sp.GetRequiredService<IOptions<LlmSettings>>().Value;
    var apiKey = settings.ResolvedEmbeddingApiKey;
    if (!string.IsNullOrEmpty(apiKey))
        client.DefaultRequestHeaders.Add("api-key", apiKey);
});
builder.Services.AddHostedService<MatchingWorker>();

// Configure authentication
builder.Services.Configure<AuthenticationSettings>(builder.Configuration.GetSection("Authentication"));
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddSingleton<IOidcTokenValidator, OidcTokenValidator>();
builder.Services.AddScoped<IOAuthService, OAuthService>();
builder.Services.AddHttpClient();

builder.Services.AddAuthentication(CookieJwtAuthenticationExtensions.SchemeName)
    .AddCookieJwtAuthentication();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("WorkspaceAdmin", policy =>
        policy.RequireClaim("workspace_role", "WorkspaceAdmin"));
});

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Register global exception handler
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

// Configure rate limiting for auth endpoints
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Fixed window limiter for login endpoints: 10 requests per minute per IP
    options.AddPolicy("auth-login", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));

    // Sliding window limiter for callback endpoints: 20 requests per minute per IP
    options.AddPolicy("auth-callback", httpContext =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 4,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));

    // Sliding window limiter for public endpoints: 60 requests per minute per IP
    options.AddPolicy("public-read", httpContext =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 60,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 4,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));
});

// Configure OpenTelemetry (skip in Testing environment)
if (!builder.Environment.IsEnvironment("Testing"))
{
    var otlpEndpoint = builder.Configuration.GetValue<string>("OpenTelemetry:OtlpEndpoint")
        ?? Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");
    var appInsightsConnectionString = builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"];

    builder.Services.AddOpenTelemetry()
        .ConfigureResource(resource => resource.AddService(DiagnosticsConfig.ServiceName))
        .WithTracing(tracing =>
        {
            tracing
                .AddAspNetCoreInstrumentation(options =>
                {
                    options.Filter = httpContext =>
                    {
                        var path = httpContext.Request.Path.Value ?? "";
                        return !path.StartsWith("/health", StringComparison.OrdinalIgnoreCase) &&
                               !path.StartsWith("/assets/", StringComparison.OrdinalIgnoreCase);
                    };
                })
                .AddEntityFrameworkCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddSource(DiagnosticsConfig.AppActivitySource.Name)
                .AddSource(DiagnosticsConfig.RepositoryActivitySource.Name);

            if (!string.IsNullOrEmpty(appInsightsConnectionString))
                tracing.AddAzureMonitorTraceExporter(o => o.ConnectionString = appInsightsConnectionString);

            if (!string.IsNullOrEmpty(otlpEndpoint))
                tracing.AddOtlpExporter(o => o.Endpoint = new Uri(otlpEndpoint));
        })
        .WithMetrics(metrics =>
        {
            metrics
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddRuntimeInstrumentation()
                .AddPrometheusExporter();

            if (!string.IsNullOrEmpty(appInsightsConnectionString))
                metrics.AddAzureMonitorMetricExporter(o => o.ConnectionString = appInsightsConnectionString);

            if (!string.IsNullOrEmpty(otlpEndpoint))
                metrics.AddOtlpExporter(o => o.Endpoint = new Uri(otlpEndpoint));
        });

    builder.Logging.AddOpenTelemetry(logging =>
    {
        logging.IncludeScopes = true;
        logging.IncludeFormattedMessage = true;

        if (!string.IsNullOrEmpty(appInsightsConnectionString))
            logging.AddAzureMonitorLogExporter(o => o.ConnectionString = appInsightsConnectionString);

        if (!string.IsNullOrEmpty(otlpEndpoint))
            logging.AddOtlpExporter(o => o.Endpoint = new Uri(otlpEndpoint));
    });
}

var app = builder.Build();

// In Development: seed database with system data (migrations applied via efbundle)
if (app.Environment.IsDevelopment())
{
    var seedsPath = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "seeds");
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")!;
    using var scope = app.Services.CreateScope();
    var seederLogger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>()
        .CreateLogger<JsonDatabaseSeeder>();
    var seeder = new JsonDatabaseSeeder(seedsPath, seederLogger);
    await seeder.SeedAsync(connectionString);
}

// Configure the HTTP request pipeline.
app.UseExceptionHandler();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}
else
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.UseWorkspaceActiveCheck();

// Serve static assets from wwwroot (CSS, favicon, etc.)
app.MapStaticAssets();

// Only serve static frontend assets in production (use Vite dev server in development)
if (!app.Environment.IsDevelopment())
{
    // Serve frontend SPA assets from wwwroot/collections at /collections path
    var collectionsPath = Path.Combine(app.Environment.WebRootPath, "collections");

    if (Directory.Exists(collectionsPath))
    {
        var fileProvider = new PhysicalFileProvider(collectionsPath);

        // Rewrite /assets/* to /collections/assets/* for frontend build compatibility
        // (allows frontend to use base: '/' for better dev experience while still serving from /collections in prod)
        app.Use(async (context, next) =>
        {
            var path = context.Request.Path.Value ?? "";
            if (path.StartsWith("/assets/", StringComparison.OrdinalIgnoreCase))
            {
                context.Request.Path = "/collections" + path;
            }
            await next();
        });

        // SPA fallback for top-level routes: rewrite /settings, /setup, /admin, /welcome to index.html
        app.Use(async (context, next) =>
        {
            var path = context.Request.Path.Value ?? "";

            // Top-level SPA routes that need fallback to index.html
            if (path.Equals("/", StringComparison.Ordinal) ||
                path.Equals("/settings", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/settings/", StringComparison.OrdinalIgnoreCase) ||
                path.Equals("/setup", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/setup/", StringComparison.OrdinalIgnoreCase) ||
                path.Equals("/admin", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase) ||
                path.Equals("/welcome", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/welcome/", StringComparison.OrdinalIgnoreCase) ||
                path.Equals("/terms", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/terms/", StringComparison.OrdinalIgnoreCase) ||
                path.Equals("/matches", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/matches/", StringComparison.OrdinalIgnoreCase))
            {
                context.Request.Path = "/collections/index.html";
            }

            await next();
        });

        // SPA fallback middleware: rewrite /collections/* requests to index.html
        // if the requested file doesn't exist (allows React Router to handle routing)
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/collections", out var remaining))
            {
                // Get the file path relative to collections folder
                var relativePath = remaining.Value?.TrimStart('/') ?? "";
                
                if (!string.IsNullOrEmpty(relativePath))
                {
                    var filePath = Path.GetFullPath(Path.Combine(collectionsPath, relativePath));
                    
                    // Security: ensure the path stays within collectionsPath
                    if (filePath.StartsWith(collectionsPath, StringComparison.OrdinalIgnoreCase) &&
                        !File.Exists(filePath) && 
                        !Directory.Exists(filePath))
                    {
                        context.Request.Path = "/collections/index.html";
                    }
                }
            }
            await next();
        });
        
        app.UseDefaultFiles(new DefaultFilesOptions()
        {
            FileProvider = fileProvider,
            RequestPath = "/collections",
            DefaultFileNames = { "index.html" }
        });
        
        app.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = fileProvider,
            RequestPath = "/collections"
        });
    }
}

app.MapRazorPages()
   .WithStaticAssets(); // Leverage immutable paths for static assets in Razor pages

app.MapControllers();

// Simple health check endpoint for deployment verification
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

// Prometheus metrics scrape endpoint
if (!app.Environment.IsEnvironment("Testing"))
{
    app.MapPrometheusScrapingEndpoint("/metrics");
}

app.Run();

public partial class Program { }

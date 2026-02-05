using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Seeding;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;

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

// Register repositories
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

// Register image provider
builder.Services.AddScoped<IImageProvider, DatabaseImageProvider>();

// Register visibility service
builder.Services.AddScoped<IVisibilityService, VisibilityService>();

// Register deletion services
builder.Services.AddScoped<IWorkspaceDeletionService, WorkspaceDeletionService>();
builder.Services.AddScoped<IUserDeletionService, UserDeletionService>();

// Configure email service
builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("Email"));
builder.Services.AddScoped<IEmailService, AzureEmailService>();

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
});

var app = builder.Build();

// In Development: run migrations and seed automatically
// In other environments: use migration bundles for deployments
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    context.Database.Migrate();

    // Seed database with system data from JSON files
    var seedsPath = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "seeds");
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")!;
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
app.UseAuditLogging();

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
                path.StartsWith("/terms/", StringComparison.OrdinalIgnoreCase))
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

app.Run();

public partial class Program { }

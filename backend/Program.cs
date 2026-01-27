using backend.Authentication;
using backend.Data;
using backend.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);

// Add services for both API controllers and Razor Pages
builder.Services.AddControllers();
builder.Services.AddRazorPages();

// Add health checks
builder.Services.AddHealthChecks()
    .AddDbContextCheck<AppDbContext>();

// Configure lowercase URLs for tag helpers
builder.Services.Configure<RouteOptions>(options =>
{
    options.LowercaseUrls = true;
});

// Configure EF Core with SQL Server
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString, sqlOptions =>
    {
        // Enable retry logic for transient failures (including serverless wake-up)
        sqlOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(30),
            errorNumbersToAdd: null);
    }));

// Register repositories
builder.Services.AddScoped<ICategoryRepository, CategoryRepository>();
builder.Services.AddScoped<ICollectionRepository, CollectionRepository>();
builder.Services.AddScoped<IItemRepository, ItemRepository>();
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IPropertySuggestionRepository, PropertySuggestionRepository>();
builder.Services.AddScoped<IItemTemplateRepository, ItemTemplateRepository>();
builder.Services.AddScoped<IThemeRepository, ThemeRepository>();

// Register image provider
builder.Services.AddScoped<IImageProvider, DatabaseImageProvider>();

// Register visibility service
builder.Services.AddScoped<IVisibilityService, VisibilityService>();

// Configure authentication
builder.Services.Configure<AuthenticationSettings>(builder.Configuration.GetSection("Authentication"));
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddSingleton<IOidcTokenValidator, OidcTokenValidator>();
builder.Services.AddScoped<IOAuthService, OAuthService>();
builder.Services.AddHttpClient();

builder.Services.AddAuthentication(CookieJwtAuthenticationExtensions.SchemeName)
    .AddCookieJwtAuthentication();

builder.Services.AddAuthorization();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Run database migrations at startup (with retry for serverless SQL Azure)
// This ensures the database schema is always up to date before serving requests
{
    using var scope = app.Services.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    
    var maxRetries = 5;
    var retryDelay = TimeSpan.FromSeconds(10);
    
    for (var attempt = 1; attempt <= maxRetries; attempt++)
    {
        try
        {
            logger.LogInformation("Applying database migrations (attempt {Attempt}/{MaxRetries})...", attempt, maxRetries);
            context.Database.Migrate();
            logger.LogInformation("Database migrations applied successfully.");
            break;
        }
        catch (Exception ex) when (attempt < maxRetries)
        {
            logger.LogWarning(ex, "Database migration failed (attempt {Attempt}/{MaxRetries}). Retrying in {Delay}s...", 
                attempt, maxRetries, retryDelay.TotalSeconds);
            Thread.Sleep(retryDelay);
            retryDelay *= 2; // Exponential backoff
        }
    }
    
    // Seed database with system data (themes, templates)
    var seeder = new DatabaseSeeder(context);
    await seeder.SeedAsync();
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
else
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

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

// Map health check endpoint (used by pipeline to verify deployment)
app.MapHealthChecks("/health");

app.Run();

public partial class Program { }

using backend.Authentication;
using backend.Data;
using backend.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);

// Add services for both API controllers and Razor Pages
builder.Services.AddControllers();
builder.Services.AddRazorPages();

// Configure lowercase URLs for tag helpers
builder.Services.Configure<RouteOptions>(options =>
{
    options.LowercaseUrls = true;
});

// Configure EF Core with SQL Server
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString));

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

// In Debug builds: run migrations automatically
// In Release builds: use migration bundle for deployments
#if DEBUG
{
    using var scope = app.Services.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    context.Database.Migrate();
    
    // Seed database with system data
    var seeder = new DatabaseSeeder(context);
    await seeder.SeedAsync();
}
#endif

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
        var indexPath = Path.Combine(collectionsPath, "index.html");
        
        // SPA fallback middleware: rewrite /collections/* requests to index.html
        // if the requested file doesn't exist (allows React Router to handle routing)
        app.Use(async (context, next) =>
        {
            var path = context.Request.Path.Value ?? "";
            if (path.StartsWith("/collections", StringComparison.OrdinalIgnoreCase))
            {
                // Get the file path relative to collections folder
                var relativePath = path.Substring("/collections".Length).TrimStart('/');
                var filePath = Path.Combine(collectionsPath, relativePath);
                
                // If the file doesn't exist and it's not a file request (no extension or not found),
                // rewrite to index.html for SPA routing
                if (!string.IsNullOrEmpty(relativePath) && 
                    !File.Exists(filePath) && 
                    !Directory.Exists(filePath))
                {
                    context.Request.Path = "/collections/index.html";
                }
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

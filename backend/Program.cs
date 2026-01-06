using backend.Data;
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

// Configure EF Core with SQLite
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register repository
builder.Services.AddScoped<ICategoryRepository, CategoryRepository>();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Ensure database is created and seed development data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    context.Database.EnsureCreated();

    if (app.Environment.IsDevelopment())
    {
        DatabaseSeeder.SeedDevelopmentData(context);
    }
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

app.UseAuthorization();

// Serve static assets from wwwroot (CSS, favicon, etc.)
app.MapStaticAssets();

// Serve frontend SPA assets from wwwroot/collections at /collections path
var collectionsPath = Path.Combine(app.Environment.WebRootPath, "collections");
if (Directory.Exists(collectionsPath))
{
    app.UseStaticFiles(new StaticFileOptions
    {
        FileProvider = new PhysicalFileProvider(collectionsPath),
        RequestPath = "/collections"
    });

    // SPA fallback for /collections routes - serve index.html for client-side routing
    app.MapFallback("/collections/{**path}", async context =>
    {
        var indexPath = Path.Combine(collectionsPath, "index.html");
        if (File.Exists(indexPath))
        {
            context.Response.ContentType = "text/html";
            await context.Response.SendFileAsync(indexPath);
        }
        else
        {
            context.Response.StatusCode = 404;
        }
    });
}

app.MapRazorPages()
   .WithStaticAssets();

app.MapControllers();

app.Run();

public partial class Program { }

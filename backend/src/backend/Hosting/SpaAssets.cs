using Microsoft.Extensions.FileProviders;

namespace OneBigHead.Server.Hosting;

/// <summary>Owns the production SPA file provider for the lifetime of the application.</summary>
internal sealed class SpaAssets : IDisposable
{
    private readonly PhysicalFileProvider? _files;

    public SpaAssets(IWebHostEnvironment environment)
    {
        // Development uses Vite; deployments without the SPA can still serve the API and Razor pages.
        if (environment.IsDevelopment() || environment.WebRootPath is null)
            return;

        var path = Path.Combine(environment.WebRootPath, "collections");
        if (Directory.Exists(path))
            _files = new PhysicalFileProvider(path);
    }

    public void Map(WebApplication app)
    {
        if (_files is null)
            return;

        app.UseStaticFiles(new StaticFileOptions { FileProvider = _files, RequestPath = "/collections" });
        app.UseStaticFiles(new StaticFileOptions { FileProvider = _files });

        // APIs and missing files must retain their 404 responses instead of returning HTML.
        foreach (var route in new[] { "collections", "settings", "setup", "admin", "welcome", "terms", "public", "workspaces", "join" })
            app.MapFallbackToFile($"/{route}/{{*path:nonfile}}", "index.html",
                new StaticFileOptions { FileProvider = _files });
    }

    public void Dispose() => _files?.Dispose();
}

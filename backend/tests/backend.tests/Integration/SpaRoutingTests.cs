using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class SpaRoutingTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"onebighead-spa-{Guid.NewGuid()}");
    private readonly CustomWebApplicationFactory _factory = new();
    private readonly WebApplicationFactory<Program> _app;

    public SpaRoutingTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "collections", "assets"));
        File.WriteAllText(Path.Combine(_root, "collections", "index.html"), "<html>SPA test shell</html>");
        File.WriteAllText(Path.Combine(_root, "collections", "assets", "app.js"), "// SPA asset");
        _app = _factory.WithWebHostBuilder(builder => builder.UseWebRoot(_root));
    }

    [Theory]
    [InlineData("/collections")]
    [InlineData("/collections/42/items/1")]
    [InlineData("/settings")]
    [InlineData("/setup")]
    [InlineData("/admin/users")]
    [InlineData("/welcome")]
    [InlineData("/public/library/collections/1")]
    [InlineData("/workspaces/new")]
    public async Task ClientRoutes_ServeSpaShell(string path)
    {
        using var client = _app.CreateClient();
        var response = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("SPA test shell", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("/api/does-not-exist")]
    [InlineData("/assets/missing.js")]
    [InlineData("/collections/assets/missing.js")]
    [InlineData("/unregistered-path")]
    public async Task MissingApisAndAssets_RemainNotFound(string path)
    {
        using var client = _app.CreateClient();
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(path)).StatusCode);
    }

    [Theory]
    [InlineData("/assets/app.js")]
    [InlineData("/collections/assets/app.js")]
    public async Task Assets_AreServedAtBothExistingPaths(string path)
    {
        using var client = _app.CreateClient();
        Assert.Equal("// SPA asset", await client.GetStringAsync(path));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/signin")]
    [InlineData("/privacy")]
    [InlineData("/terms")]
    public async Task RazorPages_KeepTheirOwnContent(string path)
    {
        using var client = _app.CreateClient();
        var content = await client.GetStringAsync(path);
        Assert.Contains("OneBigHead", content);
        Assert.DoesNotContain("SPA test shell", content);
    }

    public void Dispose()
    {
        _app.Dispose();
        _factory.Dispose();
        Directory.Delete(_root, recursive: true);
    }
}

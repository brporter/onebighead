using OneBigHead.Server.Middleware;
using OpenTelemetry.Metrics;

namespace OneBigHead.Server.Hosting;

internal static class ApplicationPipeline
{
    public static WebApplication UseApplicationPipeline(this WebApplication app)
    {
        app.UseExceptionHandler();
        if (app.Environment.IsDevelopment())
            app.MapOpenApi();
        else
            app.UseHsts();

        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseWorkspaceActiveCheck();

        app.MapStaticAssets();
        app.Services.GetRequiredService<SpaAssets>().Map(app);
        app.MapRazorPages().WithStaticAssets();
        app.MapControllers();
        app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }))
            .WithMetadata(new AllowInactiveWorkspaceAttribute());

        if (!app.Environment.IsEnvironment("Testing"))
            app.MapPrometheusScrapingEndpoint("/metrics");

        return app;
    }
}

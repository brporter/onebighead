using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Hosting;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Administration;
using OneBigHead.Server.Services.Memberships;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Tests.Hosting;

public class StartupTests
{
    internal static WebApplicationBuilder CreateBuilder(string environment, string? webRoot = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(Program).Assembly.GetName().Name,
            ContentRootPath = Path.GetFullPath("../../../../../src/backend", AppContext.BaseDirectory),
            EnvironmentName = environment,
            WebRootPath = webRoot
        });
        // No developer secrets or external telemetry endpoints participate in these hosts.
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:DefaultConnection"] = "Host=unused.invalid;Database=startup;Username=test;Password=test",
            ["Authentication:Jwt:SigningKey"] = new string('x', 64),
            ["Authentication:Jwt:Issuer"] = "startup-tests",
            ["Authentication:Jwt:Audience"] = "startup-tests"
        });
        builder.Logging.ClearProviders();
        builder.WebHost.UseTestServer();
        return builder;
    }

    [Theory]
    [InlineData("Development", true)]
    [InlineData("Production", false)]
    public async Task RealPipeline_ProvidesHealthMetricsAndEnvironmentSpecificEndpoints(string environment, bool development)
    {
        var builder = CreateBuilder(environment);
        builder.Services.AddApplicationServices(builder.Configuration, builder.Environment);
        builder.AddApplicationTelemetry();
        await using var app = builder.Build();
        app.UseApplicationPipeline();
        await app.StartAsync();
        using var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://startup.example");

        var health = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        var body = await health.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("healthy", body.GetProperty("status").GetString());
        Assert.InRange(body.GetProperty("timestamp").GetDateTime(), DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow);
        Assert.Equal(!development, health.Headers.Contains("Strict-Transport-Security"));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/metrics")).StatusCode);
        Assert.Equal(development ? HttpStatusCode.OK : HttpStatusCode.NotFound,
            (await client.GetAsync("/openapi/v1.json")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/missing")).StatusCode);
        await app.StopAsync();
    }

    [Fact]
    public async Task Services_ShareMembershipAndRevocationInstances_AndUseConfiguredPostgres()
    {
        var builder = CreateBuilder("Production");
        builder.Services.AddApplicationServices(builder.Configuration, builder.Environment);
        await using var app = builder.Build();
        var services = app.Services;
        Assert.Same(services.GetRequiredService<ITeamRoleChanges>(), services.GetRequiredService<ITeamMemberRemoval>());
        Assert.IsType<AccountSessionValidator>(services.GetRequiredService<IAccountSessionValidator>());
        await using var context = await services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync();
        Assert.Equal("Npgsql.EntityFrameworkCore.PostgreSQL", context.Database.ProviderName);
        Assert.Equal(builder.Configuration.GetConnectionString("DefaultConnection"), context.Database.GetConnectionString());
        Assert.True(services.GetRequiredService<IOptions<RouteOptions>>().Value.LowercaseUrls);
        var json = services.GetRequiredService<IOptions<Microsoft.AspNetCore.Mvc.JsonOptions>>().Value.JsonSerializerOptions;
        Assert.True(json.PropertyNameCaseInsensitive);
        Assert.Equal("\"Google\"", JsonSerializer.Serialize(IdentityProvider.Google, json));

        var policies = services.GetRequiredService<IAuthorizationPolicyProvider>();
        Assert.Contains((await policies.GetPolicyAsync(SystemAdministratorRequirement.PolicyName))!.Requirements,
            requirement => requirement is SystemAdministratorRequirement);
        var workspacePolicy = await policies.GetPolicyAsync("WorkspaceAdmin");
        var claim = Assert.Single(workspacePolicy!.Requirements.OfType<Microsoft.AspNetCore.Authorization.Infrastructure.ClaimsAuthorizationRequirement>());
        Assert.Equal("workspace_role", claim.ClaimType);
        Assert.Equal(["WorkspaceAdmin"], claim.AllowedValues);
    }

    [Fact]
    public async Task Testing_LeavesDatabaseToFixtureAndOmitsTelemetry()
    {
        var builder = CreateBuilder("Testing");
        builder.Services.AddApplicationServices(builder.Configuration, builder.Environment);
        builder.AddApplicationTelemetry();
        Assert.DoesNotContain(builder.Services, descriptor => descriptor.ServiceType == typeof(IDbContextFactory<AppDbContext>));
        Assert.DoesNotContain(builder.Services, descriptor => descriptor.ServiceType == typeof(OpenTelemetry.Trace.TracerProvider));
        builder.Services.AddDbContextFactory<AppDbContext>(options => options.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        await using var app = builder.Build();
        app.UseApplicationPipeline();
        await app.StartAsync();
        using var client = app.GetTestClient();
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/metrics")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
        await app.StopAsync();
    }

    [Fact]
    public async Task MissingProviderConfiguration_RegistersOnlyTheLocalCookieScheme()
    {
        var builder = CreateBuilder("Testing");
        builder.Configuration.Sources.Clear();
        builder.Services.AddApplicationAuthentication(builder.Configuration);
        await using var app = builder.Build();
        var schemes = await app.Services.GetRequiredService<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>()
            .GetAllSchemesAsync();
        Assert.Equal(CookieJwtAuthenticationExtensions.SchemeName, Assert.Single(schemes).Name);
    }

    [Theory]
    [InlineData("Development", true)]
    [InlineData("Production", false)]
    [InlineData("Production", true)]
    public async Task SpaAssets_MissingWebRootOrDevelopment_DoesNotAddFallback(string environment, bool hasRoot)
    {
        var hostEnvironment = Mock.Of<IWebHostEnvironment>(value => value.EnvironmentName == environment
            && value.WebRootPath == (hasRoot ? Path.GetTempPath() : null!));
        using var assets = new SpaAssets(hostEnvironment);
        var builder = CreateBuilder("Testing");
        await using var app = builder.Build();
        assets.Map(app);
        await app.StartAsync();
        using var client = app.GetTestClient();
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/collections/1")).StatusCode);
        await app.StopAsync();
    }
}

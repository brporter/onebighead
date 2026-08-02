using OneBigHead.Server.Data;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace OneBigHead.Server.Tests.Integration;

/// <summary>
/// Custom WebApplicationFactory for integration testing with in-memory database.
/// Each instance creates a unique database to ensure test isolation.
/// </summary>
public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _databaseName;

    public CustomWebApplicationFactory()
    {
        // Generate unique database name for each factory instance
        _databaseName = $"TestDb_{Guid.NewGuid()}";
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Set environment to Testing - this causes Program.cs to skip PostgreSQL configuration
        builder.UseEnvironment("Testing");

        builder.ConfigureTestServices(services =>
        {
            // Add in-memory database for testing
            // (Program.cs skips DbContext registration in Testing environment)
            services.AddDbContextFactory<AppDbContext>(options =>
            {
                options.UseInMemoryDatabase(_databaseName)
                    .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning));
            });

            // Replace email service with a test implementation
            services.RemoveAll<IEmailService>();
            services.AddSingleton<IEmailService, TestEmailService>();

            // Replace statistics repositories with in-memory-compatible test doubles
            // (the real implementations use ExecuteUpdateAsync which is unsupported by the in-memory provider)
            services.RemoveAll<IWorkspaceStatisticsRepository>();
            services.AddSingleton<IWorkspaceStatisticsRepository, TestWorkspaceStatisticsRepository>();

            services.RemoveAll<ICollectionStatisticsRepository>();
            services.AddSingleton<ICollectionStatisticsRepository, TestCollectionStatisticsRepository>();

            // Configure test authentication
            services.AddAuthentication(defaultScheme: TestAuthHandler.SchemeName)
                .AddScheme<TestAuthSchemeOptions, TestAuthHandler>(
                    TestAuthHandler.SchemeName, options => { });
        });
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        var host = base.CreateHost(builder);

        // Ensure database is created
        using var scope = host.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        context.Database.EnsureCreated();

        return host;
    }

    /// <summary>
    /// Creates a client that is authenticated with the specified claims.
    /// Defaults to WorkspaceAdmin role for backwards compatibility.
    /// </summary>
    public HttpClient CreateAuthenticatedClient(int workspaceId, int userId, string email = "test@example.com", string workspaceRole = "WorkspaceAdmin")
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, workspaceId.ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, userId.ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.EmailHeader, email);
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, workspaceRole);
        return client;
    }

    /// <summary>
    /// Creates an unauthenticated client for testing anonymous endpoints.
    /// </summary>
    public HttpClient CreateUnauthenticatedClient()
    {
        return CreateClient();
    }

    /// <summary>
    /// Seeds the database with test data using a scoped context.
    /// </summary>
    public async Task SeedDatabaseAsync(Action<AppDbContext> seedAction)
    {
        using var scope = Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        seedAction(context);
        await context.SaveChangesAsync();
    }

    /// <summary>
    /// Seeds the database with test data using an async action.
    /// </summary>
    public async Task SeedDatabaseAsync(Func<AppDbContext, Task> seedAction)
    {
        using var scope = Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await seedAction(context);
        await context.SaveChangesAsync();
    }

    /// <summary>
    /// Gets a scoped database context for assertions.
    /// </summary>
    public AppDbContext GetDbContext()
    {
        var scope = Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AppDbContext>();
    }
}
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
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
        // Set environment to Testing - this causes Program.cs to skip SQL Server configuration
        builder.UseEnvironment("Testing");

        builder.ConfigureTestServices(services =>
        {
            // Add in-memory database for testing
            // (Program.cs skips DbContext registration in Testing environment)
            services.AddDbContext<AppDbContext>(options =>
            {
                options.UseInMemoryDatabase(_databaseName)
                    .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning));
            });

            // Replace email service with a test implementation
            services.RemoveAll<IEmailService>();
            services.AddScoped<IEmailService, TestEmailService>();

            // Replace workspace statistics repository with a no-op stub
            // (the real implementation uses ExecuteUpdateAsync which is unsupported by the in-memory provider)
            services.RemoveAll<IWorkspaceStatisticsRepository>();
            services.AddScoped<IWorkspaceStatisticsRepository, TestWorkspaceStatisticsRepository>();

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

/// <summary>
/// Test email service that captures sent emails for verification.
/// </summary>
public class TestEmailService : IEmailService
{
    public List<(string To, string Subject, int RequestId)> SupportConfirmations { get; } = new();
    public List<(string To, string Subject, string Reply, int RequestId)> SupportReplies { get; } = new();

    public Task SendSupportRequestConfirmationAsync(string toEmail, string subject, int requestId, bool isLoggedInUser)
    {
        SupportConfirmations.Add((toEmail, subject, requestId));
        return Task.CompletedTask;
    }

    public Task SendSupportReplyNotificationAsync(string toEmail, string subject, string replyMessage, int requestId, bool isLoggedInUser)
    {
        SupportReplies.Add((toEmail, subject, replyMessage, requestId));
        return Task.CompletedTask;
    }
}

/// <summary>
/// Test workspace statistics repository that uses simple in-memory operations
/// instead of ExecuteUpdateAsync (which is unsupported by the EF Core in-memory provider).
/// </summary>
public class TestWorkspaceStatisticsRepository : IWorkspaceStatisticsRepository
{
    private readonly AppDbContext _context;

    public TestWorkspaceStatisticsRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task IncrementAsync(int workspaceId, StatisticType type, long amount = 1, DateOnly? date = null)
    {
        var effectiveDate = date ?? DateOnly.MinValue;

        var stat = await _context.WorkspaceStatistics
            .FirstOrDefaultAsync(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date == effectiveDate);

        if (stat != null)
        {
            stat.Value += amount;
        }
        else
        {
            _context.WorkspaceStatistics.Add(new WorkspaceStatistic
            {
                WorkspaceId = workspaceId,
                StatisticType = type,
                Date = effectiveDate,
                Value = amount,
            });
        }

        await _context.SaveChangesAsync();
    }

    public async Task DecrementAsync(int workspaceId, StatisticType type, long amount = 1)
    {
        var stat = await _context.WorkspaceStatistics
            .FirstOrDefaultAsync(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date == DateOnly.MinValue);

        if (stat != null)
        {
            stat.Value = Math.Max(0, stat.Value - amount);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<Dictionary<StatisticType, long>> GetAggregatesAsync(int workspaceId)
    {
        return await _context.WorkspaceStatistics
            .AsNoTracking()
            .Where(s => s.WorkspaceId == workspaceId && s.Date == DateOnly.MinValue)
            .ToDictionaryAsync(s => s.StatisticType, s => s.Value);
    }

    public async Task<List<DailyStatistic>> GetDailyAsync(int workspaceId, StatisticType type, DateOnly from, DateOnly to)
    {
        return await _context.WorkspaceStatistics
            .AsNoTracking()
            .Where(s => s.WorkspaceId == workspaceId && s.StatisticType == type && s.Date >= from && s.Date <= to)
            .OrderBy(s => s.Date)
            .Select(s => new DailyStatistic(s.Date, s.Value))
            .ToListAsync();
    }
}

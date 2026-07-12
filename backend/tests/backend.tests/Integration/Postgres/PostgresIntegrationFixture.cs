using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Data;
using Testcontainers.PostgreSql;

namespace OneBigHead.Server.Tests.Integration.Postgres;

/// <summary>
/// Starts a disposable PostgreSQL 17 container for the test run, applies the
/// application's EF Core migrations, and tears the container down when the
/// collection completes. Requires a running Docker daemon.
///
/// These tests are excluded from normal CI runs; execute them locally with:
///   dotnet test --filter "Category=PostgresIntegration"
/// </summary>
public sealed class PostgresIntegrationFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container =
        new PostgreSqlBuilder("postgres:17").Build();

    public string ConnectionString => _container.GetConnectionString();

    public async Task InitializeAsync()
    {
        await _container.StartAsync();

        await using var context = CreateContext();
        await context.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        await _container.DisposeAsync();
    }

    public AppDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(ConnectionString)
            .Options;
        return new AppDbContext(options);
    }

    /// <summary>
    /// Truncates all application tables (preserving migration history) and
    /// restarts identity sequences so each test class starts from a clean database.
    /// </summary>
    public async Task ResetAsync()
    {
        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();

        var tables = new List<string>();
        var listTablesSql = """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_type = 'BASE TABLE'
              AND table_name <> '__EFMigrationsHistory'
            """;
        await using (var listCmd = new NpgsqlCommand(listTablesSql, connection))
        await using (var reader = await listCmd.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
            {
                tables.Add(reader.GetString(0));
            }
        }

        if (tables.Count == 0)
        {
            return;
        }

        var tableList = string.Join(", ", tables.Select(t => $"\"{t}\""));
        await using var truncateCmd = new NpgsqlCommand(
            $"TRUNCATE {tableList} RESTART IDENTITY CASCADE", connection);
        await truncateCmd.ExecuteNonQueryAsync();
    }
}

/// <summary>
/// All PostgreSQL integration test classes join this collection so they share
/// a single container and run sequentially against it.
/// </summary>
[CollectionDefinition(Name)]
public class PostgresIntegrationCollection : ICollectionFixture<PostgresIntegrationFixture>
{
    public const string Name = "PostgresIntegration";
}
